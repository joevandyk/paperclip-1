/**
 * Drives Google sign-in through the real Better Auth mount and a migrated
 * Postgres: the redirect to Google, then the OAuth callback. Only Google's
 * token endpoint is stubbed, so account creation, account linking and the
 * allowed-domain gate all run as they do in production.
 */

import { createHash, randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  activityLog,
  authAccounts,
  authSessions,
  authUsers,
  companies,
  companyMemberships,
  createDb,
  invites,
  joinRequests,
  principalPermissionGrants,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { createBetterAuthHandler, createBetterAuthInstance, resolveBetterAuthSession } from "../auth/better-auth.js";
import { actorMiddleware } from "../middleware/auth.js";
import type { GoogleAuthConfig } from "../auth/google.js";
import type { Config } from "../config.js";

vi.hoisted(() => {
  process.env.PAPERCLIP_HOME = "/tmp/paperclip-test-home";
  process.env.PAPERCLIP_INSTANCE_ID = "vitest";
  process.env.PAPERCLIP_LOG_DIR = "/tmp/paperclip-test-home/logs";
  process.env.PAPERCLIP_IN_WORKTREE = "false";
});

const ORIGIN = "http://127.0.0.1:41998";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

type GoogleProfile = { sub: string; email: string; email_verified: boolean; hd?: string; name?: string };

function testConfig(input: { google?: GoogleAuthConfig; disableSignUp?: boolean; disablePasswordLogin?: boolean }): Config {
  return {
    deploymentMode: "authenticated",
    deploymentExposure: "private",
    authBaseUrlMode: "explicit",
    authPublicBaseUrl: ORIGIN,
    authDisableSignUp: input.disableSignUp ?? false,
    authGoogle: input.google,
    authDisablePasswordLogin: input.disablePasswordLogin ?? false,
    allowedHostnames: ["127.0.0.1"],
    port: 41998,
  } as unknown as Config;
}

function unsignedIdToken(profile: GoogleProfile): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  return [
    encode({ alg: "RS256", typ: "JWT" }),
    encode({ iss: "https://accounts.google.com", aud: "client-id", iat: now, exp: now + 3600, ...profile }),
    "signature",
  ].join(".");
}

function stubGoogleTokenEndpoint(profile: GoogleProfile) {
  const realFetch = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith(GOOGLE_TOKEN_URL)) {
      return new Response(JSON.stringify({
        access_token: "google-access-token",
        id_token: unsignedIdToken(profile),
        expires_in: 3600,
        token_type: "Bearer",
        scope: "openid email profile",
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return realFetch(input, init);
  });
}

function cookiesFrom(response: request.Response): string[] {
  const raw = response.headers["set-cookie"];
  const cookies = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return cookies.map((cookie) => cookie.split(";")[0]!);
}

describeEmbeddedPostgres("Better Auth Google sign-in against the real schema", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  let db!: ReturnType<typeof createDb>;
  const originalEnv = {
    secret: process.env.BETTER_AUTH_SECRET,
    rateLimit: process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED,
  };

  beforeAll(async () => {
    process.env.BETTER_AUTH_SECRET = "better-auth-secret-for-google-signin-tests";
    process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = "false";
    database = await startEmbeddedPostgresTestDatabase("paperclip-better-auth-google-");
    db = createDb(database.connectionString);
  }, 30_000);

  afterEach(async () => {
    vi.restoreAllMocks();
    await db.delete(activityLog);
    await db.delete(joinRequests);
    await db.delete(invites);
    await db.delete(principalPermissionGrants);
    await db.delete(companyMemberships);
    await db.delete(companies);
    await db.delete(authSessions);
    await db.delete(authAccounts);
    await db.delete(authUsers);
  });

  afterAll(async () => {
    await database?.cleanup();
    if (originalEnv.secret === undefined) delete process.env.BETTER_AUTH_SECRET;
    else process.env.BETTER_AUTH_SECRET = originalEnv.secret;
    if (originalEnv.rateLimit === undefined) delete process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED;
    else process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = originalEnv.rateLimit;
  });

  function appFor(config: Config) {
    const app = express();
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(createBetterAuthInstance(db, config, [ORIGIN])));
    return app;
  }

  /** The Better Auth mount, the session-resolving actor middleware and the invite routes, wired as in `createApp`. */
  async function appWithInvites(config: Config) {
    const { accessRoutes } = await import("../routes/access.js");
    const auth = createBetterAuthInstance(db, config, [ORIGIN]);
    const app = express();
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(auth));
    app.use(express.json());
    app.use(actorMiddleware(db, {
      deploymentMode: "authenticated",
      resolveSession: (req) => resolveBetterAuthSession(auth, req),
    }));
    app.use("/api", accessRoutes(db, {
      deploymentMode: "authenticated",
      deploymentExposure: "private",
      bindHost: "127.0.0.1",
      allowedHostnames: ["127.0.0.1"],
    }));
    app.use((err: { status?: number; message?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(err.status ?? 500).json({ error: err.message ?? "Internal server error" });
    });
    return app;
  }

  async function createHumanInvite() {
    const company = await db
      .insert(companies)
      .values({ name: "Invite Co", issuePrefix: `IV${randomUUID().replace(/-/g, "").slice(0, 6).toUpperCase()}` })
      .returning()
      .then((rows) => rows[0]!);
    const token = `pcp_invite_${randomUUID()}`;
    await db.insert(invites).values({
      companyId: company.id,
      inviteType: "company_join",
      allowedJoinTypes: "human",
      tokenHash: createHash("sha256").update(token).digest("hex"),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    return { company, token };
  }

  async function signInWithGoogle(app: express.Express, profile: GoogleProfile, callbackURL = "/invite/test-token") {
    const start = await request(app)
      .post("/api/auth/sign-in/social")
      .set("origin", ORIGIN)
      .send({ provider: "google", callbackURL, errorCallbackURL: "/auth" });
    expect(start.status).toBe(200);
    const authorizationUrl = new URL(start.body.url);
    expect(authorizationUrl.origin).toBe("https://accounts.google.com");
    expect(authorizationUrl.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/api/auth/callback/google`);

    stubGoogleTokenEndpoint(profile);
    const callback = await request(app)
      .get("/api/auth/callback/google")
      .query({ code: "google-code", state: authorizationUrl.searchParams.get("state") })
      .set("Cookie", cookiesFrom(start).join("; "));
    return { authorizationUrl, callback };
  }

  async function signUpWithPassword(app: express.Express, email: string) {
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email, password: "correct-horse-battery-staple", name: "Ada" });
    expect(signUp.status).toBe(200);
  }

  const google: GoogleAuthConfig = { clientId: "client-id", clientSecret: "client-secret", allowedDomains: [] };
  const workspace: GoogleAuthConfig = { ...google, allowedDomains: ["example.com"] };

  it("does not offer Google when it is not configured", async () => {
    const response = await request(appFor(testConfig({})))
      .post("/api/auth/sign-in/social")
      .set("origin", ORIGIN)
      .send({ provider: "google", callbackURL: "/" });
    expect(response.status).toBe(404);
  });

  it("creates a user and returns to the callback URL", async () => {
    const { callback } = await signInWithGoogle(appFor(testConfig({ google })), {
      sub: "google-1", email: "ada@gmail.com", email_verified: true, name: "Ada",
    });

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe("/invite/test-token");
    expect(cookiesFrom(callback).some((cookie) => cookie.includes("session_token"))).toBe(true);
    const users = await db.select().from(authUsers);
    expect(users).toMatchObject([{ email: "ada@gmail.com", emailVerified: true }]);
    expect(await db.select().from(authAccounts)).toMatchObject([{ providerId: "google", accountId: "google-1" }]);
  });

  it("links a verified Google email to the existing password account", async () => {
    const app = appFor(testConfig({ google }));
    await signUpWithPassword(app, "ada@example.com");

    const { callback } = await signInWithGoogle(app, {
      sub: "google-2", email: "ada@example.com", email_verified: true,
    });

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe("/invite/test-token");
    const users = await db.select().from(authUsers);
    expect(users).toHaveLength(1);
    const accounts = await db.select().from(authAccounts);
    expect(accounts.map((account) => account.providerId).sort()).toEqual(["credential", "google"]);
    expect(accounts.every((account) => account.userId === users[0]!.id)).toBe(true);
  });

  it("does not link or duplicate a password account when Google has not verified the email", async () => {
    const app = appFor(testConfig({ google }));
    await signUpWithPassword(app, "ada@example.com");

    const { callback } = await signInWithGoogle(app, {
      sub: "google-3", email: "ada@example.com", email_verified: false,
    });

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe("/auth?error=account_not_linked");
    expect(await db.select().from(authUsers)).toHaveLength(1);
    expect((await db.select().from(authAccounts)).map((account) => account.providerId)).toEqual(["credential"]);
  });

  it("does not create a user from an unverified Google email", async () => {
    const { callback } = await signInWithGoogle(appFor(testConfig({ google })), {
      sub: "google-9", email: "ada@gmail.com", email_verified: false,
    });

    expect(callback.headers.location).toMatch(/^\/auth\?error=email_not_verified&/);
    expect(await db.select().from(authUsers)).toHaveLength(0);
  });

  it("asks Google for a Workspace account and refuses other accounts", async () => {
    const app = appFor(testConfig({ google: workspace }));

    const personal = await signInWithGoogle(app, {
      sub: "google-4", email: "ada@example.com", email_verified: true,
    });
    expect(personal.authorizationUrl.searchParams.get("hd")).toBe("*");
    expect(personal.callback.headers.location).toBe("/auth?error=unable_to_get_user_info");

    const otherWorkspace = await signInWithGoogle(app, {
      sub: "google-5", email: "ada@other.example", email_verified: true, hd: "other.example",
    });
    expect(otherWorkspace.callback.headers.location).toMatch(/^\/auth\?error=email_domain_not_allowed&/);
    expect(await db.select().from(authUsers)).toHaveLength(0);
  });

  it("signs in a Workspace account from any allowed domain", async () => {
    const { callback } = await signInWithGoogle(
      appFor(testConfig({ google: { ...google, allowedDomains: ["example.com", "corp.example"] } })),
      { sub: "google-10", email: "ada@corp.example", email_verified: true, hd: "corp.example" },
    );

    expect(callback.headers.location).toBe("/invite/test-token");
    expect(await db.select().from(authUsers)).toMatchObject([{ email: "ada@corp.example" }]);
  });

  it("refuses an existing password account outside the allowed domains", async () => {
    const app = appFor(testConfig({ google: { ...google, allowedDomains: ["example.com", "corp.example"] } }));
    await signUpWithPassword(app, "ada@other.example");

    const { callback } = await signInWithGoogle(app, {
      sub: "google-6", email: "ada@other.example", email_verified: true, hd: "other.example",
    });

    expect(callback.headers.location).toMatch(/^\/auth\?error=email_domain_not_allowed&/);
    expect((await db.select().from(authAccounts)).map((account) => account.providerId)).toEqual(["credential"]);
  });

  it("lets an allowed-domain account sign up when email sign-up is disabled", async () => {
    const { callback } = await signInWithGoogle(appFor(testConfig({ google: workspace, disableSignUp: true })), {
      sub: "google-7", email: "ada@example.com", email_verified: true, hd: "example.com",
    });

    expect(callback.headers.location).toBe("/invite/test-token");
    expect(await db.select().from(authUsers)).toMatchObject([{ email: "ada@example.com" }]);
  });

  it("turns off email and password while Google keeps working", async () => {
    const app = appFor(testConfig({ google: workspace, disablePasswordLogin: true }));

    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email: "ada@example.com", password: "correct-horse-battery-staple", name: "Ada" });
    expect(signUp.status).toBe(400);
    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: "ada@example.com", password: "correct-horse-battery-staple" });
    expect(signIn.status).toBe(400);
    expect(await db.select().from(authUsers)).toHaveLength(0);

    const { callback } = await signInWithGoogle(app, {
      sub: "google-11", email: "ada@example.com", email_verified: true, hd: "example.com",
    });
    expect(callback.headers.location).toBe("/invite/test-token");
  });

  it("lets a password user keep their account by signing in with Google after passwords are turned off", async () => {
    await signUpWithPassword(appFor(testConfig({ google: workspace })), "ada@example.com");

    const { callback } = await signInWithGoogle(appFor(testConfig({ google: workspace, disablePasswordLogin: true })), {
      sub: "google-12", email: "ada@example.com", email_verified: true, hd: "example.com",
    });

    expect(callback.headers.location).toBe("/invite/test-token");
    expect(await db.select().from(authUsers)).toHaveLength(1);
  });

  it("refuses to turn off passwords when Google is not configured", () => {
    expect(() => createBetterAuthInstance(db, testConfig({ disablePasswordLogin: true }), [ORIGIN])).toThrow(
      /PAPERCLIP_AUTH_DISABLE_PASSWORD_LOGIN/,
    );
  });

  describe("with email sign-up and password login turned off", () => {
    const lockedDown = () => testConfig({ google: workspace, disableSignUp: true, disablePasswordLogin: true });

    it("refuses email sign-up when only sign-up is disabled", async () => {
      const signUp = await request(appFor(testConfig({ google: workspace, disableSignUp: true })))
        .post("/api/auth/sign-up/email")
        .set("origin", ORIGIN)
        .send({ email: "ada@example.com", password: "correct-horse-battery-staple", name: "Ada" });

      expect(signUp.status).toBeGreaterThanOrEqual(400);
      expect(await db.select().from(authUsers)).toHaveLength(0);
    });

    it("lets an invited person create their account with Google and accept the invite", async () => {
      const app = await appWithInvites(lockedDown());
      const { company, token } = await createHumanInvite();

      const { callback } = await signInWithGoogle(app, {
        sub: "google-20", email: "ada@example.com", email_verified: true, hd: "example.com",
      }, `/invite/${token}`);
      expect(callback.headers.location).toBe(`/invite/${token}`);
      const [user] = await db.select().from(authUsers);
      expect(user).toMatchObject({ email: "ada@example.com" });

      const accept = await request(app)
        .post(`/api/invites/${token}/accept`)
        .set("origin", ORIGIN)
        .set("Cookie", cookiesFrom(callback).join("; "))
        .send({ requestType: "human" });

      expect(accept.status).toBeLessThan(300);
      const requests = await db.select().from(joinRequests).where(eq(joinRequests.companyId, company.id));
      expect(requests).toMatchObject([{ requestType: "human", requestingUserId: user!.id }]);
    });

    it("lets an uninvited person from an allowed domain create an account with no company access", async () => {
      const app = await appWithInvites(lockedDown());
      await createHumanInvite();

      const { callback } = await signInWithGoogle(app, {
        sub: "google-21", email: "bob@example.com", email_verified: true, hd: "example.com",
      }, "/");
      expect(callback.headers.location).toBe("/");
      const [user] = await db.select().from(authUsers);
      expect(user).toMatchObject({ email: "bob@example.com" });

      expect(await db.select().from(companyMemberships).where(eq(companyMemberships.principalId, user!.id))).toHaveLength(0);
      expect(await db.select().from(joinRequests)).toHaveLength(0);
      const guessedInvite = await request(app)
        .post(`/api/invites/pcp_invite_${randomUUID()}/accept`)
        .set("origin", ORIGIN)
        .set("Cookie", cookiesFrom(callback).join("; "))
        .send({ requestType: "human" });
      expect(guessedInvite.status).toBe(404);
    });

    it("refuses a Google account from another domain, even with an invite link", async () => {
      const app = await appWithInvites(lockedDown());
      const { token } = await createHumanInvite();

      const otherWorkspace = await signInWithGoogle(app, {
        sub: "google-22", email: "eve@other.example", email_verified: true, hd: "other.example",
      }, `/invite/${token}`);
      expect(otherWorkspace.callback.headers.location).toMatch(/^\/auth\?error=email_domain_not_allowed&/);

      const personal = await signInWithGoogle(app, {
        sub: "google-23", email: "eve@gmail.com", email_verified: true,
      }, `/invite/${token}`);
      expect(personal.callback.headers.location).toBe("/auth?error=unable_to_get_user_info");

      expect(await db.select().from(authUsers)).toHaveLength(0);
      expect(await db.select().from(joinRequests)).toHaveLength(0);
    });
  });

  it("refuses an already-linked Google account once its domain is no longer allowed", async () => {
    const before = await signInWithGoogle(appFor(testConfig({ google })), {
      sub: "google-24", email: "ada@other.example", email_verified: true, hd: "other.example",
    });
    expect(before.callback.headers.location).toBe("/invite/test-token");
    expect(cookiesFrom(before.callback).some((cookie) => cookie.includes("session_token="))).toBe(true);

    const after = await signInWithGoogle(appFor(testConfig({ google: workspace })), {
      sub: "google-24", email: "ada@other.example", email_verified: true, hd: "other.example",
    });

    expect(after.callback.headers.location).toMatch(/^\/auth\?error=email_domain_not_allowed&/);
    expect(cookiesFrom(after.callback).some((cookie) => cookie.includes("session_token="))).toBe(false);
  });

  it("keeps sign-up closed to Google without an allowed-domain list", async () => {
    const { callback } = await signInWithGoogle(appFor(testConfig({ google, disableSignUp: true })), {
      sub: "google-8", email: "ada@gmail.com", email_verified: true,
    });

    expect(callback.headers.location).toBe("/auth?error=signup_disabled");
    expect(await db.select().from(authUsers)).toHaveLength(0);
  });
});
