import { describe, expect, it } from "vitest";
import { buildGoogleAuthOptions, parseGoogleAuthConfig, validateGoogleUserInfo } from "../auth/google.js";

const googleSource = { method: "oauth", oauth: { providerId: "google" } };

describe("parseGoogleAuthConfig", () => {
  it("stays off unless both the client id and secret are set", () => {
    expect(parseGoogleAuthConfig({})).toBeUndefined();
    expect(parseGoogleAuthConfig({ PAPERCLIP_AUTH_GOOGLE_CLIENT_ID: "id" })).toBeUndefined();
    expect(parseGoogleAuthConfig({ PAPERCLIP_AUTH_GOOGLE_CLIENT_SECRET: "secret" })).toBeUndefined();
    expect(parseGoogleAuthConfig({
      PAPERCLIP_AUTH_GOOGLE_CLIENT_ID: " ",
      PAPERCLIP_AUTH_GOOGLE_CLIENT_SECRET: "secret",
    })).toBeUndefined();
  });

  it("reads the credentials and normalizes the allowed domains", () => {
    expect(parseGoogleAuthConfig({
      PAPERCLIP_AUTH_GOOGLE_CLIENT_ID: "id",
      PAPERCLIP_AUTH_GOOGLE_CLIENT_SECRET: "secret",
      PAPERCLIP_AUTH_GOOGLE_ALLOWED_DOMAINS: " Example.com, @corp.example ,,",
    })).toEqual({ clientId: "id", clientSecret: "secret", allowedDomains: ["example.com", "corp.example"] });
  });
});

describe("buildGoogleAuthOptions", () => {
  it("adds nothing when Google is not configured", () => {
    expect(buildGoogleAuthOptions(undefined, { disableSignUp: true })).toEqual({});
  });

  it("restricts the hosted domain and keeps sign-up open for allowed domains", () => {
    const one = buildGoogleAuthOptions(
      { clientId: "id", clientSecret: "secret", allowedDomains: ["example.com"] },
      { disableSignUp: true },
    );
    expect(one.socialProviders?.google).toMatchObject({ hd: "example.com", disableSignUp: false });

    const many = buildGoogleAuthOptions(
      { clientId: "id", clientSecret: "secret", allowedDomains: ["example.com", "corp.example"] },
      { disableSignUp: false },
    );
    expect(many.socialProviders?.google).toMatchObject({ hd: "*", disableSignUp: false });
  });

  it("follows disableSignUp when no domain is allowed", () => {
    const options = buildGoogleAuthOptions(
      { clientId: "id", clientSecret: "secret", allowedDomains: [] },
      { disableSignUp: true },
    );
    expect(options.socialProviders?.google).not.toHaveProperty("hd");
    expect(options.socialProviders?.google.disableSignUp).toBe(true);
  });
});

describe("validateGoogleUserInfo", () => {
  const google = { clientId: "id", clientSecret: "secret", allowedDomains: ["example.com"] };

  it("accepts a verified email in an allowed domain", () => {
    expect(validateGoogleUserInfo(google, {
      user: { email: "ada@Example.com", emailVerified: true },
      source: googleSource,
    })).toBeUndefined();
  });

  it("refuses other domains and unverified emails", () => {
    expect(validateGoogleUserInfo(google, {
      user: { email: "ada@other.example", emailVerified: true },
      source: googleSource,
    })).toMatchObject({ error: "email_domain_not_allowed" });
    expect(validateGoogleUserInfo(google, {
      user: { email: "ada@example.com.other.example", emailVerified: true },
      source: googleSource,
    })).toMatchObject({ error: "email_domain_not_allowed" });
    expect(validateGoogleUserInfo(google, {
      user: { email: "ada@example.com", emailVerified: false },
      source: googleSource,
    })).toMatchObject({ error: "email_not_verified" });
  });

  it("ignores email/password users", () => {
    expect(validateGoogleUserInfo(google, {
      user: { email: "ada@other.example", emailVerified: false },
      source: { method: "email-password" },
    })).toBeUndefined();
  });
});
