export type GoogleAuthConfig = {
  clientId: string;
  clientSecret: string;
  /** Lowercase email domains. Empty means any verified Google account. */
  allowedDomains: string[];
};

type UserInfoValidationInput = {
  user: { email?: string | null; emailVerified?: boolean | null };
  source: { method: string; oauth?: { providerId?: string } };
};

export function parseGoogleAuthConfig(env: NodeJS.ProcessEnv = process.env): GoogleAuthConfig | undefined {
  const clientId = env.PAPERCLIP_AUTH_GOOGLE_CLIENT_ID?.trim();
  const clientSecret = env.PAPERCLIP_AUTH_GOOGLE_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) return undefined;
  const allowedDomains = (env.PAPERCLIP_AUTH_GOOGLE_ALLOWED_DOMAINS ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase().replace(/^@/, ""))
    .filter((value) => value.length > 0);
  return { clientId, clientSecret, allowedDomains };
}

/**
 * Better Auth options that turn on Google sign-in. Returns an empty object when
 * Google is not configured, so the email/password-only setup stays unchanged.
 */
export function buildGoogleAuthOptions(google: GoogleAuthConfig | undefined, input: { disableSignUp: boolean }) {
  if (!google) return {};
  const restrictsDomains = google.allowedDomains.length > 0;
  return {
    socialProviders: {
      google: {
        clientId: google.clientId,
        clientSecret: google.clientSecret,
        // `hd: "*"` makes Better Auth reject ID tokens without a hosted-domain claim,
        // so personal Google accounts that use a company address are refused.
        // `validateUserInfo` checks the email domain.
        ...(restrictsDomains ? { hd: "*" } : {}),
        // The allowed-domain list is an explicit sign-up policy: it lets invited
        // teammates create their account with Google when email sign-up is off.
        disableSignUp: input.disableSignUp && !restrictsDomains,
      },
    },
    account: {
      accountLinking: {
        enabled: true,
        // Email/password accounts are never email-verified in Paperclip, so the
        // default would refuse every link. Better Auth still requires Google to
        // report the email as verified before it links.
        requireLocalEmailVerified: false,
      },
    },
    user: {
      validateUserInfo: (data: UserInfoValidationInput) => validateGoogleUserInfo(google, data),
    },
  };
}

export function validateGoogleUserInfo(google: GoogleAuthConfig, data: UserInfoValidationInput) {
  if (data.source.method !== "oauth" || data.source.oauth?.providerId !== "google") return;
  if (data.user.emailVerified !== true) {
    return { error: "email_not_verified", errorDescription: "Google has not verified this email address." };
  }
  if (google.allowedDomains.length === 0) return;
  const domain = data.user.email?.split("@").pop()?.toLowerCase();
  if (!domain || !google.allowedDomains.includes(domain)) {
    return { error: "email_domain_not_allowed", errorDescription: "This Google account is not allowed to sign in." };
  }
}
