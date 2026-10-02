import { useState } from "react";
import type { HealthStatus } from "@/api/health";
import { authApi } from "@/api/auth";
import { Button } from "@/components/ui/button";

export function isGoogleSignInEnabled(health: HealthStatus | undefined) {
  return health?.authSocialProviders?.includes("google") ?? false;
}

/** Text for the `error` query param Better Auth adds when a Google sign-in fails. */
export function googleSignInErrorMessage(code: string | null) {
  if (!code) return null;
  switch (code) {
    case "account_not_linked":
      return "Google has not verified this email, so it was not linked to your existing account. Sign in with your password.";
    case "signup_disabled":
      return "There is no account for this Google user, and sign-up is disabled on this instance.";
    case "email_domain_not_allowed":
      return "This Google account is not allowed to sign in to this instance.";
    case "email_not_verified":
      return "Google has not verified the email address of this account.";
    case "unable_to_get_user_info":
      return "Google sign-in failed. If this instance only allows company accounts, use your company Google account.";
    default:
      return `Google sign-in failed (${code}). Try again.`;
  }
}

export function GoogleSignInButton({
  callbackURL,
  errorCallbackURL,
  className,
}: {
  callbackURL: string;
  errorCallbackURL: string;
  className?: string;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="space-y-2">
      <Button
        type="button"
        variant="outline"
        className={`w-full ${className ?? ""}`}
        disabled={pending}
        onClick={async () => {
          setPending(true);
          setError(null);
          try {
            window.location.assign(await authApi.signInSocial({ provider: "google", callbackURL, errorCallbackURL }));
          } catch (err) {
            setError(err instanceof Error ? err.message : "Google sign-in failed");
            setPending(false);
          }
        }}
      >
        <svg aria-hidden="true" viewBox="0 0 48 48" className="size-4">
          <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
          <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
          <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
          <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
        </svg>
        {pending ? "Redirecting…" : "Continue with Google"}
      </Button>
      {error ? <p role="alert" className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}
