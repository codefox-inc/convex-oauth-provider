import { useAuthActions } from "@convex-dev/auth/react";
import { Authenticated, Unauthenticated, useMutation } from "convex/react";
import { api } from "../convex/_generated/api";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import "./App.css";

function ConsentForm() {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const clientId = searchParams.get("client_id");
  const redirectUri = searchParams.get("redirect_uri");
  const responseType = searchParams.get("response_type");
  const scope = searchParams.get("scope");
  const state = searchParams.get("state");
  const codeChallenge = searchParams.get("code_challenge");
  const codeChallengeMethod = searchParams.get("code_challenge_method");
  const nonce = searchParams.get("nonce");
  const approveAuth = useMutation(api.oauth.issueAuthorizationCode);

  // Validate required params
  if (!clientId || !redirectUri || responseType !== "code") {
    return (
      <div className="oauth-consent">
        <div className="consent-card">
          <h2>Invalid Request</h2>
          <div className="consent-error">
            <p>Missing required parameters or invalid response_type.</p>
            <p>client_id: {clientId || "missing"}</p>
            <p>redirect_uri: {redirectUri || "missing"}</p>
            <p>response_type: {responseType || "missing"}</p>
          </div>
        </div>
      </div>
    );
  }

  const handleApprove = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      const code = await approveAuth({
        clientId,
        redirectUri,
        scopes: scope ? scope.split(" ") : ["openid"],
        codeChallenge: codeChallenge || undefined,
        codeChallengeMethod: codeChallengeMethod || undefined,
        nonce: nonce || undefined,
        state: state || undefined,
      });

      // Redirect to callback with code
      const callbackUrl = new URL(redirectUri);
      callbackUrl.searchParams.set("code", code);
      if (state) callbackUrl.searchParams.set("state", state);

      window.location.assign(callbackUrl.toString());
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setError(message);
      setIsSubmitting(false);
    }
  };

  const handleDeny = () => {
    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("error", "access_denied");
    if (state) callbackUrl.searchParams.set("state", state);
    window.location.assign(callbackUrl.toString());
  };

  const displayClientName = clientId?.includes('-')
    ? 'MCP Client'
    : clientId;

  return (
    <div className="oauth-consent">
      <div className="consent-card">
        <h2>Authorize Access</h2>
        <p>
          <strong>{displayClientName}</strong> wants to access your account.
        </p>

        {error && <div className="consent-error">{error}</div>}

        <div className="consent-scopes">
          <p>Permissions requested</p>
          <ul>
            {scope ? scope.split(" ").map((s) => <li key={s}>{s}</li>) : <li>openid</li>}
          </ul>
        </div>

        <div className="consent-actions">
          <button onClick={handleDeny} disabled={isSubmitting}>
            Deny
          </button>
          <button onClick={handleApprove} disabled={isSubmitting}>
            {isSubmitting ? "Authorizing..." : "Approve"}
          </button>
        </div>
      </div>
    </div>
  );
}

function SignInFirst() {
  const { signIn } = useAuthActions();
  const [isLoading, setIsLoading] = useState(false);

  const handleSignIn = async () => {
    setIsLoading(true);
    try {
      await signIn("anonymous");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="oauth-consent">
      <div className="consent-card">
        <h2>Sign In Required</h2>
        <p>You need to sign in before authorizing this application.</p>
        <div className="consent-actions">
          <button onClick={handleSignIn} disabled={isLoading}>
            {isLoading ? "Signing in..." : "Sign in anonymously"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function OAuthConsent() {
  return (
    <>
      <Authenticated>
        <ConsentForm />
      </Authenticated>
      <Unauthenticated>
        <SignInFirst />
      </Unauthenticated>
    </>
  );
}
