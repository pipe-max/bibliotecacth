/**
 * Netlify Function: /auth/login
 * Redirects to Google OAuth 2.0 with the proper parameters.
 * 
 * Env vars used:
 *   - GOOGLE_CLIENT_ID (required)
 *   - SITE_ORIGIN (optional, e.g. https://bibliotecacth.netlify.app)
 *   - ALLOWED_DOMAIN (optional, e.g. theodoro.edu.co to hint Google login page)
 */

const crypto = require("crypto");

exports.handler = async (event) => {
  const {
    GOOGLE_CLIENT_ID,
    SITE_ORIGIN,
    ALLOWED_DOMAIN,
  } = process.env;

  if (!GOOGLE_CLIENT_ID) {
    return {
      statusCode: 500,
      body: "Missing env var: GOOGLE_CLIENT_ID",
    };
  }

  // Figure out our origin (prod URL) if not provided explicitly
  const proto = event.headers["x-forwarded-proto"] || "https";
  const host = event.headers["x-forwarded-host"] || event.headers["host"];
  const origin = SITE_ORIGIN || `${proto}://${host}`;

  // This must match the redirect URI you put in Google Cloud
  const redirect_uri = `${origin}/.netlify/functions/auth/callback`;

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri,
    response_type: "code",
    scope: "openid email profile",
    include_granted_scopes: "true",
    access_type: "offline",
    prompt: "consent",
  });

  // If you restrict to one Google Workspace, hint it here
  if (ALLOWED_DOMAIN) {
    params.set("hd", ALLOWED_DOMAIN);
  }

  // Optional CSRF token (cookie) - your /callback can validate it
  const state = require("crypto").randomBytes(16).toString("hex");
  params.set("state", state);

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

  return {
    statusCode: 302,
    headers: {
      Location: authUrl,
      "Cache-Control": "no-store",
      "Set-Cookie": `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    },
    body: "",
  };
};
