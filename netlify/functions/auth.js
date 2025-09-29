// netlify/functions/auth/auth.js
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SITE_ORIGIN,
  SESSION_SECRET,
} = process.env;

// Helpers -------------------------------------------------
function setCookie(name, value, { maxAgeSec = 3600, path = "/", secure = true } = {}) {
  const parts = [
    `${name}=${value}`,
    `Path=${path}`,
    `Max-Age=${maxAgeSec}`,
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function sign(data) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("hex");
}

// Handler -------------------------------------------------
export async function handler(event) {
  try {
    const url = new URL(event.rawUrl);
    const pathname = url.pathname; // /.netlify/functions/auth/login | /callback | /me | /logout

    // 1) LOGIN -------------------------------------------------------
    if (pathname.endsWith("/login")) {
      const redirectUri = `${SITE_ORIGIN}/.netlify/functions/auth/callback`;
      const oauth2Client = new OAuth2Client({
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        redirectUri,
      });

      const authorizeUrl = oauth2Client.generateAuthUrl({
        access_type: "offline",
        prompt: "consent",
        scope: [
          "openid",
          "email",
          "profile",
        ],
      });

      return {
        statusCode: 302,
        headers: { Location: authorizeUrl },
      };
    }

    // 2) CALLBACK ----------------------------------------------------
    if (pathname.endsWith("/callback")) {
      const code = url.searchParams.get("code");
      const error = url.searchParams.get("error");

      // Log de diagnóstico por si vuelve a fallar
      console.log("CALLBACK rawUrl:", event.rawUrl);
      console.log("CALLBACK query:", Object.fromEntries(url.searchParams.entries()));

      if (error) {
        return {
          statusCode: 400,
          body: `OAuth error from Google: ${error}`,
        };
      }
      if (!code) {
        return {
          statusCode: 400,
          body: "Missing authorization code (no 'code' in callback URL).",
        };
      }

      const redirectUri = `${SITE_ORIGIN}/.netlify/functions/auth/callback`;
      const oauth2Client = new OAuth2Client({
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        redirectUri,
      });

      // Intercambia code -> tokens
      const { tokens } = await oauth2Client.getToken(code);
      const idToken = tokens.id_token; // JWT con email, nombre, etc.

      if (!idToken) {
        console.log("Tokens recibidos:", tokens);
        return { statusCode: 400, body: "Missing ID token from Google." };
      }

      // Firma simple del token para cookie
      const sig = sign(idToken);
      const value = Buffer.from(JSON.stringify({ id: idToken, sig })).toString("base64url");

      return {
        statusCode: 302,
        headers: {
          "Set-Cookie": setCookie("session", value, { maxAgeSec: 60 * 60 * 8 }),
          Location: `${SITE_ORIGIN}/?login=ok`,
        },
      };
    }

    // 3) LOGOUT ------------------------------------------------------
    if (pathname.endsWith("/logout")) {
      return {
        statusCode: 302,
        headers: {
          "Set-Cookie": setCookie("session", "", { maxAgeSec: 0 }),
          Location: `${SITE_ORIGIN}/?logout=ok`,
        },
      };
    }

    // 4) ME (debug para ver quién sos) -------------------------------
    if (pathname.endsWith("/me")) {
      const cookie = event.headers.cookie || "";
      const m = cookie.match(/(?:^|;\s*)session=([^;]+)/);
      if (!m) return { statusCode: 401, body: "No session cookie" };

      const raw = Buffer.from(m[1], "base64url").toString();
      const { id, sig } = JSON.parse(raw);
      if (sig !== sign(id)) return { statusCode: 401, body: "Invalid session signature" };

      // Decodifica el JWT sin verificar (solo para ver los claims)
      const payload = JSON.parse(Buffer.from(id.split(".")[1], "base64url").toString());
      return { statusCode: 200, body: JSON.stringify(payload, null, 2) };
    }

    // Ruta por defecto
    return { statusCode: 404, body: "Not found" };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, body: `Auth function error: ${err.message}` };
  }
}
