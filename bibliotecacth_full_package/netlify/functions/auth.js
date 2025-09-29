
import { OAuth2Client } from 'google-auth-library';
import crypto from 'node:crypto';
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'theodoro.edu.co').toLowerCase();
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomUUID();
const SITE_ORIGIN = process.env.SITE_ORIGIN || 'https://bibliotecacth.netlify.app';
const cors = {
  'Access-Control-Allow-Origin': SITE_ORIGIN,
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Allow-Methods': 'POST,OPTIONS'
};
function makeCookie(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors };
  try {
    const { credential } = JSON.parse(event.body || '{}');
    if (!credential) return { statusCode: 400, headers: cors, body: 'missing token' };
    const ticket = await client.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase();
    const hd = (payload.hd || '').toLowerCase();
    const allowedByDomain = hd === ALLOWED_DOMAIN;
    const allowed = ALLOWED_EMAILS.length ? ALLOWED_EMAILS.includes(email) : allowedByDomain;
    if (!allowed) return { statusCode: 403, headers: cors, body: 'forbidden' };
    const cookie = makeCookie({ sub: payload.sub, email, exp: Date.now() + 1000*60*60*8 });
    return { statusCode: 200, headers: { ...cors, 'Set-Cookie': `session=${cookie}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60*60*8}; Secure` }, body: JSON.stringify({ ok:true, email }) };
  } catch (e) { return { statusCode: 401, headers: cors, body: 'invalid token' }; }
}
