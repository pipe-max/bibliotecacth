
import crypto from 'node:crypto';
export function requireSession(event) {
  const secret = process.env.SESSION_SECRET;
  const m = (event.headers.cookie || '').match(/(?:^|;\s*)session=([^;]+)/);
  if (!m) throw new Error('no session');
  const [payload, sig] = m[1].split('.');
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (sig !== expected) throw new Error('bad sig');
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (Date.now() > data.exp) throw new Error('expired');
  return data;
}
