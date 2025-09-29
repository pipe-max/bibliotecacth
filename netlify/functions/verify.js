// netlify/functions/verify.js
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { credential } = JSON.parse(event.body || '{}');
    if (!credential) {
      return { statusCode: 400, body: 'Missing credential' };
    }

    // Verifica el id_token que manda Google (popup)
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload(); // { email, name, picture, hd, ... }
    const email = (payload.email || '').toLowerCase();

    // Reglas de acceso
    const allowedDomain = (process.env.ALLOWED_DOMAIN || '').toLowerCase().trim();
    const allowedEmails = (process.env.ALLOWED_EMAILS || '')
      .toLowerCase()
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);

    let autorizado = false;
    if (allowedEmails.length && allowedEmails.includes(email)) autorizado = true;
    if (!autorizado && allowedDomain && email.endsWith('@' + allowedDomain)) autorizado = true;
    // Si no configuraste nada, deja pasar solo el email verificado de Google:
    if (!autorizado && !allowedDomain && !allowedEmails.length && payload.email_verified) {
      autorizado = true;
    }

    if (!autorizado) {
      return { statusCode: 403, body: 'No autorizado' };
    }

    // Creamos una cookie muy simple firmada (válida 8h)
    const data = JSON.stringify({ email, exp: Date.now() + 8 * 3600 * 1000 });
    const sig = crypto
      .createHmac('sha256', process.env.SESSION_SECRET || 'dev')
      .update(data)
      .digest('hex');
    const value = Buffer.from(`${data}.${sig}`).toString('base64url');

    return {
      statusCode: 200,
      headers: {
        'Set-Cookie': `cth_session=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${8 * 3600}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, name: payload.name, picture: payload.picture }),
    };
  } catch (err) {
    console.error(err);
    return { statusCode: 401, body: 'Token inválido' };
  }
};
