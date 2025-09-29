// netlify/functions/auth/login.js
const SITE = process.env.SITE_ORIGIN || 'https://bibliotecacth.netlify.app';

exports.handler = async () => {
  const AUTH = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  AUTH.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
  AUTH.searchParams.set('redirect_uri', `${SITE}/.netlify/functions/auth/callback`);
  AUTH.searchParams.set('response_type', 'code');
  AUTH.searchParams.set('scope', 'openid email profile');
  AUTH.searchParams.set('access_type', 'offline');
  AUTH.searchParams.set('prompt', 'consent');
  AUTH.searchParams.set('include_granted_scopes', 'true');

  return {
    statusCode: 302,
    headers: { Location: AUTH.toString() }
  };
};
