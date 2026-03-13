
export async function handler() {
  return { statusCode: 200, headers: { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure' }, body: 'ok' };
}
