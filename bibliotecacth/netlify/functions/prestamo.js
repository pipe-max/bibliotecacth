
import { requireSession } from './helper.js';
export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: { 'Access-Control-Allow-Origin': process.env.SITE_ORIGIN || '*', 'Access-Control-Allow-Methods': 'POST,OPTIONS', 'Access-Control-Allow-Headers': 'content-type' } };
  }
  try {
    const user = requireSession(event);
    const { alumnoId, libroId, accion } = JSON.parse(event.body || '{}');
    if (!alumnoId || !libroId || !accion) return { statusCode: 400, body: 'faltan campos' };
    console.log('Prestamo/Devolucion', { by: user.email, alumnoId, libroId, accion, at: new Date().toISOString() });
    return { statusCode: 200, body: 'ok' };
  } catch (e) { return { statusCode: 401, body: 'unauthorized' }; }
}
