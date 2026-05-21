export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Solo interceptar /img-proxy?url=...
    if (url.pathname === '/img-proxy') {
      const target = url.searchParams.get('url');
      if (!target) return new Response('Missing url', { status: 400 });

      try {
        // Seguir todas las redirecciones (incluidas las de goo.su)
        const imgRes = await fetch(target, {
          redirect: 'follow',
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; ImageProxy/1.0)',
            'Referer': '',
          },
        });

        const contentType = imgRes.headers.get('content-type') || 'image/jpeg';

        // Solo devolver si es una imagen
        if (!contentType.startsWith('image/')) {
          return new Response('Not an image', { status: 422 });
        }

        return new Response(imgRes.body, {
          status: 200,
          headers: {
            'Content-Type': contentType,
            'Cache-Control': 'public, max-age=86400',
            'Access-Control-Allow-Origin': '*',
          },
        });
      } catch (e) {
        return new Response('Proxy error: ' + e.message, { status: 500 });
      }
    }

    // Todo lo demás: comportamiento normal de Pages
    return env.ASSETS.fetch(request);
  },
};
