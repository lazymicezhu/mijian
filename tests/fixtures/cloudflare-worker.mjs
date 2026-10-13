import { handleApi } from '../../lib/cloudflare-app.mjs';

export default {
  fetch(request, env, ctx) {
    // Miniflare transports dispatchFetch over localhost and replaces Host, while
    // preserving the supplied URL. Model the Host Cloudflare supplies in production.
    const headers = new Headers(request.headers);
    headers.set('Host', new URL(request.url).host);
    return handleApi(new Request(request, { headers }), env, ctx);
  },
};
