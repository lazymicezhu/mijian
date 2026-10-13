import { handleApi } from '../../lib/cloudflare-app.mjs';

export function onRequest(context) {
  return handleApi(context.request, context.env, context);
}
