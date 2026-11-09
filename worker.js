/*
 Glamourless Apps license checker (Cloudflare Worker).
 Checks Payhip license keys for QuietScript and ProofStack without putting
 the Payhip product secret keys inside the apps.

 Secrets (set in Cloudflare > Worker > Settings > Variables and Secrets, type "Secret"):
   QUIETSCRIPT_SECRET   Payhip product secret key for QuietScript
   PROOFSTACK_SECRET    Payhip product secret key for ProofStack

 Endpoints (POST, JSON body {"app":"quietscript"|"proofstack","key":"XXXXX-..."}):
   /activate    checks the key and uses one of the 2 device slots
   /check       checks the key is still valid (refunded keys come back invalid)
   /deactivate  gives a device slot back
*/

const DEVICE_LIMIT = 2;
const ALLOWED_ORIGINS = [
  'https://www.glamourlessapps.com',
  'https://glamourlessapps.com',
  'https://proofstack.glamourlessapps.com',
  'https://proofstack-63q.pages.dev'
];
const API = 'https://payhip.com/api/v2/license';

function cors(origin) {
  const ok = ALLOWED_ORIGINS.includes(origin) || /^https:\/\/[a-z0-9-]+\.proofstack-63q\.pages\.dev$/.test(origin || '');
  return {
    'Access-Control-Allow-Origin': ok ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

function reply(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...cors(origin) }
  });
}

function maskEmail(e) {
  if (!e || e.indexOf('@') < 1) return '';
  const [u, d] = e.split('@');
  return u.slice(0, 2) + '***@' + d;
}

async function payhip(method, path, secret, key) {
  const init = { method, headers: { 'product-secret-key': secret } };
  let url = API + path;
  if (method === 'GET') url += '?license_key=' + encodeURIComponent(key);
  else {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = 'license_key=' + encodeURIComponent(key);
  }
  const res = await fetch(url, init);
  const text = await res.text();
  if (res.status === 401) throw new Error('auth');
  if (!text.trim()) return null;
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  return j && j.data ? j.data : null;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    const path = new URL(request.url).pathname;
    if (request.method === 'GET' && path === '/') return reply({ ok: true, service: 'glamourless-license' }, 200, origin);
    if (request.method !== 'POST') return reply({ ok: false, reason: 'method' }, 405, origin);

    let body;
    try { body = await request.json(); } catch { return reply({ ok: false, reason: 'bad_request' }, 400, origin); }
    const app = String(body.app || '').toLowerCase();
    const key = String(body.key || '').trim().toUpperCase();
    const secret = app === 'quietscript' ? env.QUIETSCRIPT_SECRET : app === 'proofstack' ? env.PROOFSTACK_SECRET : null;
    if (!secret) return reply({ ok: false, reason: 'unknown_app' }, 400, origin);
    if (!/^[A-Z0-9-]{10,64}$/.test(key)) return reply({ ok: false, reason: 'not_found' }, 200, origin);

    try {
      const lic = await payhip('GET', '/verify', secret, key);
      if (!lic) return reply({ ok: false, reason: 'not_found' }, 200, origin);
      if (!lic.enabled) return reply({ ok: false, reason: 'disabled' }, 200, origin);
      const uses = Number(lic.uses || 0);
      const info = { email: maskEmail(lic.buyer_email), limit: DEVICE_LIMIT };

      if (path === '/check') return reply({ ok: true, uses, ...info }, 200, origin);

      if (path === '/activate') {
        if (uses >= DEVICE_LIMIT) return reply({ ok: false, reason: 'limit', uses, ...info }, 200, origin);
        const after = await payhip('PUT', '/usage', secret, key);
        return reply({ ok: true, uses: after ? Number(after.uses) : uses + 1, ...info }, 200, origin);
      }

      if (path === '/deactivate') {
        let left = uses;
        if (uses > 0) { const after = await payhip('PUT', '/decrease', secret, key); left = after ? Number(after.uses) : uses - 1; }
        return reply({ ok: true, uses: left, ...info }, 200, origin);
      }

      return reply({ ok: false, reason: 'not_found_path' }, 404, origin);
    } catch (e) {
      return reply({ ok: false, reason: e.message === 'auth' ? 'server_setup' : 'server_error' }, 502, origin);
    }
  }
};
