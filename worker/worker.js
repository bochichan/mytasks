// Cloudflare Worker - mytasks OAuth proxy
// 環境変数: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET, KV

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const DRIVE_UPLOAD = 'https://www.googleapis.com/upload/drive/v3';
const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
const REDIRECT_URI = 'https://mytasks.kinoerumesu2000.workers.dev/callback';
const APP_ORIGIN = 'https://bochichan.github.io';
const FILE_NAME = 'tasks.json';

// ── CORS ──
function corsHeaders(origin) {
  const allowed = [APP_ORIGIN, 'https://mytasks.kinoerumesu2000.workers.dev'];
  const o = allowed.includes(origin) ? origin : APP_ORIGIN;
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function json(data, status = 200, origin = APP_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

// ── セッション ──
async function makeSessionId() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

function getBearerSid(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null;
}

// ── トークン管理 ──
async function saveTokens(sid, tokens, env) {
  await env.KV.put(`session:${sid}`, JSON.stringify({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_at: Date.now() + (tokens.expires_in || 3600) * 1000,
  }), { expirationTtl: 60 * 60 * 24 * 30 });
}

async function getValidToken(sid, env) {
  const raw = await env.KV.get(`session:${sid}`);
  if (!raw) return null;
  const session = JSON.parse(raw);

  // トークンがまだ有効（5分余裕を持つ）
  if (session.expires_at - Date.now() > 5 * 60 * 1000) {
    return session.access_token;
  }

  // リフレッシュ
  if (!session.refresh_token) return null;
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: session.refresh_token,
      grant_type: 'refresh_token',
    }),
  });

  if (!res.ok) {
    await env.KV.delete(`session:${sid}`);
    return null;
  }

  const newTokens = await res.json();
  session.access_token = newTokens.access_token;
  session.expires_at = Date.now() + (newTokens.expires_in || 3600) * 1000;
  // refresh_tokenは新しいものが来た場合のみ更新
  if (newTokens.refresh_token) session.refresh_token = newTokens.refresh_token;

  await env.KV.put(`session:${sid}`, JSON.stringify(session), {
    expirationTtl: 60 * 60 * 24 * 30,
  });

  return session.access_token;
}

// ── Drive API プロキシ ──
async function driveRequest(method, path, accessToken, body, contentType) {
  const headers = { Authorization: `Bearer ${accessToken}` };
  if (contentType) headers['Content-Type'] = contentType;
  const res = await fetch(`https://www.googleapis.com${path}`, {
    method,
    headers,
    body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
  });
  return res;
}

async function findTaskFile(accessToken) {
  const res = await driveRequest('GET',
    `/drive/v3/files?spaces=appDataFolder&q=name='${FILE_NAME}'&fields=files(id)`,
    accessToken);
  const data = await res.json();
  return data.files?.[0]?.id || null;
}

async function readTaskFile(fileId, accessToken) {
  const res = await driveRequest('GET', `/drive/v3/files/${fileId}?alt=media`, accessToken);
  return await res.json();
}

async function createTaskFile(content, accessToken) {
  const boundary = 'tasks_boundary';
  const meta = JSON.stringify({ name: FILE_NAME, parents: ['appDataFolder'] });
  const bodyStr = `--${boundary}\r\nContent-Type: application/json\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(content)}\r\n--${boundary}--`;
  const res = await fetch(`${DRIVE_UPLOAD}/files?uploadType=multipart&fields=id`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': `multipart/related; boundary=${boundary}`,
    },
    body: bodyStr,
  });
  return (await res.json()).id;
}

async function updateTaskFile(fileId, content, accessToken) {
  await fetch(`${DRIVE_UPLOAD}/files/${fileId}?uploadType=media`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(content),
  });
}

// ══════════════════════
//   ROUTES
// ══════════════════════
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || APP_ORIGIN;
    const sid = getBearerSid(request);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // ── /login ── Googleの認証画面にリダイレクト
    if (url.pathname === '/login') {
      const state = await makeSessionId();
      await env.KV.put(`state:${state}`, '1', { expirationTtl: 600 });
      const authUrl = new URL(GOOGLE_AUTH_URL);
      authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
      authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', SCOPE);
      authUrl.searchParams.set('access_type', 'offline');
      authUrl.searchParams.set('prompt', 'consent');
      authUrl.searchParams.set('state', state);
      return Response.redirect(authUrl.toString(), 302);
    }

    // ── /callback ── Googleからのリダイレクト先
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      const stateValid = await env.KV.get(`state:${state}`);
      if (!stateValid) return new Response('Invalid state', { status: 400 });
      await env.KV.delete(`state:${state}`);

      const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code',
        }),
      });

      if (!tokenRes.ok) return new Response('Token exchange failed', { status: 500 });
      const tokens = await tokenRes.json();

      const newSid = await makeSessionId();
      await saveTokens(newSid, tokens, env);

      // GitHub Pagesのアプリに戻す。sidはURLフラグメントで渡す
      // （サーバーに送られず、Cookieに頼らないためFirefoxのTotal Cookie Protection等の
      //   クロスサイトCookie分離の影響を受けない）
      return Response.redirect(`${APP_ORIGIN}/mytasks/#login=ok&sid=${newSid}`, 302);
    }

    // ── /auth/status ── ログイン状態確認
    if (url.pathname === '/auth/status') {
      if (!sid) return json({ loggedIn: false }, 200, origin);
      const token = await getValidToken(sid, env);
      return json({ loggedIn: !!token }, 200, origin);
    }

    // ── /auth/logout ──
    if (url.pathname === '/auth/logout') {
      if (sid) await env.KV.delete(`session:${sid}`);
      return json({ ok: true }, 200, origin);
    }

    // ── /tasks (GET) ── タスク読み込み
    if (url.pathname === '/tasks' && request.method === 'GET') {
      if (!sid) return json({ error: 'unauthorized' }, 401, origin);
      const token = await getValidToken(sid, env);
      if (!token) return json({ error: 'unauthorized' }, 401, origin);

      const fileId = await findTaskFile(token);
      if (!fileId) {
        const empty = { nodes: [], inbox: [] };
        await createTaskFile(empty, token);
        return json(empty, 200, origin);
      }
      const data = await readTaskFile(fileId, token);
      // KVにfileIdをキャッシュ
      await env.KV.put(`fileid:${sid}`, fileId, { expirationTtl: 60 * 60 * 24 * 30 });
      return json(data, 200, origin);
    }

    // ── /tasks (POST) ── タスク保存
    if (url.pathname === '/tasks' && request.method === 'POST') {
      if (!sid) return json({ error: 'unauthorized' }, 401, origin);
      const token = await getValidToken(sid, env);
      if (!token) return json({ error: 'unauthorized' }, 401, origin);

      const body = await request.json();

      let fileId = await env.KV.get(`fileid:${sid}`);
      if (!fileId) fileId = await findTaskFile(token);

      if (fileId) {
        await updateTaskFile(fileId, body, token);
      } else {
        fileId = await createTaskFile(body, token);
        await env.KV.put(`fileid:${sid}`, fileId, { expirationTtl: 60 * 60 * 24 * 30 });
      }

      return json({ ok: true }, 200, origin);
    }
    // ── /api/setup-key (POST) ── APIキーを生成・保存
    if (url.pathname === '/api/setup-key' && request.method === 'POST') {
      if (!sid) return json({ error: 'unauthorized' }, 401, origin);
      const token = await getValidToken(sid, env);
      if (!token) return json({ error: 'unauthorized' }, 401, origin);
      const apiKey = await makeSessionId();
      await env.KV.put(`apikey:${apiKey}`, sid, { expirationTtl: 60 * 60 * 24 * 365 });
      return json({ key: apiKey }, 200, origin);
    }

    // ── /api/inbox (POST) ── APIキー認証でInboxに追加
    if (url.pathname === '/api/inbox' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization') || '';
      const apiKey = authHeader.replace('Bearer ', '').trim();
      if (!apiKey) return json({ error: 'unauthorized' }, 401, origin);
      const userSid = await env.KV.get(`apikey:${apiKey}`);
      if (!userSid) return json({ error: 'unauthorized' }, 401, origin);
      const token = await getValidToken(userSid, env);
      if (!token) return json({ error: 'session_expired' }, 401, origin);
      const body = await request.json();
      const title = body.title?.trim();
      if (!title) return json({ error: 'title required' }, 400, origin);
      let fileId = await env.KV.get(`fileid:${userSid}`);
      if (!fileId) fileId = await findTaskFile(token);
      let data = { nodes: [], inbox: [] };
      if (fileId) {
        data = await readTaskFile(fileId, token);
      }
      const newItem = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2),
        title,
        createdAt: Date.now(),
      };
      data.inbox = [newItem, ...(data.inbox || [])];
      if (fileId) {
        await updateTaskFile(fileId, data, token);
      } else {
        fileId = await createTaskFile(data, token);
        await env.KV.put(`fileid:${userSid}`, fileId, { expirationTtl: 60 * 60 * 24 * 30 });
      }
      return json({ ok: true, id: newItem.id }, 200, origin);
    }
    return new Response('Not found', { status: 404 });
  },
};
