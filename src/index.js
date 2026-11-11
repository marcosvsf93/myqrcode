// QR dinâmico: programação no primeiro acesso + gerenciador do administrador.
// Requer: KV namespace "QR_LINKS", secret "ADMIN_PASSWORD" e binding "ASSETS".

import MANAGER_HTML from "./manager.html";

const ID_REGEX = /^[a-zA-Z0-9_-]{1,60}$/;
const SESSION_SECONDS = 60 * 60 * 8; // login vale 8 horas
const MAX_FAILS = 5;                 // tentativas erradas por IP...
const LOCK_SECONDS = 15 * 60;        // ...antes de bloquear por 15 min

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page(title, content, status = 200) {
  const body = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<style>
  :root { --bg:#f5f5f5; --card:#fff; --text:#222; --muted:#666; --border:#ccc; --accent:#2563eb; --danger:#b91c1c; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#161616; --card:#222; --text:#eee; --muted:#aaa; --border:#444; --accent:#60a5fa; --danger:#f87171; }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:1rem; background:var(--bg); color:var(--text); font-family:system-ui,sans-serif; }
  main { width:100%; max-width:420px; background:var(--card); border-radius:12px; padding:1.5rem; box-shadow:0 2px 12px rgba(0,0,0,.12); }
  h1 { font-size:1.3rem; margin:0 0 .5rem; }
  p { color:var(--muted); line-height:1.4; margin:.4rem 0 1rem; }
  code { background:var(--bg); padding:.1rem .4rem; border-radius:4px; word-break:break-all; }
  label { display:block; font-weight:600; margin:1rem 0 .3rem; }
  input { width:100%; padding:.7rem; font-size:1rem; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); }
  button, .btn { display:block; width:100%; margin-top:1rem; padding:.8rem; font-size:1rem; font-weight:600; border:0; border-radius:8px; background:var(--accent); color:#fff; cursor:pointer; text-align:center; text-decoration:none; }
  button.danger { background:transparent; color:var(--danger); border:1px solid var(--danger); }
  .erro { color:var(--danger); font-weight:600; margin:.5rem 0; }
</style>
</head>
<body><main>${content}</main></body>
</html>`;
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex",
    },
  });
}

function formPage(id, atual, erro = "", status = 200) {
  const editando = Boolean(atual);
  return page(
    editando ? "Editar QR code" : "Programar QR code",
    `<h1>${editando ? "Editar QR code" : "Programar QR code"}</h1>
     <p>Placa: <code>/${esc(id)}</code></p>
     <p>${editando ? "Altere o destino deste QR code." : "Este QR code ainda não foi programado. Para onde ele deve levar?"}</p>
     ${erro ? `<div class="erro">${esc(erro)}</div>` : ""}
     <form method="POST" autocomplete="off">
       <label for="destino">Link de destino</label>
       <input id="destino" name="destino" type="text" inputmode="url" placeholder="https://..." value="${esc(atual || "")}" required>
       <label for="senha">Senha de administrador</label>
       <input id="senha" name="senha" type="password" required>
       <button type="submit" name="acao" value="salvar">Salvar</button>
       ${editando ? `<button type="submit" name="acao" value="apagar" class="danger" formnovalidate>Apagar programação</button>` : ""}
     </form>`,
    status
  );
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

const configError = () =>
  page("Configuração incompleta", `<h1>Configuração incompleta</h1><p>Faltam o KV <code>QR_LINKS</code> ou a variável <code>ADMIN_PASSWORD</code> no Cloudflare.</p>`, 500);

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=UTF-8", "Cache-Control": "no-store" },
  });

const sameOrigin = (request) => {
  const o = request.headers.get("Origin");
  return !o || o === new URL(request.url).origin;
};

/* ---------- senha, bloqueio de tentativas e sessão ---------- */

// Retorna "ok", "wrong" ou "locked"
async function checkPassword(request, env, senha) {
  const key = "rl:" + (request.headers.get("CF-Connecting-IP") || "desconhecido");
  const fails = parseInt((await env.QR_LINKS.get(key)) || "0", 10);
  if (fails >= MAX_FAILS) return "locked";
  if (await safeEqual(senha, env.ADMIN_PASSWORD)) {
    if (fails > 0) await env.QR_LINKS.delete(key);
    return "ok";
  }
  await env.QR_LINKS.put(key, String(fails + 1), { expirationTtl: LOCK_SECONDS });
  return "wrong";
}

const passwordMessage = (r) =>
  r === "locked" ? "Muitas tentativas erradas. Aguarde 15 minutos." : "Senha incorreta.";

async function hmacHex(secret, msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function makeToken(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  return exp + "." + (await hmacHex(env.ADMIN_PASSWORD, "sessao:" + exp));
}

async function isAdmin(request, env) {
  const m = /(?:^|;\s*)qr_admin=([^;]+)/.exec(request.headers.get("Cookie") || "");
  if (!m) return false;
  const [exp, sig] = m[1].split(".");
  if (!exp || !sig || !(Number(exp) > Date.now() / 1000)) return false;
  return safeEqual(sig, await hmacHex(env.ADMIN_PASSWORD, "sessao:" + exp));
}

const cookie = (value, maxAge) =>
  `qr_admin=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;

/* ---------- dados ---------- */

function normalizeUrl(input, host) {
  let destino = String(input || "").trim();
  if (!/^https?:\/\//i.test(destino)) destino = "https://" + destino;
  let parsed;
  try {
    parsed = new URL(destino);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("protocolo");
  } catch {
    return { ok: false, error: "Link inválido. Confira o endereço." };
  }
  if (parsed.host === host) return { ok: false, error: "O destino não pode ser o próprio endereço do QR." };
  return { ok: true, href: parsed.href };
}

// O destino fica no valor da chave; os metadados (limite de 1 KB) guardam uma cópia
// para a lista do gerenciador não precisar ler chave por chave.
async function saveLink(env, id, href, label) {
  const meta = { t: Date.now() };
  const nome = String(label || "").trim().slice(0, 60);
  if (nome) meta.n = nome;
  if (new TextEncoder().encode(href).length <= 600) meta.u = href;
  await env.QR_LINKS.put(id, href, { metadata: meta });
}

async function listAll(env) {
  const items = [];
  let cursor;
  do {
    const res = await env.QR_LINKS.list({ cursor, limit: 1000 });
    for (const k of res.keys) {
      if (k.name.includes(":")) continue; // chaves internas (bloqueio de tentativas)
      const meta = k.metadata || {};
      const url = meta.u || (await env.QR_LINKS.get(k.name)) || "";
      items.push({ id: k.name, url, label: meta.n || "", t: meta.t || 0 });
    }
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  items.sort((a, b) => a.id.localeCompare(b.id));
  return items;
}

/* ---------- área do administrador ---------- */

function loginPage(erro = "", status = 200) {
  return page(
    "Entrar",
    `<h1>Gerenciador de QR codes</h1>
     <p>Acesso restrito ao administrador.</p>
     ${erro ? `<div class="erro">${esc(erro)}</div>` : ""}
     <form method="POST" action="/_/login">
       <label for="senha">Senha de administrador</label>
       <input id="senha" name="senha" type="password" required autofocus>
       <button type="submit">Entrar</button>
     </form>`,
    status
  );
}

const redirect = (location, setCookie) =>
  new Response(null, {
    status: 303,
    headers: { Location: location, "Cache-Control": "no-store", ...(setCookie ? { "Set-Cookie": setCookie } : {}) },
  });

async function handleHome(request, env) {
  if (!["GET", "HEAD"].includes(request.method)) return new Response("Método não permitido", { status: 405 });
  if (await isAdmin(request, env)) {
    return new Response(MANAGER_HTML, {
      headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
    });
  }
  return loginPage();
}

async function handleAdmin(request, env, path) {
  const method = request.method;

  if (method === "POST" && !sameOrigin(request)) return json({ error: "Origem não permitida" }, 403);

  if (path === "/_/login" && method === "POST") {
    const data = await request.formData();
    const r = await checkPassword(request, env, String(data.get("senha") || ""));
    if (r !== "ok") return loginPage(passwordMessage(r), r === "locked" ? 429 : 401);
    return redirect("/", cookie(await makeToken(env), SESSION_SECONDS));
  }

  if (path === "/_/logout" && method === "POST") return redirect("/", cookie("", 0));

  if (!(await isAdmin(request, env))) return json({ error: "Não autorizado" }, 401);

  if (path === "/_/api/list" && method === "GET") return json({ items: await listAll(env) });

  if (path === "/_/api/save" && method === "POST") {
    const body = await request.json().catch(() => null);
    const id = String(body?.id || "").trim();
    if (!ID_REGEX.test(id)) return json({ error: "Nome inválido. Use letras, números, - ou _ (até 60 caracteres)." }, 400);
    const r = normalizeUrl(body?.url, new URL(request.url).host);
    if (!r.ok) return json({ error: r.error }, 400);
    await saveLink(env, id, r.href, body?.label);
    return json({ ok: true });
  }

  if (path === "/_/api/delete" && method === "POST") {
    const body = await request.json().catch(() => null);
    const id = String(body?.id || "").trim();
    if (!ID_REGEX.test(id)) return json({ error: "Nome inválido." }, 400);
    await env.QR_LINKS.delete(id);
    return json({ ok: true });
  }

  return json({ error: "Não encontrado" }, 404);
}

/* ---------- páginas públicas dos QR codes ---------- */

async function handleGet(request, env, id) {
  const destino = await env.QR_LINKS.get(id);
  const editar = new URL(request.url).searchParams.has("editar");

  if (destino && !editar) {
    return new Response(null, {
      status: 302,
      headers: { Location: destino, "Cache-Control": "no-store" },
    });
  }
  return formPage(id, destino);
}

async function handlePost(request, env, id) {
  if (!sameOrigin(request)) return new Response("Origem não permitida", { status: 403 });

  const { value: atual, metadata } = await env.QR_LINKS.getWithMetadata(id);
  const data = await request.formData();
  const acao = String(data.get("acao") || "salvar");

  const r = await checkPassword(request, env, String(data.get("senha") || ""));
  if (r !== "ok") return formPage(id, atual, passwordMessage(r), r === "locked" ? 429 : 401);

  if (acao === "apagar") {
    await env.QR_LINKS.delete(id);
    return page(
      "Programação apagada",
      `<h1>Programação apagada</h1><p>O próximo acesso a <code>/${esc(id)}</code> vai pedir um novo destino.</p>`
    );
  }

  const n = normalizeUrl(data.get("destino"), new URL(request.url).host);
  if (!n.ok) return formPage(id, atual, n.error, 400);

  await saveLink(env, id, n.href, metadata?.n);
  return page(
    "Salvo!",
    `<h1>Pronto! ✅</h1>
     <p><code>/${esc(id)}</code> agora leva para:</p>
     <p><code>${esc(n.href)}</code></p>
     <a class="btn" href="/${esc(id)}">Testar agora</a>
     <p style="margin-top:1rem">Para alterar depois, acesse <code>/${esc(id)}?editar</code></p>`
  );
}

/* ---------- roteamento ---------- */

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    const isAdminPath = path.startsWith("/_/");
    const isHome = path === "/";
    const id = path.replace(/^\/|\/$/g, "");
    const isQr = !isHome && ID_REGEX.test(id) && ["GET", "HEAD", "POST"].includes(request.method);

    // Arquivos estáticos (ex.: /qrcode.js) seguem direto
    if (!isAdminPath && !isHome && !isQr) return env.ASSETS.fetch(request);

    if (!env.QR_LINKS || !env.ADMIN_PASSWORD) return configError();

    if (isAdminPath) return handleAdmin(request, env, path);
    if (isHome) return handleHome(request, env);
    return request.method === "POST" ? handlePost(request, env, id) : handleGet(request, env, id);
  },
};
