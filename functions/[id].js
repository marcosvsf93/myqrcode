// QR dinâmico com programação no primeiro acesso.
// Requer: KV namespace ligado com o nome QR_LINKS
//         variável secreta ADMIN_PASSWORD

const ID_REGEX = /^[a-zA-Z0-9_-]{1,60}$/;

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

export async function onRequestGet({ request, env, params, next }) {
  const id = params.id;
  if (!ID_REGEX.test(id)) return next();
  if (!env.QR_LINKS || !env.ADMIN_PASSWORD) return configError();

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

export async function onRequestPost({ request, env, params, next }) {
  const id = params.id;
  if (!ID_REGEX.test(id)) return next();
  if (!env.QR_LINKS || !env.ADMIN_PASSWORD) return configError();

  const atual = await env.QR_LINKS.get(id);
  const data = await request.formData();
  const senha = String(data.get("senha") || "");
  const acao = String(data.get("acao") || "salvar");

  if (!(await safeEqual(senha, env.ADMIN_PASSWORD))) {
    return formPage(id, atual, "Senha incorreta.", 401);
  }

  if (acao === "apagar") {
    await env.QR_LINKS.delete(id);
    return page(
      "Programação apagada",
      `<h1>Programação apagada</h1><p>O próximo acesso a <code>/${esc(id)}</code> vai pedir um novo destino.</p>`
    );
  }

  let destino = String(data.get("destino") || "").trim();
  if (!/^https?:\/\//i.test(destino)) destino = "https://" + destino;

  let parsed;
  try {
    parsed = new URL(destino);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("protocolo");
  } catch {
    return formPage(id, atual, "Link inválido. Confira o endereço.", 400);
  }
  if (parsed.host === new URL(request.url).host) {
    return formPage(id, atual, "O destino não pode ser o próprio endereço do QR.", 400);
  }

  await env.QR_LINKS.put(id, parsed.href);
  return page(
    "Salvo!",
    `<h1>Pronto! ✅</h1>
     <p><code>/${esc(id)}</code> agora leva para:</p>
     <p><code>${esc(parsed.href)}</code></p>
     <a class="btn" href="/${esc(id)}">Testar agora</a>
     <p style="margin-top:1rem">Para alterar depois, acesse <code>/${esc(id)}?editar</code></p>`
  );
}
