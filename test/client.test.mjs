import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { requestAuthorization, validateConfig } from '../src/client.mjs';
import { decisionBytes, verifyDecision } from '../src/protocol.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = publicKey.export({ type: 'spki', format: 'pem' });
const credential = 'test-only-placeholder-credential'.repeat(2);
function signed(request, decision = 'approved', transform = x => x) {
  const payload = transform({ ...request, decision, decided_at: Date.now() });
  return { payload, signature: sign(null, decisionBytes(payload), privateKey).toString('base64url') };
}
async function fake(t, respond) {
  let lastRequest;
  const server = createServer(async (req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${credential}`);
    if (req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;
      lastRequest = JSON.parse(body);
    }
    const reply = respond(lastRequest, req);
    res.writeHead(reply.code ?? 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(reply.body ?? reply));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { endpoint: `http://127.0.0.1:${server.address().port}`, identity: 'test-client', publicKey: pem, allowLoopbackHttp: true };
}
const options = { summary: 'Executar ação de teste', ttl: 2, token: credential, pollMs: 5 };

test('servidor falso: aprovado', async t => {
  const config = await fake(t, r => signed(r));
  assert.equal((await requestAuthorization(config, options)).decision, 'approved');
});
test('servidor falso: recusado', async t => {
  const config = await fake(t, r => signed(r, 'denied'));
  assert.equal((await requestAuthorization(config, options)).decision, 'denied');
});
test('servidor falso: decisão com relógio 3 segundos à frente é aceita', async t => {
  const config = await fake(t, r => signed(r, 'approved', d => ({ ...d, decided_at: Date.now() + 3000 })));
  assert.equal((await requestAuthorization(config, { ...options, ttl: 30 })).decision, 'approved');
});
test('servidor falso: decisão com relógio 10 segundos à frente é recusada', async t => {
  const config = await fake(t, r => signed(r, 'approved', d => ({ ...d, decided_at: Date.now() + 10000 })));
  await assert.rejects(requestAuthorization(config, { ...options, ttl: 30 }), /invalid_decision/);
});
test('servidor falso: pendente até expirar', async t => {
  const config = await fake(t, () => ({ status: 'pending' }));
  assert.equal((await requestAuthorization(config, { ...options, ttl: 1 })).decision, 'expired');
});
test('servidor falso: assinatura inválida', async t => {
  const config = await fake(t, r => ({ ...signed(r), signature: 'A'.repeat(86) }));
  await assert.rejects(requestAuthorization(config, options), /invalid_signature/);
});
test('servidor falso: resumo alterado após assinatura', async t => {
  const config = await fake(t, r => {
    const e = signed(r);
    e.payload.summary = 'Outra ação';
    return e;
  });
  await assert.rejects(requestAuthorization(config, options), /invalid_decision/);
});
test('servidor falso: resposta repetida de outro pedido', async t => {
  let previous;
  const config = await fake(t, r => previous ??= signed(r));
  await requestAuthorization(config, options);
  await assert.rejects(requestAuthorization(config, options), /invalid_decision/);
});
test('servidor falso: identidade, prazo e versão alterados com assinatura válida', async t => {
  for (const mutation of [r => ({ ...r, requester: 'other-client' }), r => ({ ...r, expires_at: r.expires_at + 1000 }), r => ({ ...r, v: 2 })]) {
    const config = await fake(t, r => signed(r, 'approved', mutation));
    await assert.rejects(requestAuthorization(config, options), /invalid_decision/);
  }
});
test('servidor falso: pendente depois aprovado', async t => {
  const config = await fake(t, (r, req) => req.method === 'POST' ? { status: 'pending' } : signed(r));
  assert.equal((await requestAuthorization(config, options)).decision, 'approved');
});
test('servidor falso: erros HTTP e resposta inesperada recusam', async t => {
  for (const response of [{ code: 401, body: {} }, { status: 'approved' }]) {
    const config = await fake(t, () => response);
    await assert.rejects(requestAuthorization(config, options));
  }
});
test('servidor falso: redirecionamento não encaminha credencial', async t => {
  const config = await fake(t, () => ({ code: 302, body: {} }));
  await assert.rejects(requestAuthorization(config, options));
});

function captureStderr(t) {
  const lines = [];
  const write = process.stderr.write;
  process.stderr.write = chunk => { lines.push(String(chunk)); return true; };
  t.after(() => { process.stderr.write = write; });
  return lines;
}
test('servidor falso: pedido esquecido é reenviado uma vez e aprovado pelo novo id', async t => {
  const posts = [];
  const config = await fake(t, (r, req) => {
    if (req.method === 'POST') { posts.push(r); return { status: 'pending' }; }
    return req.url.endsWith(`/${posts[0].id}`) ? { code: 404, body: {} } : signed(r);
  });
  const lines = captureStderr(t);
  const result = await requestAuthorization(config, { ...options, ttl: 60 });
  assert.equal(result.decision, 'approved');
  assert.equal(posts.length, 2);
  assert.notEqual(posts[1].id, posts[0].id);
  assert.equal(posts[1].expires_at, posts[0].expires_at);
  assert.ok(posts[1].created_at >= posts[0].created_at);
  assert.equal(posts[1].summary, posts[0].summary);
  assert.equal(posts[1].requester, posts[0].requester);
  assert.equal(result.id, posts[1].id);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /reenviado/);
});
test('servidor falso: segundo pedido esquecido não é reenviado de novo', async t => {
  const posts = [];
  const config = await fake(t, (r, req) => {
    if (req.method === 'POST') { posts.push(r); return { status: 'pending' }; }
    return { code: 404, body: {} };
  });
  const lines = captureStderr(t);
  await assert.rejects(requestAuthorization(config, { ...options, ttl: 60 }), /server_error/);
  assert.equal(posts.length, 2);
  assert.equal(lines.length, 1);
});
test('servidor falso: pedido esquecido com menos de 30 segundos não é reenviado', async t => {
  const posts = [];
  const config = await fake(t, (r, req) => {
    if (req.method === 'POST') { posts.push(r); return { status: 'pending' }; }
    return { code: 404, body: {} };
  });
  const lines = captureStderr(t);
  assert.equal((await requestAuthorization(config, options)).decision, 'expired');
  assert.equal(posts.length, 1);
  assert.equal(lines.length, 0);
});
test('servidor falso: decisão assinada para o pedido esquecido não vale para o reenvio', async t => {
  const posts = [];
  const config = await fake(t, (r, req) => {
    if (req.method === 'POST') { posts.push(r); return { status: 'pending' }; }
    return req.url.endsWith(`/${posts[0].id}`) ? { code: 404, body: {} } : signed(posts[0]);
  });
  captureStderr(t);
  await assert.rejects(requestAuthorization(config, { ...options, ttl: 60 }), /invalid_decision/);
  assert.equal(posts.length, 2);
});
test('prazo vencido e decisão futura não autorizam', () => {
  const now = Date.now();
  const request = { v: 1, id: 'a'.repeat(64), requester: 'test-client', summary: 'Teste', created_at: now - 2000, expires_at: now - 1000 };
  const envelope = signed(request, 'approved', d => ({ ...d, decided_at: now - 1500 }));
  assert.equal(verifyDecision(envelope, request, pem, now), 'expired');
  assert.throws(() => verifyDecision(signed(request), request, pem, now), /invalid_decision/);
});
test('TLS obrigatório fora de loopback e chave Ed25519 obrigatória', () => {
  const withCredentials = new URL('https://example.invalid');
  withCredentials.username = 'user';
  withCredentials.password = 'password';
  for (const endpoint of ['http://example.invalid', 'https://example.invalid/path', withCredentials.href]) {
    assert.throws(() => validateConfig({ endpoint, publicKey: pem, allowLoopbackHttp: true }));
  }
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => validateConfig({ endpoint: 'https://example.invalid', publicKey: rsa }));
});
test('entradas inválidas não chegam à rede', async () => {
  const config = { endpoint: 'https://example.invalid', identity: 'test-client', publicKey: pem };
  for (const summary of ['', 'A\nB', 'A\u202eB', 'x'.repeat(501)]) {
    await assert.rejects(requestAuthorization(config, { ...options, summary }), /invalid_request/);
  }
});
