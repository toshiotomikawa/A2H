import { randomBytes, createPublicKey } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { validRequest, verifyDecision } from './protocol.mjs';

export const EXIT = Object.freeze({ approved: 0, denied: 1, expired: 2, invalid: 3, error: 4 });

// A forgotten pending request is resubmitted only while this much time is left.
const RESEND_MIN_MS = 30000;

export function validateConfig(config) {
  const url = new URL(config.endpoint);
  const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(config.allowLoopbackHttp === true && loopback && url.protocol === 'http:'))
    || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('invalid_config');
  if (createPublicKey(config.publicKey).asymmetricKeyType !== 'ed25519') throw new Error('invalid_config');
  return url.origin;
}

export async function requestAuthorization(config, { summary, ttl = 300, token, pollMs = 1000 }) {
  const base = validateConfig(config);
  if (typeof token !== 'string' || token.length < 32 || /\s/.test(token)) throw new Error('missing_credential');
  const created_at = Date.now();
  const expires_at = created_at + ttl * 1000;
  let request = { v: 1, id: randomBytes(32).toString('hex'), requester: config.identity,
    summary, created_at, expires_at };
  if (!Number.isInteger(ttl) || !validRequest(request)) throw new Error('invalid_request');
  const deadline = performance.now() + ttl * 1000;
  const remaining = () => Math.min(expires_at - Date.now(), deadline - performance.now());
  async function exchange(path, body) {
    const response = await fetch(base + path, {
      method: body ? 'POST' : 'GET', redirect: 'error',
      headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(Math.max(1, Math.ceil(Math.min(10000, remaining())))),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(response.status === 404 ? 'not_found' : 'server_error');
    }
    let size = 0;
    const chunks = [];
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 16384) throw new Error('invalid_decision');
      chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }
  let result;
  let resent = false;
  try {
    result = await exchange('/actions/a2h/requests', request);
    while (remaining() > 0) {
      if (result?.payload) {
        const decision = verifyDecision(result, request, config.publicKey);
        return { decision, id: request.id, expires_at: request.expires_at };
      }
      if (!result || Object.keys(result).length !== 1 || result.status !== 'pending') throw new Error('invalid_decision');
      await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.min(pollMs, remaining()))));
      if (remaining() <= 0) break;
      try {
        result = await exchange(`/actions/a2h/requests/${request.id}`);
      } catch (error) {
        if (error?.message !== 'not_found') throw error;
        // The server forgot the pending request; the only fallback is one brand-new request.
        if (resent) throw new Error('server_error');
        if (remaining() < RESEND_MIN_MS) return { decision: 'expired', id: request.id, expires_at: request.expires_at };
        resent = true;
        request = { v: 1, id: randomBytes(32).toString('hex'), requester: request.requester,
          summary: request.summary, created_at: Date.now(), expires_at };
        if (!validRequest(request)) throw new Error('invalid_request');
        process.stderr.write('a2h: pedido não encontrado no servidor; reenviado uma vez como pedido novo\n');
        result = await exchange('/actions/a2h/requests', request);
      }
    }
  } catch (error) {
    if (remaining() > 0) throw error;
  }
  return { decision: 'expired', id: request.id, expires_at: request.expires_at };
}
