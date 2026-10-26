import { createPublicKey, verify } from 'node:crypto';

export const REQUEST_FIELDS = ['v', 'id', 'requester', 'summary', 'created_at', 'expires_at'];
export const DECISION_FIELDS = [...REQUEST_FIELDS, 'decision', 'decided_at'];
const exact = (value, fields) => value && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every(k => Object.hasOwn(value, k));

export function validRequest(r) {
  return exact(r, REQUEST_FIELDS) && r.v === 1 && /^[a-f0-9]{64}$/.test(r.id)
    && typeof r.requester === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(r.requester)
    && typeof r.summary === 'string' && r.summary.length >= 1 && r.summary.length <= 500
    && !/[\p{C}]/u.test(r.summary) && r.summary === r.summary.trim()
    && Number.isSafeInteger(r.created_at) && Number.isSafeInteger(r.expires_at)
    && r.created_at > 0 && r.expires_at - r.created_at >= 1000
    && r.expires_at - r.created_at <= 3600000;
}

// Fixed positional UTF-8 encoding; no object-order or delimiter ambiguity.
export function decisionBytes(d) {
  return Buffer.from(JSON.stringify(['A2H-DECISION-v1', ...DECISION_FIELDS.map(k => d[k])]), 'utf8');
}

export function verifyDecision(envelope, expected, publicKey, now = Date.now()) {
  if (!validRequest(expected) || !exact(envelope, ['payload', 'signature'])) throw new Error('invalid_decision');
  const d = envelope.payload;
  if (!exact(d, DECISION_FIELDS) || !REQUEST_FIELDS.every(k => d[k] === expected[k])
    || !['approved', 'denied', 'expired'].includes(d.decision)
    || !Number.isSafeInteger(d.decided_at) || d.decided_at < d.created_at
    || d.decided_at > now || now < d.created_at
    || (d.decision === 'expired' ? d.decided_at < d.expires_at : d.decided_at >= d.expires_at)
    || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) {
    throw new Error('invalid_decision');
  }
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519'
    || !verify(null, decisionBytes(d), key, Buffer.from(envelope.signature, 'base64url'))) {
    throw new Error('invalid_signature');
  }
  if (now >= expected.expires_at) return 'expired';
  return d.decision;
}
