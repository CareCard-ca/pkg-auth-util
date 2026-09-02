'use strict';

const { createHash, createPrivateKey, createPublicKey } = require('node:crypto');

const ED25519_KEY_BYTES = 32;
const signingKeys = new WeakMap();
const verificationKeys = new WeakMap();
const SIGNING_JWK_MEMBERS = ['alg', 'crv', 'd', 'key_ops', 'kid', 'kty', 'use', 'x'];
const VERIFICATION_JWK_MEMBERS = ['alg', 'crv', 'key_ops', 'kid', 'kty', 'use', 'x'];

function parseJsonObject(serializedValue, configurationName) {
  try {
    const value = JSON.parse(serializedValue);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new TypeError();
    }
    return value;
  } catch {
    throw new Error(`Invalid ${configurationName} configuration.`);
  }
}

function isCanonicalBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  const decodedValue = Buffer.from(value, 'base64url');
  return decodedValue.length === ED25519_KEY_BYTES && decodedValue.toString('base64url') === value;
}

function deriveJwkThumbprint(jwk) {
  const canonicalJwk = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x });
  return createHash('sha256').update(canonicalJwk).digest('base64url');
}

function hasExactKeyOperation(jwk, operation) {
  return Array.isArray(jwk.key_ops) && jwk.key_ops.length === 1 && jwk.key_ops[0] === operation;
}

function hasExactMembers(value, expectedMembers) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const members = Object.keys(value).sort();
  return (
    members.length === expectedMembers.length &&
    members.every((member, index) => member === expectedMembers[index])
  );
}

function hasValidSharedMetadata(jwk) {
  return (
    jwk.kty === 'OKP' &&
    jwk.crv === 'Ed25519' &&
    jwk.alg === 'EdDSA' &&
    jwk.use === 'sig' &&
    isCanonicalBase64Url(jwk.x) &&
    jwk.kid === deriveJwkThumbprint(jwk)
  );
}

function createSigningKey(jwk) {
  try {
    const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
    const derivedPublicJwk = createPublicKey(privateKey).export({ format: 'jwk' });
    if (derivedPublicJwk.x !== jwk.x) {
      throw new TypeError();
    }
    return privateKey;
  } catch {
    throw new Error('Invalid JWT signing JWK configuration.');
  }
}

function parseJwtSigningJwk(serializedJwk) {
  const jwk = parseJsonObject(serializedJwk, 'JWT signing JWK');
  if (!hasExactMembers(jwk, SIGNING_JWK_MEMBERS) || !hasValidSharedMetadata(jwk)) {
    throw new Error('Invalid JWT signing JWK configuration.');
  }
  if (!hasExactKeyOperation(jwk, 'sign') || !isCanonicalBase64Url(jwk.d)) {
    throw new Error('Invalid JWT signing JWK configuration.');
  }
  const parsedJwk = Object.freeze({ ...jwk, key_ops: Object.freeze(['sign']) });
  signingKeys.set(parsedJwk, createSigningKey(jwk));
  return parsedJwk;
}

function parseVerificationJwk(jwk) {
  if (!hasExactMembers(jwk, VERIFICATION_JWK_MEMBERS) || !hasValidSharedMetadata(jwk)) {
    throw new Error('Invalid JWT verification JWKS configuration.');
  }
  if (!hasExactKeyOperation(jwk, 'verify')) {
    throw new Error('Invalid JWT verification JWKS configuration.');
  }
  try {
    return [jwk.kid, createPublicKey({ key: jwk, format: 'jwk' })];
  } catch {
    throw new Error('Invalid JWT verification JWKS configuration.');
  }
}

function parseJwtVerificationJwks(serializedJwks) {
  const jwks = parseJsonObject(serializedJwks, 'JWT verification JWKS');
  if (!hasExactMembers(jwks, ['keys']) || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error('Invalid JWT verification JWKS configuration.');
  }
  const entries = jwks.keys.map(parseVerificationJwk);
  const keyMap = new Map(entries);
  if (keyMap.size !== entries.length) {
    throw new Error('Invalid JWT verification JWKS configuration.');
  }
  const parsedJwks = Object.freeze({ kids: Object.freeze([...keyMap.keys()]) });
  verificationKeys.set(parsedJwks, keyMap);
  return parsedJwks;
}

function getJwtSigningKey(signingJwk) {
  return signingKeys.get(signingJwk) ?? null;
}

function getJwtVerificationKey(jwks, kid) {
  return verificationKeys.get(jwks)?.get(kid) ?? null;
}

module.exports = {
  getJwtSigningKey,
  getJwtVerificationKey,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
};
