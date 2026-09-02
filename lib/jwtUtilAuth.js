'use strict';

const { sign, verify } = require('node:crypto');
const { getJwtSigningKey, getJwtVerificationKey } = require('./jwkUtilAuth');

const normalizePayload = payloadObject => {
  const payload = { ...payloadObject };
  const now = Math.floor(Date.now() / 1000);
  const fieldsToNormalize = ['iat', 'exp', 'nbf', 'auth_time'];
  const msThreshold = 1000000000000;
  if (!Number.isFinite(payload.iat)) {
    payload.iat = now;
  }
  fieldsToNormalize.forEach(field => {
    if (Number.isFinite(payload[field]) && payload[field] > msThreshold) {
      payload[field] = Math.floor(payload[field] / 1000);
    }
  });
  if (!Number.isFinite(payload.exp)) {
    payload.exp = payload.iat + 3600;
  }
  return payload;
};

const encodeJwtPart = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const decodeJwtPart = value => JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));

const isDecodedJwtObject = value => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

const isNonEmptyString = value => typeof value === 'string' && value.trim().length > 0;

const isNonEmptyAudience = audience => {
  return (
    isNonEmptyString(audience) ||
    (Array.isArray(audience) && audience.length > 0 && audience.every(isNonEmptyString))
  );
};

const normalizeSeconds = value => {
  if (!Number.isFinite(value)) {
    return null;
  }
  return value > 1000000000000 ? Math.floor(value / 1000) : Math.floor(value);
};

function createSignedJwtFromObject(payloadObject, signingJwk) {
  const privateKey = getJwtSigningKey(signingJwk);
  if (!privateKey || !isDecodedJwtObject(payloadObject)) {
    return null;
  }
  const header = { alg: 'EdDSA', typ: 'JWT', kid: signingJwk.kid };
  const token = `${encodeJwtPart(header)}.${encodeJwtPart(normalizePayload(payloadObject))}`;
  const signature = sign(null, Buffer.from(token), privateKey).toString('base64url');
  return `${token}.${signature}`;
}

function createServiceJwt({
  issuer,
  audience,
  signingJwk,
  subject = issuer,
  issuedAt = Math.floor(Date.now() / 1000),
  expiresInSeconds = 60,
  claims = {},
} = {}) {
  if (!isNonEmptyString(issuer) || !isNonEmptyAudience(audience) || !isNonEmptyString(subject)) {
    return null;
  }
  if (!Number.isInteger(expiresInSeconds) || expiresInSeconds <= 0) {
    return null;
  }
  const iat = normalizeSeconds(issuedAt);
  if (!Number.isInteger(iat) || !isDecodedJwtObject(claims)) {
    return null;
  }
  return createSignedJwtFromObject(
    { ...claims, iss: issuer, aud: audience, sub: subject, iat, exp: iat + expiresInSeconds },
    signingJwk,
  );
}

function createServiceAuthorizationHeader(options = {}) {
  const token = createServiceJwt(options);
  return token ? `Bearer ${token}` : null;
}

function hasValidJwtHeader(header) {
  return (
    isDecodedJwtObject(header) &&
    header.alg === 'EdDSA' &&
    header.typ === 'JWT' &&
    isNonEmptyString(header.kid)
  );
}

function decodeCanonicalSignature(signature) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9_-]+$/.test(signature)) {
    return null;
  }
  const decoded = Buffer.from(signature, 'base64url');
  return decoded.length === 64 && decoded.toString('base64url') === signature ? decoded : null;
}

function verifyJwtSignature(jwt, verificationJwks) {
  try {
    if (typeof jwt !== 'string') {
      return false;
    }
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return false;
    }
    const header = decodeJwtPart(parts[0]);
    const signature = decodeCanonicalSignature(parts[2]);
    const publicKey = hasValidJwtHeader(header)
      ? getJwtVerificationKey(verificationJwks, header.kid)
      : null;
    const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);
    return Boolean(publicKey && signature && verify(null, signedData, publicKey, signature));
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error;
    }
    return false;
  }
}

function getHeaderPayloadFromJwt(jwt) {
  try {
    if (typeof jwt !== 'string' || jwt.split('.').length !== 3) {
      return null;
    }
    const [headerPart, payloadPart] = jwt.split('.');
    const header = decodeJwtPart(headerPart);
    const payload = decodeJwtPart(payloadPart);
    return isDecodedJwtObject(header) && isDecodedJwtObject(payload) ? { header, payload } : null;
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error;
    }
    return null;
  }
}

module.exports = {
  createSignedJwtFromObject,
  createServiceJwt,
  createServiceAuthorizationHeader,
  getHeaderPayloadFromJwt,
  verifyJwtSignature,
  _normalizePayload: normalizePayload,
  _encode: encodeJwtPart,
  _decode: decodeJwtPart,
  _isNonEmptyAudience: isNonEmptyAudience,
  _normalizeSeconds: normalizeSeconds,
};
