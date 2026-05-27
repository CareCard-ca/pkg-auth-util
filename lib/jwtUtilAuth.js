const crypto = require('crypto');

const _normalizePayload = payloadObject => {
  const payload = { ...payloadObject };
  const now = Math.floor(Date.now() / 1000);
  const fieldsToNormalize = ['iat', 'exp', 'nbf', 'auth_time'];
  const msThreshold = 1000000000000;

  if (!payload.iat) {
    payload.iat = now;
  }

  fieldsToNormalize.forEach(field => {
    if (payload[field] && payload[field] > msThreshold) {
      payload[field] = Math.floor(payload[field] / 1000);
    }
  });

  if (!payload.exp) {
    payload.exp = payload.iat + 3600;
  }
  return payload;
};

const _encode = obj => {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
};

const _decode = str => {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
};

const _sign = (token, alg, privateKey) => {
  if (alg === 'EdDSA' || alg === 'Ed25519') {
    return crypto.sign(null, Buffer.from(token), privateKey).toString('base64url');
  }

  const sign = crypto.createSign(alg);
  sign.write(token);
  sign.end();
  return sign.sign(privateKey, 'base64url');
};

const _verify = (token, signature, alg, publicKey) => {
  if (alg === 'EdDSA' || alg === 'Ed25519') {
    return crypto.verify(null, Buffer.from(token), publicKey, Buffer.from(signature, 'base64url'));
  }

  const verify = crypto.createVerify(alg);
  verify.update(token);
  verify.end();
  return verify.verify(publicKey, signature, 'base64url');
};

const isNonEmptyString = value => {
  return typeof value === 'string' && value.trim().length > 0;
};

const audienceIsNonEmptyStringArray = audience => {
  return Array.isArray(audience) && audience.length > 0 && audience.every(audienceValue => isNonEmptyString(audienceValue));
};

const isNonEmptyAudience = audience => {
  return isNonEmptyString(audience) || audienceIsNonEmptyStringArray(audience);
};

const normalizeSeconds = value => {
  if (!Number.isFinite(value)) return null;
  return value > 1000000000000 ? Math.floor(value / 1000) : Math.floor(value);
};

/**
 * Creates Url safe jwt
 * @param headerObject
 * @param payloadObject
 * @param privateKey
 * @return {string|null}
 */
const createSignedJwtFromObject = (headerObject, payloadObject, privateKey) => {
  try {
    if (!privateKey) return null;

    const header = { ...headerObject };
    header.alg = header.alg || 'EdDSA';
    header.typ = 'JWT';

    const payload = _normalizePayload(payloadObject);

    const headerBase64UrlSafe = _encode(header);
    const payloadBase64UrlSafe = _encode(payload);
    const token = headerBase64UrlSafe + '.' + payloadBase64UrlSafe;

    const signature = _sign(token, header.alg, privateKey);

    return token + '.' + signature;
  } catch (error) {
    return null;
  }
};

function createServiceJwt({
  issuer,
  audience,
  privateKey,
  subject = issuer,
  issuedAt = Math.floor(Date.now() / 1000),
  expiresInSeconds = 60,
  algorithm = 'EdDSA',
  claims = {},
} = {}) {
  if (
    !isNonEmptyString(issuer) ||
    !isNonEmptyAudience(audience) ||
    !isNonEmptyString(subject) ||
    !isNonEmptyString(privateKey) ||
    !Number.isInteger(expiresInSeconds) ||
    expiresInSeconds <= 0
  ) {
    return null;
  }

  const iat = normalizeSeconds(issuedAt);
  if (!Number.isInteger(iat)) return null;

  // Service-to-service tokens use registered JWT claims so receivers can
  // validate sender, intended audience, subject, and lifetime consistently.
  return createSignedJwtFromObject(
    { alg: algorithm, typ: 'JWT' },
    {
      ...claims,
      iss: issuer,
      aud: audience,
      sub: subject,
      iat,
      exp: iat + expiresInSeconds,
    },
    privateKey,
  );
}

function createServiceAuthorizationHeader(options = {}) {
  const token = createServiceJwt(options);
  return token ? `Bearer ${token}` : null;
}

/**
 * Verify signature of jwt
 * @param jwt
 * @param publicKey
 * @return {boolean}
 */
const verifyJwtSignature = (jwt, publicKey) => {
  try {
    if (!jwt || !publicKey) return false;
    const splitJWT = jwt.split('.');
    if (splitJWT.length !== 3) return false;

    const [header, payload, signature] = splitJWT;
    const token = header + '.' + payload;
    const headerObject = _decode(header);

    return _verify(token, signature, headerObject.alg, publicKey);
  } catch (error) {
    return false;
  }
};

/**
 * Returns header and payload object for jwt.
 * @param jwt
 * @return {{payload: *, header: *}|null}
 */
const getHeaderPayloadFromJwt = jwt => {
  try {
    if (typeof jwt !== 'string') return null;
    const splitJWT = jwt.split('.');
    if (splitJWT.length !== 3) return null;

    const headerObject = _decode(splitJWT[0]);
    const payloadObject = _decode(splitJWT[1]);

    return { header: headerObject, payload: payloadObject };
  } catch (e) {
    return null;
  }
};

module.exports = {
  createSignedJwtFromObject,
  createServiceJwt,
  createServiceAuthorizationHeader,
  verifyJwtSignature,
  getHeaderPayloadFromJwt,
  _normalizePayload,
  _encode,
  _decode,
  _sign,
  _verify,
  _isNonEmptyAudience: isNonEmptyAudience,
  _normalizeSeconds: normalizeSeconds,
};
