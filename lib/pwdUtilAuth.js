'use strict';

const { argon2, randomBytes, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');

const deriveArgon2Tag = promisify(argon2);
const ARGON2_ALGORITHM = 'argon2id';
const ARGON2_VERSION = 19;
const ARGON2_MEMORY_KIB = 19456;
const ARGON2_PASSES = 2;
const ARGON2_PARALLELISM = 1;
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_TAG_BYTES = 32;
const PASSWORD_KEY_BYTES = 32;
const PASSWORD_KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const passwordKeyringSecrets = new WeakMap();
const PASSWORD_HASH_PATTERN =
  /^\$argon2id\$v=19\$m=19456,t=2,p=1\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/;

// Pattern: Canonicalization - converts well-formed NFC password text to stable UTF-8 bytes.
function createPasswordBuffer(password) {
  if (typeof password !== 'string' || !password.isWellFormed()) {
    throw new TypeError('Password must be a well-formed Unicode string.');
  }
  return Buffer.from(password.normalize('NFC'), 'utf8');
}

// Pattern: Serializer Helper - emits canonical unpadded PHC Base64 text.
function encodePhcBase64(value) {
  return value.toString('base64').replace(/=+$/, '');
}

// Pattern: Parser Guard - accepts only canonical PHC Base64 with the required byte length.
function decodePhcBase64(value, expectedLength) {
  const decodedValue = Buffer.from(value, 'base64');
  if (decodedValue.length !== expectedLength || encodePhcBase64(decodedValue) !== value) {
    return null;
  }
  return decodedValue;
}

// Pattern: Strict Parser - accepts only the exact CareCard Argon2id storage contract.
function parsePasswordHash(savedHash) {
  if (typeof savedHash !== 'string') {
    return null;
  }
  const match = savedHash.match(PASSWORD_HASH_PATTERN);
  if (!match) {
    return null;
  }
  const salt = decodePhcBase64(match[1], PASSWORD_SALT_BYTES);
  const tag = decodePhcBase64(match[2], PASSWORD_TAG_BYTES);
  return salt && tag ? { salt, tag } : null;
}

// Pattern: Parameter Object - centralizes the fixed Argon2id security profile.
function createArgon2Parameters(passwordBuffer, salt, pepperBuffer) {
  return {
    message: passwordBuffer,
    nonce: salt,
    parallelism: ARGON2_PARALLELISM,
    tagLength: PASSWORD_TAG_BYTES,
    memory: ARGON2_MEMORY_KIB,
    passes: ARGON2_PASSES,
    secret: pepperBuffer,
  };
}

// Pattern: Cryptographic Adapter - derives one tag through Node's asynchronous Argon2 boundary.
async function derivePasswordTag(password, salt, pepperBuffer) {
  const parameters = createArgon2Parameters(createPasswordBuffer(password), salt, pepperBuffer);
  return deriveArgon2Tag(ARGON2_ALGORITHM, parameters);
}

// Pattern: Serializer - records the fixed parameters, salt, and tag in strict PHC form.
function serializePasswordHash(salt, tag) {
  const parameters = `m=${ARGON2_MEMORY_KIB},t=${ARGON2_PASSES},p=${ARGON2_PARALLELISM}`;
  return `$${ARGON2_ALGORITHM}$v=${ARGON2_VERSION}$${parameters}$${encodePhcBase64(salt)}$${encodePhcBase64(tag)}`;
}

// Pattern: Strict Configuration Parser - creates an opaque versioned password keyring.
function parsePasswordHashKeyring(activeKeyId, serializedKeyring) {
  if (!PASSWORD_KEY_ID_PATTERN.test(activeKeyId) || typeof serializedKeyring !== 'string') {
    throw new Error('Invalid password hash keyring configuration.');
  }
  if (!serializedKeyring || /\s/.test(serializedKeyring)) {
    throw new Error('Invalid password hash keyring configuration.');
  }
  const entries = serializedKeyring.split(',').map(parsePasswordKeyEntry);
  const keyMap = new Map(entries);
  if (keyMap.size !== entries.length || !keyMap.has(activeKeyId)) {
    throw new Error('Invalid password hash keyring configuration.');
  }
  const keyring = Object.freeze({ activeKeyId, keyIds: Object.freeze([...keyMap.keys()]) });
  passwordKeyringSecrets.set(keyring, keyMap);
  return keyring;
}

function parsePasswordKeyEntry(entry) {
  const separatorIndex = entry.indexOf(':');
  if (separatorIndex <= 0 || separatorIndex !== entry.lastIndexOf(':')) {
    throw new Error('Invalid password hash keyring configuration.');
  }
  const keyId = entry.slice(0, separatorIndex);
  const encodedKey = entry.slice(separatorIndex + 1);
  const key = Buffer.from(encodedKey, 'base64');
  if (!PASSWORD_KEY_ID_PATTERN.test(keyId) || !isCanonicalPasswordKey(key, encodedKey)) {
    throw new Error('Invalid password hash keyring configuration.');
  }
  return [keyId, key];
}

function isCanonicalPasswordKey(key, encodedKey) {
  return key.length === PASSWORD_KEY_BYTES && key.toString('base64') === encodedKey;
}

function getPasswordKeyringSecrets(keyring) {
  const keys = passwordKeyringSecrets.get(keyring);
  if (!keys) {
    throw new TypeError('A parsed password hash keyring is required.');
  }
  return keys;
}

async function createPasswordCredential(password, keyring) {
  const keys = getPasswordKeyringSecrets(keyring);
  const pepper = keys.get(keyring.activeKeyId);
  const salt = randomBytes(PASSWORD_SALT_BYTES);
  const tag = await derivePasswordTag(password, salt, pepper);
  return Object.freeze({ hash: serializePasswordHash(salt, tag), hashKeyId: keyring.activeKeyId });
}

async function verifyPasswordCredential(password, credential, keyring) {
  const keys = getPasswordKeyringSecrets(keyring);
  const pepper = keys.get(credential?.hashKeyId);
  const parsedHash = parsePasswordHash(credential?.hash);
  if (!pepper || !parsedHash || typeof password !== 'string' || !password.isWellFormed()) {
    return { isValid: false, needsRehash: false };
  }
  const candidateTag = await derivePasswordTag(password, parsedHash.salt, pepper);
  const isValid = timingSafeEqual(candidateTag, parsedHash.tag);
  return { isValid, needsRehash: isValid && credential.hashKeyId !== keyring.activeKeyId };
}

module.exports = {
  createPasswordCredential,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
};
