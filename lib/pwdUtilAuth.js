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
const MINIMUM_PEPPER_BYTES = 32;
const PASSWORD_HASH_PATTERN =
  /^\$argon2id\$v=19\$m=19456,t=2,p=1\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/;

// Pattern: Configuration Guard - converts only a sufficiently strong string pepper to bytes.
function createPepperBuffer(pepper) {
  if (typeof pepper !== 'string') {
    throw new TypeError('Password pepper must be a string.');
  }
  const pepperBuffer = Buffer.from(pepper, 'utf8');
  if (pepperBuffer.length < MINIMUM_PEPPER_BYTES) {
    throw new RangeError('Password pepper must be at least 32 bytes.');
  }
  return pepperBuffer;
}

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

// Pattern: Credential Factory - creates an independently salted Argon2id password hash.
async function createPasswordHash(password, pepper) {
  const pepperBuffer = createPepperBuffer(pepper);
  const salt = randomBytes(PASSWORD_SALT_BYTES);
  const tag = await derivePasswordTag(password, salt, pepperBuffer);
  return serializePasswordHash(salt, tag);
}

// Pattern: Constant-Time Verification - derives and compares a strict Argon2id credential tag.
async function verifyPassword(password, savedHash, pepper) {
  const pepperBuffer = createPepperBuffer(pepper);
  if (typeof password !== 'string' || !password.isWellFormed()) {
    return false;
  }
  const parsedHash = parsePasswordHash(savedHash);
  if (!parsedHash) {
    return false;
  }
  const candidateTag = await derivePasswordTag(password, parsedHash.salt, pepperBuffer);
  return timingSafeEqual(candidateTag, parsedHash.tag);
}

module.exports = { createPasswordHash, verifyPassword };
