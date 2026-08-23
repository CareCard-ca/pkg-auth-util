const crypto = require('crypto');

const PASSWORD_HASH_VERSION = '1';

// Pattern: Pure Function - creates a digest in which both the pepper and random salt participate.
function createSaltedPasswordDigest(password, secret, algorithm, salt) {
  return crypto
    .createHmac(algorithm, secret)
    .update(Buffer.from(salt, 'base64'))
    .update(password)
    .digest('base64');
}

// Pattern: Pure Function - recreates the historical digest for existing stored credentials.
function createLegacyPasswordDigest(password, secret, algorithm) {
  return crypto.createHmac(algorithm, secret).update(password).digest('base64');
}

// Pattern: Serializer - preserves the published password-hash storage contract.
function serializePasswordHash(algorithmBase64, hashBase64, salt) {
  return `$${PASSWORD_HASH_VERSION}$${algorithmBase64}$${hashBase64}$${salt}$`;
}

// Pattern: Constant-Time Comparison - avoids credential-dependent string comparison timing.
function passwordHashesMatch(candidateHash, savedPasswordHash) {
  const candidateBuffer = Buffer.from(candidateHash);
  const savedBuffer = Buffer.from(savedPasswordHash);
  return (
    candidateBuffer.length === savedBuffer.length &&
    crypto.timingSafeEqual(candidateBuffer, savedBuffer)
  );
}

// Pattern: Factory - creates a password hash whose random salt changes the credential digest.
const createPasswordHashWithRandomSalt = (password, secret, algorithm) => {
  const salt = crypto.randomBytes(32).toString('base64');
  const algorithmBase64 = Buffer.from(algorithm).toString('base64');
  const hashBase64 = createSaltedPasswordDigest(password, secret, algorithm, salt);
  return serializePasswordHash(algorithmBase64, hashBase64, salt);
};

// Pattern: Compatibility Verification - verifies salted hashes while retaining existing credentials.
const createPasswordHashBasedOnSavedAlgorithmSalt = (password, savedPasswordHash, secret) => {
  if (typeof savedPasswordHash !== 'string') {
    return null;
  }

  const splitStringArray = savedPasswordHash.split('$');
  if (splitStringArray.length !== 6) {
    return null;
  }

  const version = splitStringArray[1];
  const algBase64 = splitStringArray[2];
  const salt = splitStringArray[4];
  if (version !== PASSWORD_HASH_VERSION || !algBase64 || !salt) {
    return null;
  }
  const algorithm = Buffer.from(algBase64, 'base64').toString('utf8');
  const saltedDigest = createSaltedPasswordDigest(password, secret, algorithm, salt);
  const saltedHash = serializePasswordHash(algBase64, saltedDigest, salt);
  const legacyDigest = createLegacyPasswordDigest(password, secret, algorithm);
  const legacyHash = serializePasswordHash(algBase64, legacyDigest, salt);
  return passwordHashesMatch(legacyHash, savedPasswordHash) ? legacyHash : saltedHash;
};

module.exports = {
  createPasswordHashWithRandomSalt,
  createPasswordHashBasedOnSavedAlgorithmSalt,
};
