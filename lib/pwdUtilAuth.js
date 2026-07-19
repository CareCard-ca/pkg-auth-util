const crypto = require('crypto');

/**
 * Automatically adds random salt.
 * @param password
 * @param secret
 * @param algorithm
 * @return {string}
 */
const createPasswordHashWithRandomSalt = (password, secret, algorithm) => {
  const salt = crypto.randomBytes(32).toString('base64');
  const algorithmBase64 = Buffer.from(algorithm).toString('base64');
  const hashBase64 = crypto.createHmac(algorithm, secret).update(password).digest('base64');
  return '$1$' + algorithmBase64 + '$' + hashBase64 + '$' + salt + '$';
};

/**
 * Creates hash based on saved hash in database.
 * @param password
 * @param savedPasswordHash
 * @param secret
 * @return {string}
 */
const createPasswordHashBasedOnSavedAlgorithmSalt = (password, savedPasswordHash, secret) => {
  if (typeof savedPasswordHash !== 'string') return null;

  const splitStringArray = savedPasswordHash.split('$');
  if (splitStringArray.length !== 6) return null;

  const algBase64 = splitStringArray[2];
  const salt = splitStringArray[4];
  const algorithm = Buffer.from(algBase64, 'base64').toString('utf8');

  const hashBase64 = crypto.createHmac(algorithm, secret).update(password).digest('base64');
  return '$1$' + algBase64 + '$' + hashBase64 + '$' + salt + '$';
};

module.exports = {
  createPasswordHashWithRandomSalt,
  createPasswordHashBasedOnSavedAlgorithmSalt,
};
