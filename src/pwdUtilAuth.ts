import * as cryptoUtilAuth from './cryptoUtilAuth';
import * as stringUtilAuth from './stringUtilAuth';

/**
 * Just assemble password together
 * @param algorithmBase64
 * @param hashBase64
 * @param saltBase64
 * @return {string}
 */
export const _assemblePasswordHash = (
  algorithmBase64: string,
  hashBase64: string,
  saltBase64: string,
): string => {
  return '$1$' + algorithmBase64 + '$' + hashBase64 + '$' + saltBase64 + '$';
};

/**
 * Break password into its parts does not reverse base64 encoding.
 * @param passwordHashStored
 * @return {{salt: *, version: *, alg: *, hash: *}}
 */
export const _disassemblePasswordHash = (passwordHashStored: string): any => {
  return stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt(passwordHashStored);
};

/**
 * Creates password hash ready to be saved in database.
 * @param password
 * @param secret
 * @param salt
 * @param algorithm
 * @return {string}
 */
export const _createPasswordHash = (
  password: string,
  secret: string,
  salt: string,
  algorithm: string,
): string => {
  const algorithmBase64 = stringUtilAuth.asciiToBase64(algorithm);
  const hashBase64 = cryptoUtilAuth.createHmacBase64(password, secret, algorithm);
  return _assemblePasswordHash(algorithmBase64, hashBase64, salt);
};

/**
 * Automatically adds random salt.
 * @param password
 * @param secret
 * @param algorithm
 * @return {string}
 */
export const createPasswordHashWithRandomSalt = (
  password: string,
  secret: string,
  algorithm: string,
): string => {
  const salt = cryptoUtilAuth.createSaltBase64();
  return _createPasswordHash(password, secret, salt, algorithm);
};

/**
 * Creates hash based on saved hash in database.
 * @param password
 * @param savedPasswordHash
 * @param secret
 * @return {string}
 */
export const createPasswordHashBasedOnSavedAlgorithmSalt = (
  password: string,
  savedPasswordHash: string,
  secret: string,
): string => {
  const { alg, salt } = _disassemblePasswordHash(savedPasswordHash);
  const algorithm = stringUtilAuth.base64ToAscii(alg);
  return _createPasswordHash(password, secret, salt, algorithm);
};
