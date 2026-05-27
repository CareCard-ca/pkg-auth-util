import * as crypto from 'crypto';

/**
 * Signs a token returns signature string
 * @param token
 * @param privateKey
 * @param signingAlgorithm
 * @returns {string}
 */
export const createBase64SignatureOfToken = function (
  token: string = '',
  privateKey: string,
  signingAlgorithm: string,
): string {
  const sign = crypto.createSign(signingAlgorithm);
  sign.write(token);
  sign.end();
  return sign.sign(privateKey, 'base64');
};

/**
 * Verifies the signature returns true or false
 * @param token
 * @param signature
 * @param publicKey
 * @param signingAlgorithm
 * @returns {boolean}
 */
export const verifyBase64SignatureOfToken = function (
  token: string = '',
  signature: string,
  publicKey: string,
  signingAlgorithm: string,
): boolean {
  const verify = crypto.createVerify(signingAlgorithm);
  verify.update(token);
  verify.end();
  return verify.verify(publicKey, signature, 'base64');
};

/**
 * Creates the hash of given string
 * @param string
 * @param secret
 * @param algorithm
 * @returns {string}
 */
export const createHmacBase64 = function (
  string: string = '',
  secret: string,
  algorithm: string,
): string {
  const hmac = crypto.createHmac(algorithm, secret);
  hmac.update(string);
  return hmac.digest('base64');
};

/**
 * Create random salt
 * @returns {string}
 */
export const createSaltBase64 = (): string => {
  const date = new Date().valueOf();
  const hmac = crypto.createHmac('SHA256', date.toString());
  hmac.update(date.toString());
  return hmac.digest('base64');
};

/**
 * Encrypt given string
 * @param string
 * @param salt
 * @param secret
 * @param algorithm
 * @returns {string}
 */
export const encryptStringAsciiToBase64 = (
  string: string,
  salt: string,
  secret: string,
  algorithm: string,
): string => {
  const key = crypto.scryptSync(secret, salt, 24);
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(string, 'ascii', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
};

/**
 * Decrypts given string
 * @param encryptedString
 * @param salt
 * @param secret
 * @param algorithm
 * @returns {string}
 */
export const decryptStringBase64ToAscii = (
  encryptedString: string,
  salt: string,
  secret: string,
  algorithm: string,
): string => {
  const key = crypto.scryptSync(secret, salt, 24);
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedString, 'base64', 'ascii');
  decrypted += decipher.final('ascii');
  return decrypted;
};
