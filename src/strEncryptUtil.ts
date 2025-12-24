// src/strEncryptUtil.ts
import * as crypto from 'crypto';

/**
 * Derive a key using scrypt.
 */
export function createKey(key: crypto.BinaryLike, keyLength = 32): Buffer {
  // scryptSync returns a Buffer
  return crypto.scryptSync(key, key, keyLength);
}

/* --------------------------------------------------
 * Config Types
 * -------------------------------------------------- */

export interface EncryptionConfig {
  privateKey: string | Buffer | crypto.KeyObject;
  encryptedTextEncoding: BufferEncoding; // e.g., 'base64' | 'hex' | ...
}

export interface DecryptionConfig {
  publicKey: string | Buffer | crypto.KeyObject;
  encryptedTextEncoding: BufferEncoding; // encoding of input cipher text buffer
  plainTextEncoding: BufferEncoding; // encoding for output text, e.g., 'utf8'
}

export interface SymmetricCryptoConfig {
  cipherAlgorithm: string; // e.g., 'aes-256-cbc'
  encryptionKey: crypto.BinaryLike; // passphrase or raw key-like data
  keyLength: number; // e.g., 32 for aes-256
  plainTextEncoding: BufferEncoding; // e.g., 'utf8'
  encryptedTextEncoding: BufferEncoding; // e.g., 'base64' | 'hex'
}

/* --------------------------------------------------
 * Helpers
 * -------------------------------------------------- */

function getErrorCodeOrFallback(error: unknown): string {
  // Safely narrow 'unknown' to read 'code' when available
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof (error as { code?: unknown }).code === 'string'
  ) {
    return (error as { code: string }).code;
  }
  if (error instanceof Error) {
    // You can return message or name; using name keeps it short
    return `ERROR:${error.name}`;
  }
  return 'UNKNOWN_ERROR';
}

/* --------------------------------------------------
 * Asymmetric Encryption (RSA or similar)
 * -------------------------------------------------- */

/**
 * Encrypts text using a private key, returning an encoded cipher text string.
 * On error, returns a code string if present, otherwise a fallback.
 */
export const encryptByPrivateKey = (
  encryptionConfigObj: EncryptionConfig,
  textToEncrypt: string,
): string => {
  try {
    const encrypted = crypto.privateEncrypt(
      encryptionConfigObj.privateKey,
      Buffer.from(textToEncrypt, 'utf8'),
    );
    return encrypted.toString(encryptionConfigObj.encryptedTextEncoding);
  } catch (error: unknown) {
    return getErrorCodeOrFallback(error);
  }
};

/**
 * Decrypts text using a public key, returning a plain text string.
 * On error, returns a code string if present, otherwise a fallback.
 */
export const decryptByPublicKey = (
  decryptionConfigObj: DecryptionConfig,
  textToDecrypt: string,
): string => {
  try {
    const decrypted = crypto.publicDecrypt(
      decryptionConfigObj.publicKey,
      Buffer.from(textToDecrypt, decryptionConfigObj.encryptedTextEncoding),
    );
    return decrypted.toString(decryptionConfigObj.plainTextEncoding);
  } catch (error: unknown) {
    return getErrorCodeOrFallback(error);
  }
};

/* --------------------------------------------------
 * Symmetric Encryption (AES or similar)
 * -------------------------------------------------- */

/**
 * Encrypts text using a symmetric algorithm and derived key, returning an encoded cipher string.
 * On error, returns a code string if present, otherwise a fallback.
 *
 * NOTE: This uses a zero IV (Buffer.alloc(16, 0)) which is generally **not recommended** for production.
 * Prefer a random IV per encryption and prepend/append it to the output for decryption.
 */
export const encryptByKey = (
  encryptConfigObj: SymmetricCryptoConfig,
  textToEncrypt: string,
): string => {
  try {
    const iv = Buffer.alloc(16, 0); // ⚠️ consider using a random IV for security
    const key = createKey(encryptConfigObj.encryptionKey, encryptConfigObj.keyLength);

    const cipher = crypto.createCipheriv(encryptConfigObj.cipherAlgorithm, key, iv);

    let encrypted = cipher.update(
      textToEncrypt,
      encryptConfigObj.plainTextEncoding,
      encryptConfigObj.encryptedTextEncoding,
    );
    encrypted += cipher.final(encryptConfigObj.encryptedTextEncoding);

    return encrypted;
  } catch (error: unknown) {
    return getErrorCodeOrFallback(error);
  }
};

/**
 * Decrypts a cipher string using a symmetric algorithm and derived key,
 * returning the plain text string. On error, returns a code string or fallback.
 *
 * NOTE: Must use the same IV that was used during encryption. Here it assumes a zero IV.
 */
export const decryptByKey = (
  encryptConfigObj: SymmetricCryptoConfig,
  textToDecrypt: string,
): string => {
  try {
    const iv = Buffer.alloc(16, 0); // ⚠️ must match the IV used in encryptByKey
    const key = createKey(encryptConfigObj.encryptionKey, encryptConfigObj.keyLength);

    const decipher = crypto.createDecipheriv(encryptConfigObj.cipherAlgorithm, key, iv);

    let decrypted = decipher.update(
      textToDecrypt,
      encryptConfigObj.encryptedTextEncoding,
      encryptConfigObj.plainTextEncoding,
    );
    decrypted += decipher.final(encryptConfigObj.plainTextEncoding);

    return decrypted;
  } catch (error: unknown) {
    return getErrorCodeOrFallback(error);
  }
};
