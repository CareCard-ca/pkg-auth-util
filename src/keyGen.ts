import { generateKeyPairSync } from 'node:crypto';

export const generateKeyPair = (modulusLength: number = 4096) =>
  generateKeyPairSync('rsa', {
    modulusLength: modulusLength,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
