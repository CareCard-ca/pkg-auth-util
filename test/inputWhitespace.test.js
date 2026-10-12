'use strict';

const assert = require('node:assert/strict');
const {
  createPasswordCredential,
  verifyPasswordCredential,
  parsePasswordHashKeyring,
  jwtCreateSignedToken,
  jwtVerifySignedToken,
  jwtGetHeaderPayload,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
} = require('..');
const { serializeIdentity } = require('./keys/keys');

describe('Whitespace-normalized authentication input', () => {
  it('uses trimmed NFC bytes for both credential creation and verification', async () => {
    const keyring = parsePasswordHashKeyring(
      'active',
      `active:${Buffer.alloc(32, 9).toString('base64')}`,
    );
    const credential = await createPasswordCredential('\t mot de passe cafe\u0301 \n', keyring);
    assert.deepEqual(await verifyPasswordCredential('mot de passe café', credential, keyring), {
      isValid: true,
      needsRehash: false,
    });
    assert.deepEqual(
      await verifyPasswordCredential('\r\n mot de passe café \u00a0', credential, keyring),
      { isValid: true, needsRehash: false },
    );
    assert.deepEqual(await verifyPasswordCredential('mot  de passe café', credential, keyring), {
      isValid: false,
      needsRehash: false,
    });
  });

  it('trims only the outside of a signed proof before verification and decomposition', () => {
    const identity = serializeIdentity();
    const signing = parseJwtSigningJwk(identity.signingJwk);
    const verification = parseJwtVerificationJwks(identity.verificationJwks);
    const token = jwtCreateSignedToken({ sub: 'user', comment: 'internal  spaces' }, signing);
    const padded = `\t ${token} \r\n`;
    assert.equal(jwtVerifySignedToken(padded, verification), true);
    assert.deepEqual(jwtGetHeaderPayload(padded), jwtGetHeaderPayload(token));
    assert.equal(jwtVerifySignedToken(token.replace('.', '. '), verification), false);
  });
});
