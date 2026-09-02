'use strict';

const assert = require('node:assert').strict;
const {
  createPasswordCredential,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
} = require('..');

const encodedKey = Buffer.alloc(32, 7).toString('base64');
const keyring = parsePasswordHashKeyring('test-key', `test-key:${encodedKey}`);
const invalidResult = { isValid: false, needsRehash: false };

describe('password credentials', function () {
  it('normalizes well-formed Unicode passwords to NFC', async function () {
    const credential = await createPasswordCredential('mot de passe café', keyring);

    assert.deepStrictEqual(
      await verifyPasswordCredential('mot de passe cafe\u0301', credential, keyring),
      { isValid: true, needsRehash: false },
    );
  });

  it('rejects malformed Unicode password input', async function () {
    await assert.rejects(createPasswordCredential('\ud800', keyring), /well-formed Unicode/);
    const credential = await createPasswordCredential('password phrase', keyring);
    assert.deepStrictEqual(
      await verifyPasswordCredential('\ud800', credential, keyring),
      invalidResult,
    );
  });

  it('requires a keyring returned by the public parser', async function () {
    await assert.rejects(
      createPasswordCredential('password phrase', { activeKeyId: 'test-key' }),
      /parsed password hash keyring/,
    );
    await assert.rejects(
      verifyPasswordCredential('password phrase', {}, { activeKeyId: 'test-key' }),
      /parsed password hash keyring/,
    );
  });

  it('rejects noncanonical and differently parameterized hashes', async function () {
    const credential = await createPasswordCredential('password phrase', keyring);
    const invalidHashes = [
      credential.hash.replace('$argon2id$', '$argon2i$'),
      credential.hash.replace('m=19456', 'm=19457'),
      `${credential.hash}=`,
      '$argon2id$v=19$m=19456,t=2,p=1$invalid$invalid',
    ];

    for (const hash of invalidHashes) {
      assert.deepStrictEqual(
        await verifyPasswordCredential('password phrase', { hash, hashKeyId: 'test-key' }, keyring),
        invalidResult,
      );
    }
  });
});
