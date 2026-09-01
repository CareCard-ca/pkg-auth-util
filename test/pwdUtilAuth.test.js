const assert = require('assert').strict;
const { describe, it } = require('mocha');
const { createPasswordHash, verifyPassword } = require('../index');

const TEST_PEPPER = 'carecard-test-pepper-is-at-least-32-bytes';
const OTHER_PEPPER = 'carecard-other-pepper-is-at-least-32-bytes';
const ARGON2ID_PHC_PATTERN =
  /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/;

describe('password hashing', function () {
  it('creates a salted Argon2id PHC credential and verifies it', async function () {
    const savedHash = await createPasswordHash('password', TEST_PEPPER);

    assert.match(savedHash, ARGON2ID_PHC_PATTERN);
    assert.strictEqual(await verifyPassword('password', savedHash, TEST_PEPPER), true);
    assert.strictEqual(await verifyPassword('wrong password', savedHash, TEST_PEPPER), false);
    assert.strictEqual(await verifyPassword('password', savedHash, OTHER_PEPPER), false);
  });

  it('creates a unique salted credential for the same password', async function () {
    const [firstHash, secondHash] = await Promise.all([
      createPasswordHash('password', TEST_PEPPER),
      createPasswordHash('password', TEST_PEPPER),
    ]);

    assert.notStrictEqual(firstHash, secondHash);
    assert.strictEqual(await verifyPassword('password', firstHash, TEST_PEPPER), true);
    assert.strictEqual(await verifyPassword('password', secondHash, TEST_PEPPER), true);
  });

  it('normalizes passwords to NFC for creation and comparison', async function () {
    const savedHash = await createPasswordHash('mot de passe café', TEST_PEPPER);

    assert.strictEqual(
      await verifyPassword('mot de passe cafe\u0301', savedHash, TEST_PEPPER),
      true,
    );
  });

  it('rejects an undersized pepper as a configuration error', async function () {
    await assert.rejects(createPasswordHash('password', 'too-short'), /at least 32 bytes/);
    await assert.rejects(
      verifyPassword('password', '$argon2id$invalid', 'too-short'),
      /at least 32 bytes/,
    );
  });

  it('returns false for malformed, modified, and legacy saved hashes', async function () {
    const validHash = await createPasswordHash('password', TEST_PEPPER);
    const invalidHashes = [
      null,
      '',
      '$1$c2hhNTEy$legacy$legacy$',
      validHash.replace('m=19456', 'm=65536'),
      validHash.replace('v=19', 'v=16'),
      `${validHash}=`,
      validHash.replace(/.$/, '!'),
    ];

    for (const savedHash of invalidHashes) {
      assert.strictEqual(await verifyPassword('password', savedHash, TEST_PEPPER), false);
    }
  });
});
