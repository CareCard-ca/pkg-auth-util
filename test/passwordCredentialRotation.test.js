'use strict';

const assert = require('node:assert').strict;
const {
  createPasswordCredential,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
} = require('..');

const ACTIVE_KEY = Buffer.alloc(32, 1).toString('base64');
const RETIRING_KEY = Buffer.alloc(32, 2).toString('base64');

describe('password credential key rotation', function () {
  const createKeyring = (activeKeyId = 'active-20260902') =>
    parsePasswordHashKeyring(
      activeKeyId,
      `active-20260902:${ACTIVE_KEY},retiring-20260801:${RETIRING_KEY}`,
    );

  it('creates independently salted credentials with the active key id', async function () {
    const keyring = createKeyring();
    const first = await createPasswordCredential('password phrase', keyring);
    const second = await createPasswordCredential('password phrase', keyring);

    assert.strictEqual(first.hashKeyId, 'active-20260902');
    assert.strictEqual(second.hashKeyId, 'active-20260902');
    assert.notStrictEqual(first.hash, second.hash);
    assert.deepStrictEqual(await verifyPasswordCredential('password phrase', first, keyring), {
      isValid: true,
      needsRehash: false,
    });
  });

  it('reports a valid retiring credential as needing rehash', async function () {
    const retiringKeyring = createKeyring('retiring-20260801');
    const retiringCredential = await createPasswordCredential('password phrase', retiringKeyring);
    const activeKeyring = createKeyring();

    assert.deepStrictEqual(
      await verifyPasswordCredential('password phrase', retiringCredential, activeKeyring),
      { isValid: true, needsRehash: true },
    );
  });

  it('fails closed for wrong, malformed, or removed-key credentials', async function () {
    const keyring = createKeyring();
    const credential = await createPasswordCredential('password phrase', keyring);
    const invalidResult = { isValid: false, needsRehash: false };

    assert.deepStrictEqual(
      await verifyPasswordCredential('wrong phrase', credential, keyring),
      invalidResult,
    );
    assert.deepStrictEqual(
      await verifyPasswordCredential(
        'password phrase',
        { ...credential, hashKeyId: 'removed' },
        keyring,
      ),
      invalidResult,
    );
    assert.deepStrictEqual(
      await verifyPasswordCredential(
        'password phrase',
        { hash: 'invalid', hashKeyId: 'active-20260902' },
        keyring,
      ),
      invalidResult,
    );
  });

  for (const [name, activeKeyId, serializedKeyring] of [
    ['an unsafe id', 'unsafe:id', `unsafe:id:${ACTIVE_KEY}`],
    ['a missing active id', 'missing', `active:${ACTIVE_KEY}`],
    ['a duplicate id', 'active', `active:${ACTIVE_KEY},active:${RETIRING_KEY}`],
    ['a short key', 'active', `active:${Buffer.alloc(31).toString('base64')}`],
    ['noncanonical base64', 'active', `active:${ACTIVE_KEY.replace(/=$/, '')}`],
    ['an empty keyring', 'active', ''],
  ]) {
    it(`rejects ${name}`, function () {
      assert.throws(() => parsePasswordHashKeyring(activeKeyId, serializedKeyring));
    });
  }
});
