import * as assert from 'assert';
import * as cryptoUtilAuth from '../src/cryptoUtilAuth';
import { generateKeyPair } from '../src';

describe('Create key to use with jwt', function () {
  it('tests if keys created work', function () {
    const { publicKey, privateKey } = generateKeyPair();

    const algorithm = 'SHA256';
    const token = 'Hi I am token';

    const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken(
      token,
      privateKey,
      algorithm,
    );
    const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken(
      token,
      returnedSignature,
      publicKey,
      algorithm,
    );

    assert.deepStrictEqual(returnedValue, true);
  });
});
