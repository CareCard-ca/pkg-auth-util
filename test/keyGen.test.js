const assert = require('assert').strict;
const { describe, it } = require('mocha');
const crypto = require('crypto');

const { generateKeyPair } = require('../lib/keyGen');

describe('keyGen test', function () {
  describe('generateKeyPair', function () {
    it('should create ed25519 keys by default', function () {
      const { publicKey, privateKey } = generateKeyPair();
      assert.ok(publicKey);
      assert.ok(privateKey);

      const token = 'Hi I am token';
      const signature = crypto.sign(null, Buffer.from(token), privateKey);
      assert.ok(crypto.verify(null, Buffer.from(token), publicKey, signature));
    });

    it('should create rsa keys when specified', function () {
      const { publicKey, privateKey } = generateKeyPair('rsa');
      assert.ok(publicKey);
      assert.ok(privateKey);

      const token = 'Hi I am token';
      const sign = crypto.createSign('SHA256');
      sign.update(token);
      sign.end();
      const signature = sign.sign(privateKey);

      const verify = crypto.createVerify('SHA256');
      verify.update(token);
      verify.end();
      assert.ok(verify.verify(publicKey, signature));
    });

    it('should handle ed25519 when explicitly passed', function () {
      const { publicKey, privateKey } = generateKeyPair('ed25519');
      assert.ok(publicKey);
      assert.ok(privateKey);
    });
  });
});
