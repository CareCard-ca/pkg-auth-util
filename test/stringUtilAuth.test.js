const assert = require('assert').strict;
const { describe, it } = require('mocha');
const stringUtilAuth = require('../lib/stringUtilAuth');

describe('StringUtilAuth test', function () {
  describe('makeStringUrlSafe', function () {
    it('should return url safe string', function () {
      const urlUnsafeString = 'eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===';
      const urlSafeString = 'eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz';

      const returnedString = stringUtilAuth.makeStringUrlSafe(urlUnsafeString);
      assert.strictEqual(returnedString, urlSafeString);
    });

    it('should handle default parameters', function () {
      const result = stringUtilAuth.makeStringUrlSafe(undefined);
      assert.strictEqual(result, '');
    });
  });

  describe('reverseStringUrlSafe', function () {
    it('should return url unsafe string with padding', function () {
      const urlSafeString = 'eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz';
      const urlUnsafeString = 'eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===';

      const returnedString = stringUtilAuth.reverseStringUrlSafe(urlSafeString);
      assert.strictEqual(returnedString, urlUnsafeString);
    });

    it('should handle default parameters', function () {
      const result = stringUtilAuth.reverseStringUrlSafe(undefined);
      assert.strictEqual(result, '');
    });

    it('makeStringUrlSafe and reverseStringUrlSafe should be inverses (excluding padding)', function () {
      const original = 'a+b/c=';
      const urlSafe = stringUtilAuth.makeStringUrlSafe(original);
      assert.strictEqual(urlSafe, 'a-b_c');

      const reversed = stringUtilAuth.reverseStringUrlSafe(urlSafe);
      assert.strictEqual(reversed, 'a+b/c===');
    });
  });

  describe('asciiToBase64', function () {
    it('should return base64 string', function () {
      const asciiString = 'How are you';
      const base64String = 'SG93IGFyZSB5b3U=';

      const returnedString = stringUtilAuth.asciiToBase64(asciiString);
      assert.strictEqual(returnedString, base64String);
    });

    it('should handle UTF-8 characters', function () {
      const original = 'Hello World! ©®™';
      const base64 = stringUtilAuth.asciiToBase64(original);
      const reversed = stringUtilAuth.base64ToAscii(base64);
      assert.strictEqual(reversed, original);
    });
  });

  describe('base64ToAscii', function () {
    it('should return ascii string', function () {
      const base64String = 'SG93IGFyZSB5b3U=';
      const asciiString = 'How are you';

      const returnedString = stringUtilAuth.base64ToAscii(base64String);
      assert.strictEqual(returnedString, asciiString);
    });
  });

  describe('dollarSignConnectedStringToAlgorithmHashSalt', function () {
    it('should split at $ and return object', function () {
      const inputHash = '$1$c2hhNTEy$eyJhbGciOiJzaG$OiJzaGE1MTIiL$';
      const expectedObject = {
        version: '1',
        alg: 'c2hhNTEy',
        hash: 'eyJhbGciOiJzaG',
        salt: 'OiJzaGE1MTIiL',
      };

      const returnedObject = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt(inputHash);
      assert.deepStrictEqual(returnedObject, expectedObject);
    });

    it('should parse password hash correctly', function () {
      const validHash = '$1$someAlg$someHash$someSalt$someExtra'; // length 6
      const result = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt(validHash);
      assert.ok(result);
      assert.strictEqual(result.version, '1');
      assert.strictEqual(result.alg, 'someAlg');
      assert.strictEqual(result.hash, 'someHash');
      assert.strictEqual(result.salt, 'someSalt');

      const invalidHash = '$1$too$few$parts';
      const resultNull = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt(invalidHash);
      assert.strictEqual(resultNull, null);
    });
  });

  describe('dotConnectedStringToHeaderPayloadSignature', function () {
    it('should split at . and return object', function () {
      const inputString = 'c2hhNTEy.eyJhbGciOiJzaG.OiJzaGE1MTIiL';
      const expectedObject = {
        header: 'c2hhNTEy',
        payload: 'eyJhbGciOiJzaG',
        signature: 'OiJzaGE1MTIiL',
      };

      const returnedObject = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(inputString);
      assert.deepStrictEqual(returnedObject, expectedObject);
    });

    it('should parse JWT correctly', function () {
      const jwt = 'header.payload.signature';
      const result = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(jwt);
      assert.strictEqual(result.header, 'header');
      assert.strictEqual(result.payload, 'payload');
      assert.strictEqual(result.signature, 'signature');
    });

    it('should handle non-string or invalid input', function () {
      assert.strictEqual(stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(null), null);
      assert.strictEqual(stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(123), null);
      assert.strictEqual(stringUtilAuth.dotConnectedStringToHeaderPayloadSignature('one.two'), null);
    });
  });

  describe('objectToBase64UrlSafeString', function () {
    it('should return url safe base64 string', function () {
      const object = {
        header: {
          alg: 'HS512',
          typ: 'JWT',
        },
      };
      const expectedBase64String = 'eyJoZWFkZXIiOnsiYWxnIjoiSFM1MTIiLCJ0eXAiOiJKV1QifX0';

      const returnedBase64String = stringUtilAuth.objectToBase64UrlSafeString(object);
      assert.strictEqual(returnedBase64String, expectedBase64String);
    });
  });

  describe('urlSafeBase64ToObject', function () {
    it('should return object', function () {
      const base64String = 'eyJoZWFkZXIiOnsiYWxnIjoiSFM1MTIiLCJ0eXAiOiJKV1QifX0';
      const expectedObject = {
        header: {
          alg: 'HS512',
          typ: 'JWT',
        },
      };

      const returnedObject = stringUtilAuth.urlSafeBase64ToObject(base64String);
      assert.deepStrictEqual(returnedObject, expectedObject);
    });

    it('objectToBase64UrlSafeString and urlSafeBase64ToObject should be inverses', function () {
      const obj = { foo: 'bar', baz: 123, utf8: '©' };
      const base64Url = stringUtilAuth.objectToBase64UrlSafeString(obj);
      const reversed = stringUtilAuth.urlSafeBase64ToObject(base64Url);
      assert.deepStrictEqual(reversed, obj);
    });
  });
});
