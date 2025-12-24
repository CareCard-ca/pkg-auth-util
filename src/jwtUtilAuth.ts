import * as stringUtilAuth from './stringUtilAuth';
import * as cryptoUtilAuth from './cryptoUtilAuth';

/**
 * User supplied header, payload and signature create jwt.
 * @returns {string|null}
 * @param headerBase64
 * @param payloadBase64
 * @param signatureBase64
 */
export const _assembleJwt = (
  headerBase64: string,
  payloadBase64: string,
  signatureBase64: string,
): string => {
  return headerBase64 + '.' + payloadBase64 + '.' + signatureBase64;
};

/**
 * User supplied header, payload and signature create jwt.
 * @returns {{payload: *, signature: *, header: *}}
 * @param jwt
 */
export const _splitJwtInToHeaderPayloadSignature = (jwt: string): any => {
  return stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(jwt);
};

/**
 * Creates Url safe jwt
 * @param headerObject
 * @param payloadObject
 * @param privateKey
 * @return {string|null}
 */
export const createSignedJwtFromObject = (
  headerObject: any,
  payloadObject: any,
  privateKey: string,
): any => {
  try {
    const algorithm = headerObject.alg;
    const headerBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString(headerObject);
    const payloadBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString(payloadObject);
    const token = headerBase64UrlSafe + '.' + payloadBase64UrlSafe;
    const signature = cryptoUtilAuth.createBase64SignatureOfToken(token, privateKey, algorithm);
    const urlSafeSignature = stringUtilAuth.makeStringUrlSafe(signature);
    return _assembleJwt(headerBase64UrlSafe, payloadBase64UrlSafe, urlSafeSignature);
  } catch (error) {
    return null;
  }
};

/**
 * Verify signature of jwt
 * @param jwt
 * @param publicKey
 * @return {boolean}
 */
export const verifyJwtSignature = (jwt: string, publicKey: string): boolean => {
  try {
    const { header, payload, signature } = _splitJwtInToHeaderPayloadSignature(jwt);
    const token = header + '.' + payload;
    const headerObject = stringUtilAuth.urlSafeBase64ToObject(header);
    return cryptoUtilAuth.verifyBase64SignatureOfToken(
      token,
      signature,
      publicKey,
      headerObject.alg,
    );
  } catch (error) {
    return false;
  }
};

/**
 * Returns header and payload object for jwt.
 * @param jwt
 * @return {{payload: any, header: any}}
 */
export const getHeaderPayloadFromJwt = (jwt: string): any => {
  const { header, payload } = _splitJwtInToHeaderPayloadSignature(jwt);
  let headerAscii = stringUtilAuth.base64ToAscii(header);
  let payloadAscii = stringUtilAuth.base64ToAscii(payload);
  return { header: JSON.parse(headerAscii), payload: JSON.parse(payloadAscii) };
};
