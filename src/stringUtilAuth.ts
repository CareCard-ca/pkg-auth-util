'use strict';
/**
 * For incoming jwt token validation, splitting and parsing.
 * For outgoing jwt token assembling to jwt, make it url safe.
 */

/**
 * Adjusts padding of base64String
 * @param base64String
 * @return {*}
 */
export const adjustBase64Padding = (base64String: string): string => {
  while (base64String.length % 4) base64String += '=';
  return base64String;
};

/**
 * Removes /, + and = from the string
 * @returns {string}
 */
export const makeStringUrlSafe = (urlUnsafeString: string = ''): string => {
  return urlUnsafeString.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Put back /, + and = into the string
 * @returns {string}
 */
export const reverseStringUrlSafe = (urlSafeString: string = ''): string => {
  let myString = urlSafeString.replace(/-/g, '+').replace(/_/g, '/');
  return adjustBase64Padding(myString);
};

/**
 * Encode string to base64 string
 * @param unCodedString
 * @returns {string}
 */
export const asciiToBase64 = (unCodedString: string): string => {
  return Buffer.from(unCodedString).toString('base64');
};

/** Decode string from base64
 * @param codedString
 * @returns {string}
 */
export const base64ToAscii = (codedString: string): string => {
  return Buffer.from(codedString, 'base64').toString('ascii');
};

/**
 * Decompose $ connected string and return an object
 * return null if error
 * @param passwordHash
 */
export const dollarSignConnectedStringToAlgorithmHashSalt = (passwordHash: string) => {
  const splitStringArray = passwordHash.split('$');
  if (splitStringArray.length !== 6) return null;
  return {
    version: splitStringArray[1],
    alg: splitStringArray[2],
    hash: splitStringArray[3],
    salt: splitStringArray[4],
  };
};

/**
 * Decompose . connected string and return an object with
 * {header: 'string', payload: 'string', signature: 'string'}
 * return null if error
 */
export const dotConnectedStringToHeaderPayloadSignature = (jwt: string) => {
  const splitJWT = jwt.split('.');
  if (splitJWT.length !== 3) return null;
  return {
    header: splitJWT[0],
    payload: splitJWT[1],
    signature: splitJWT[2],
  };
};

/**
 * Turns object into url safe string
 * @param object
 * @return {string}
 */
export const objectToBase64UrlSafeString = (object: any): string => {
  let stringAscii = JSON.stringify(object);
  let base64String = asciiToBase64(stringAscii);
  return makeStringUrlSafe(base64String);
};

/**
 * Turns base64 into object
 * @param urlSafeBase64String
 * @return {any}
 */
export const urlSafeBase64ToObject = (urlSafeBase64String: string): any => {
  let base64String = reverseStringUrlSafe(urlSafeBase64String);
  let stringAscii = base64ToAscii(base64String);
  return JSON.parse(stringAscii);
};
