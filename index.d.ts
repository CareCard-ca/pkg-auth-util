/**
 * Utility functions for authentication and authorization in the CareCard ecosystem.
 */

import type { Request } from 'express';

/**
 * Represents the standard JWT header structure.
 */
export interface JwtHeader {
  /** The cryptographic algorithm used to secure the JWT. */
  alg?: string;
  /** The media type of the JWT. Defaults to 'JWT'. */
  typ?: string;
  /** RFC 7638 thumbprint identifying the signing key. */
  kid?: string;

  /** Any other custom header fields. */
  [key: string]: unknown;
}

/**
 * Represents the standard JWT payload (claims) structure.
 */
export interface JwtPayload {
  /** Issued at time, in seconds since the epoch. */
  iat?: number;
  /** Expiration time, in seconds since the epoch. */
  exp?: number;
  /** Not before time, in seconds since the epoch. */
  nbf?: number;
  /** Authentication time, in seconds since the epoch. */
  auth_time?: number;
  /** Subject (usually the client ID). */
  sub?: string;
  /** Roles assigned to the user. */
  roles?: string[];

  /** Any other custom payload fields. */
  [key: string]: unknown;
}

/**
 * Claims used by service-to-service JWTs.
 */
export interface ServiceJwtPayload extends JwtPayload {
  /** Issuing microservice name, for example 'ms-institutions'. */
  iss: string;
  /** Receiving microservice name or names. */
  aud: string | string[];
  /** Subject. Defaults to the issuing microservice name. */
  sub: string;
}

/**
 * Options for creating a service-to-service JWT.
 */
export interface ServiceJwtOptions {
  /** Issuing microservice name, for example 'ms-institutions'. */
  issuer: string;
  /** Receiving microservice name or names. */
  audience: string | string[];
  /** Parsed private Ed25519 JWK owned by the issuing microservice. */
  signingJwk: JwtSigningJwk;
  /** Subject claim. Defaults to issuer. */
  subject?: string;
  /** Issued-at timestamp in seconds or milliseconds. Defaults to now. */
  issuedAt?: number;
  /** Token lifetime in seconds. Defaults to 60. */
  expiresInSeconds?: number;
  /** Additional non-sensitive JWT claims. */
  claims?: Record<string, unknown>;
}

/**
 * Container for the decoded header and payload of a JWT.
 */
export interface JwtParts {
  /** Decoded JWT header. */
  header: JwtHeader;
  /** Decoded JWT payload. */
  payload: JwtPayload;
}

/**
 * Structure of the JWT object attached to the request.
 */
export interface JwtRequestObject {
  header: JwtHeader;
  payload: JwtPayload;
  age?: number;
  jwtClientId: (req?: AuthenticatedRequest) => string | undefined;
  doesJwtUserHasRole: (role: string) => boolean;
  isJwtExpired: (jwtValiditySeconds?: number) => boolean;
  jwtAgeInSeconds: (req?: AuthenticatedRequest) => number;
}

/**
 * Structure of the visitor object attached to the request.
 */
export interface VisitorRequestObject {
  header: JwtHeader;
  payload: JwtPayload;
  visitorClientId: (req?: AuthenticatedRequest) => string | undefined;
}

/**
 * Extended Express Request to include jwt and visitor objects.
 */
export interface AuthenticatedRequest extends Request {
  jwt?: JwtRequestObject | null;
  visitor?: VisitorRequestObject | null;
}

declare const jwtSigningJwkBrand: unique symbol;
declare const jwtVerificationJwksBrand: unique symbol;
declare const passwordHashKeyringBrand: unique symbol;

export interface JwtSigningJwk {
  readonly kid: string;
  readonly [jwtSigningJwkBrand]: true;
}

export interface JwtVerificationJwks {
  readonly kids: readonly string[];
  readonly [jwtVerificationJwksBrand]: true;
}

export interface PasswordHashKeyring {
  readonly activeKeyId: string;
  readonly keyIds: readonly string[];
  readonly [passwordHashKeyringBrand]: true;
}

export interface PasswordCredential {
  readonly hash: string;
  readonly hashKeyId: string;
}

export interface PasswordCredentialVerification {
  readonly isValid: boolean;
  readonly needsRehash: boolean;
}

/**
 * Utility functions for string manipulation, base64 encoding, and parsing auth-related strings.
 * @deprecated Use native Buffer methods or other modern alternatives.
 */
export const stringUtilAuth: {
  /**
   * Converts a base64 string to be URL-safe (replaces + with -, / with _, and removes =).
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param urlUnsafeString - The string to convert.
   * @returns URL-safe string.
   */
  makeStringUrlSafe: (urlUnsafeString?: string) => string;
  /**
   * Reverses URL-safe conversion and restores standard base64 characters and padding.
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param urlSafeString - The URL-safe string to restore.
   * @returns Standard base64 string.
   */
  reverseStringUrlSafe: (urlSafeString?: string) => string;
  /**
   * Encodes a plain-text string to base64.
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param unCodedString - Plain-text string.
   * @returns Base64 encoded string.
   */
  asciiToBase64: (unCodedString: string) => string;
  /**
   * Decodes a base64 string to UTF-8 plain-text.
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param codedString - Base64 encoded string.
   * @returns Decoded plain-text string.
   */
  base64ToAscii: (codedString: string) => string;
  /**
   * Splits a JWT into its three base64-encoded string parts (header, payload, signature).
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param jwt - The full JWT string.
   * @returns An object with the three raw parts, or null if the format is invalid.
   */
  dotConnectedStringToHeaderPayloadSignature: (jwt: string) => {
    header: string;
    payload: string;
    signature: string;
  } | null;
  /**
   * Serializes an object into a URL-safe base64 string.
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param object - The object to serialize.
   * @returns URL-safe base64 string.
   */
  objectToBase64UrlSafeString: (object: unknown) => string;
  /**
   * Parses a URL-safe base64 string into an object.
   * @deprecated Use native Buffer methods or other modern alternatives.
   * @param urlSafeBase64String - URL-safe base64 string.
   * @returns The parsed object.
   */
  urlSafeBase64ToObject: (urlSafeBase64String: string) => unknown;
};

/**
 * Creates an EdDSA JWT with a fixed JWT header and the signing JWK's kid.
 * @param payloadObject - Payload data for the JWT.
 * @param signingJwk - A parsed private Ed25519 signing JWK.
 * @returns Signed JWT string or null for invalid input.
 */
export function jwtCreateSignedToken(
  payloadObject: JwtPayload,
  signingJwk: JwtSigningJwk,
): string | null;

/**
 * Creates a signed service-to-service JWT using the issuing service's private key.
 * @param options - Service JWT creation options.
 * @returns Signed JWT string or null if validation or signing fails.
 */
export function jwtCreateServiceToken(options: ServiceJwtOptions): string | null;

/**
 * Creates a Bearer Authorization header containing a signed service-to-service JWT.
 * @param options - Service JWT creation options.
 * @returns Bearer Authorization header or null if validation or signing fails.
 */
export function jwtCreateServiceAuthorizationHeader(options: ServiceJwtOptions): string | null;

/**
 * Verifies a JWT by selecting its kid from a parsed public JWKS.
 * @param jwt - The JWT string to verify.
 * @param verificationJwks - Parsed public Ed25519 verification keys.
 * @returns True if the signature is valid, false otherwise.
 */
export function jwtVerifySignedToken(jwt: string, verificationJwks: JwtVerificationJwks): boolean;

/** Parses and validates one private Ed25519 signing JWK. */
export function parseJwtSigningJwk(serializedJwk: string): JwtSigningJwk;

/** Parses and validates an RFC 7517 public Ed25519 JWKS. */
export function parseJwtVerificationJwks(serializedJwks: string): JwtVerificationJwks;

/**
 * Decodes a JWT and returns its header and payload as objects.
 * Note: This does NOT verify the signature.
 * @param jwt - The JWT string to parse.
 * @returns An object containing the header and payload, or null if parsing fails.
 */
export function jwtGetHeaderPayload(jwt: string): JwtParts | null;

/** Parses a validated active/retiring password hash keyring. */
export function parsePasswordHashKeyring(
  activeKeyId: string,
  serializedKeyring: string,
): PasswordHashKeyring;

/** Creates a freshly salted active-key Argon2id credential. */
export function createPasswordCredential(
  password: string,
  keyring: PasswordHashKeyring,
): Promise<PasswordCredential>;

/** Verifies a credential and reports whether it should move to the active key. */
export function verifyPasswordCredential(
  password: string,
  credential: PasswordCredential,
  keyring: PasswordHashKeyring,
): Promise<PasswordCredentialVerification>;
