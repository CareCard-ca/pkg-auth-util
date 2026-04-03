/**
 * Utility functions for authentication and authorization in the CareCard ecosystem.
 */

import {Request} from 'express';

/**
 * Represents the standard JWT header structure.
 */
export interface JwtHeader {
    /** The cryptographic algorithm used to secure the JWT. */
    alg?: string;
    /** The media type of the JWT. Defaults to 'JWT'. */
    typ?: string;

    /** Any other custom header fields. */
    [key: string]: any;
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
    [key: string]: any;
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
    jwtClientId: (req?: any) => string | undefined;
    doesJwtUserHasRole: (role: string) => boolean;
    isJwtExpired: (jwtValiditySeconds?: number) => boolean;
    jwtAgeInSeconds: (req?: any) => number;
}

/**
 * Structure of the visitor object attached to the request.
 */
export interface VisitorRequestObject {
    header: JwtHeader;
    payload: JwtPayload;
    visitorClientId: (req?: any) => string | undefined;
}

/**
 * Extended Express Request to include jwt and visitor objects.
 */
export interface AuthenticatedRequest extends Request {
    jwt?: JwtRequestObject | null;
    visitor?: VisitorRequestObject | null;
}

/**
 * Represents the decomposed parts of a stored password hash.
 * @deprecated Use native Buffer methods or other modern alternatives.
 */
export interface PasswordParts {
    /** Version indicator of the hashing format. */
    version: string;
    /** Base64 encoded algorithm name. */
    alg: string;
    /** Base64 encoded password hash. */
    hash: string;
    /** Base64 encoded random salt. */
    salt: string;
}

/**
 * Contains a pair of public and private cryptographic keys.
 */
export interface KeyPair {
    /** PEM formatted public key string. */
    publicKey: string;
    /** PEM formatted private key string. */
    privateKey: string;
}

/**
 * Utility functions for creating, verifying, and parsing JSON Web Tokens (JWT).
 */
export const jwtUtilAuth: {
    /**
     * Creates a signed JWT from header and payload objects.
     * Automatically normalizes header (sets alg/typ) and payload (sets iat/exp/etc. in seconds).
     * @param headerObject - Header data for the JWT.
     * @param payloadObject - Payload data for the JWT.
     * @param privateKey - PEM formatted private key to sign the token.
     * @returns Signed JWT string or null if an error occurs.
     */
    createSignedJwtFromObject: (headerObject: JwtHeader, payloadObject: JwtPayload, privateKey: string) => string | null;
    /**
     * Verifies the signature of a JWT using a public key.
     * @param jwt - The JWT string to verify.
     * @param publicKey - PEM formatted public key.
     * @returns True if the signature is valid, false otherwise.
     */
    verifyJwtSignature: (jwt: string, publicKey: string) => boolean;
    /**
     * Decodes a JWT and returns its header and payload as objects.
     * Note: This does NOT verify the signature.
     * @param jwt - The JWT string to parse.
     * @returns An object containing the header and payload, or null if parsing fails.
     */
    getHeaderPayloadFromJwt: (jwt: string) => JwtParts | null;
};

/**
 * Utility functions for password hashing and verification.
 */
export const pwdUtilAuth: {
    /**
     * Generates a password hash using a random salt and specified algorithm.
     * @param password - The plain-text password to hash.
     * @param secret - A pepper/secret key to combine with the password.
     * @param algorithm - The hashing algorithm to use (e.g., 'sha256').
     * @returns A string containing the formatted hash with metadata ($1$alg$hash$salt$).
     */
    createPasswordHashWithRandomSalt: (password: string, secret: string, algorithm: string) => string;
    /**
     * Generates a password hash using the same algorithm and salt from a previously saved hash.
     * Useful for verifying a password against a stored hash.
     * @param password - The plain-text password to verify.
     * @param savedPasswordHash - The full stored hash string (including salt and metadata).
     * @param secret - The pepper/secret key used for hashing.
     * @returns A hash string that should match the saved hash if the password is correct.
     */
    createPasswordHashBasedOnSavedAlgorithmSalt: (password: string, savedPasswordHash: string, secret: string) => string;
};

/**
 * Generates a public/private key pair for JWT signing.
 * @param algorithm - The algorithm to use ('ed25519' or 'rsa'). Defaults to 'ed25519'.
 * @returns A KeyPair object containing PEM formatted keys.
 */
export const createKeys: (algorithm?: 'ed25519' | 'rsa' | string) => KeyPair;

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
     * Parses a stored password hash string into its constituent parts.
     * @deprecated Use native Buffer methods or other modern alternatives.
     * @param passwordHash - The formatted hash string ($1$alg$hash$salt$).
     * @returns A PasswordParts object or null if the format is invalid.
     */
    dollarSignConnectedStringToAlgorithmHashSalt: (passwordHash: string) => PasswordParts | null;
    /**
     * Splits a JWT into its three base64-encoded string parts (header, payload, signature).
     * @deprecated Use native Buffer methods or other modern alternatives.
     * @param jwt - The full JWT string.
     * @returns An object with the three raw parts, or null if the format is invalid.
     */
    dotConnectedStringToHeaderPayloadSignature: (jwt: string) => {
        header: string,
        payload: string,
        signature: string
    } | null;
    /**
     * Serializes an object into a URL-safe base64 string.
     * @deprecated Use native Buffer methods or other modern alternatives.
     * @param object - The object to serialize.
     * @returns URL-safe base64 string.
     */
    objectToBase64UrlSafeString: (object: any) => string;
    /**
     * Parses a URL-safe base64 string into an object.
     * @deprecated Use native Buffer methods or other modern alternatives.
     * @param urlSafeBase64String - URL-safe base64 string.
     * @returns The parsed object.
     */
    urlSafeBase64ToObject: (urlSafeBase64String: string) => any;
};


export function jwtCreateSignedFromObject(headerObject: JwtHeader, payloadObject: JwtPayload, privateKey: string): string | null;

export function jwtVerifySignature(jwt: string, publicKey: string): boolean;

export function jwtGetHeaderPayloadFromJwt(jwt: string): JwtParts | null;

export function passwordCreateHashWithRandomSalt(password: string, secret: string, algorithm: string): string;

export function passwordCreateHashBasedOnSavedAlgorithmSalt(password: string, savedPasswordHash: string, secret: string): string;
