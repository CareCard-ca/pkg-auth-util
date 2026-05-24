---
name: pkg-auth-util
description: Use when changing pkg-auth-util, the @carecard/auth-util CommonJS authentication utility package. Covers JWT creation, verification, decomposition, password hashing and saved-hash verification, crypto primitives, Ed25519/RSA key generation, base64/JWT/password string parsing, public exports, TypeScript declarations, Mocha tests, type tests, and security-sensitive auth behavior.
---

# Package Auth Util

## Overview

Use this skill when working inside `pkg-auth-util`, the `@carecard/auth-util`
package. It provides core authentication and authorization utilities for the
CareCard ecosystem.

Use `$carecard-workspace-standards` for shared workspace, dependency, package,
testing, and security rules. Legacy `pkg-auth-util/.codex` and
`pkg-auth-util/.junie` guidance has been migrated into these skills; do not
depend on those folders being present.

## Non-Negotiable Rules

- Never use TypeScript type `any`. Use precise exported interfaces, index
  signatures with `unknown`, generics, explicit unions, or explicit narrowing.
- Follow the existing CommonJS utility-package style, Mocha tests, TypeScript
  declaration tests, and CareCard package conventions.
- Follow existing naming conventions:
  - Public functions use camelCase.
  - Internal helpers use the established underscore prefix.
- Keep public exports in `index.js`, declarations in `index.d.ts`,
  implementation modules in `lib`, and tests in `test`.
- Use Test-Driven Development. Add or update Mocha and type tests before
  changing behavior or exported API.
- Never suppress errors, type errors, linter warnings, crypto failures, or
  failing tests. Fix the cause.
- Do not add dependencies unless absolutely required. Ask for confirmation first
  with the reason and tradeoff.
- Before finalizing work, run every direct script in `.husky`. Do not bypass
  Husky.

## Package Scope

- `index.js` is the centralized public export surface.
- `index.d.ts` must stay aligned with every public export in `index.js`.
- `lib/jwtUtilAuth.js` owns JWT creation, verification, and decomposition.
- `lib/pwdUtilAuth.js` owns password hashing and saved-hash verification.
- `lib/cryptoUtilAuth.js` wraps Node.js `crypto` primitives for signing,
  verifying, generating HMACs, and salts.
- `lib/keyGen.js` owns Ed25519 and RSA key generation.
- `lib/stringUtilAuth.js` owns legacy base64, base64-url-safe, JWT, and
  password-hash string parsing helpers.
- Keep direct exports preferred and deprecated nested exports backward
  compatible unless a breaking change is explicitly requested.
- Preserve CommonJS exports unless the repository intentionally migrates module
  systems.

## JWT Layer

- Use EdDSA/Ed25519 as the default JWT algorithm unless a task explicitly
  changes crypto behavior.
- Preserve standardized headers and payload behavior, including automatic `iat`
  and `exp` population where the existing API does that.
- Do not silently change token timing behavior, token formats, JWT string
  assembly, signature verification semantics, or decomposition return shapes.
- Expected parse and verify failures should return `null` or `false` where the
  current public API does so.

## Password And Crypto Layer

- Preserve the HMAC-based password hashing behavior.
- Preserve the saved password hash string format:

  ```text
  $1$base64(algorithm)$base64(hash)$base64(salt)$
  ```

- Always handle salt automatically when creating new password hashes.
- Do not silently change cryptographic defaults, password hash string format,
  salt behavior, or key output format.
- Prefer Node.js `crypto` primitives already used by the package over new
  dependencies.

## String Utilities

- Use `stringUtilAuth` for base64 and URL-safe string transformations to keep
  parsing and serialization consistent.
- Keep legacy formatted string parsing behavior backward-compatible.
- Cover edge cases for malformed JWT strings, malformed password hashes, bad
  base64 input, missing segments, and unsupported algorithms when these paths
  change.

## Security And Error Handling

- Treat JWT signing, verification, password hashing, salts, secrets, private
  keys, public keys, reset tokens, and key generation as security-sensitive.
- Do not log secrets, private keys, tokens, password hashes, salts, raw
  payloads, full JWT payloads, or credentials.
- Preserve the current utility style: expected parse, verify, and hash failures
  should fail gracefully by returning `null` or `false` where the existing API
  does so.
- Use `try/catch` inside utility functions where existing functions fail
  gracefully instead of throwing uncaught exceptions.
- Do not broaden catch blocks in a way that hides unexpected implementation
  errors in callers that currently expect throws.

## Types And Exports

- Keep `index.d.ts` in sync with every public export in `index.js`.
- Avoid new loose index signatures. If payloads need custom claims, type them as
  `Record<string, unknown>` or a named claim interface.
- Keep deprecated APIs marked as deprecated and prefer direct export examples in
  docs and tests.
- Update type tests whenever public exports, overloads, return values, payload
  shapes, or declaration behavior changes.

## Tests

- Use Mocha for runtime tests under `test`.
- Every implementation module in `lib` should have matching tests under `test`.
  For example, `lib/jwtUtilAuth.js` should be covered by
  `test/jwtUtilAuth.test.js`.
- `test/index.test.js` should cover scenarios through the public exports from
  `index.js`.
- `test/types.test.ts` verifies TypeScript declarations with `tsc`.
- Cover success and failure cases for JWT parsing, signature verification,
  password hashing, saved-hash verification, key generation, base64 conversion,
  URL-safe conversion, and string parsing.
- Keep tests deterministic and avoid external services.

## Validation

Useful commands:

- `npm run lint`
- `npm run lint:fix`
- `npm run format`
- `npm run format:check`
- `npm run test`
- `npm run test:types`
- `npm run test:coverage`
- `npm run test:All`

Before pushing or finalizing, run every direct `.husky` script. The current
`.husky/pre-commit` runs:

```bash
npm run lint:fix
npm run format
npm run test:All
```

If any validation command cannot run, report the exact command, failure reason,
and remaining risk.
