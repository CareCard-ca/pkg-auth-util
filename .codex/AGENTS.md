# Codex Instructions For pkg-auth-util

These instructions apply to the `pkg-auth-util` repository. Follow the
workspace instructions in
`/Users/pankajpriscilla/SO_CareCardCa/.codex/AGENTS.md` first, then apply the
repository-specific guidance below.

## Non-Negotiable Instructions

- Never use TypeScript type `any`. Use precise exported interfaces, index
  signatures with `unknown`, generics, or explicit unions.
- Always follow the existing CommonJS utility-package style, Mocha tests,
  TypeScript declaration tests, and CareCard package conventions.
- Always follow existing naming conventions. Public functions use camelCase;
  internal helpers use the established underscore prefix.
- Always follow the existing project structure. Keep public exports in
  `index.js`, declarations in `index.d.ts`, implementation modules in `lib`,
  and tests in `test`.
- Always use Test-Driven Development. Add or update Mocha and type tests before
  changing behavior or exported API.
- Never suppress errors, type errors, linter warnings, crypto failures, or
  failing tests. Fix the cause.
- Do not add dependencies unless they are absolutely required. Ask for
  confirmation first with the reason and tradeoff.
- Before finalizing work, run every direct script in `.husky` and follow
  `.junie/guidelines.md`. Do not bypass Husky.

## Package Scope

- This package provides authentication utilities used across CareCard services.
- `lib/jwtUtilAuth.js` owns JWT creation, verification, and decomposition.
- `lib/pwdUtilAuth.js` owns password hashing and saved-hash verification.
- `lib/keyGen.js` owns Ed25519 and RSA key generation.
- `lib/stringUtilAuth.js` owns legacy base64, URL-safe, JWT, and password-hash
  string parsing helpers.
- `index.js` is the public export surface. Keep direct exports preferred and
  deprecated nested exports backward compatible unless a breaking change is
  explicitly requested.

## Security And Error Handling

- Treat JWT signing, verification, password hashing, salts, secrets, and key
  generation as security-sensitive.
- Do not log secrets, private keys, tokens, password hashes, salts, or raw
  payloads.
- Preserve the current utility style: expected parse, verify, and hash failures
  should return `null` or `false` where the existing API does so.
- Do not silently change cryptographic defaults, token timing behavior, password
  hash string format, or key output format.
- Prefer Node.js `crypto` primitives already used by the package over new
  dependencies.

## Types And Exports

- Keep `index.d.ts` in sync with every public export in `index.js`.
- Avoid new loose index signatures. If payloads need custom claims, type them as
  `Record<string, unknown>` or a named claim interface.
- Keep deprecated APIs marked as deprecated and prefer direct export examples in
  docs and tests.
- Preserve CommonJS exports unless the repository intentionally migrates module
  systems.

## Testing And Validation

- Every implementation module in `lib` should have matching tests under `test`.
- `test/index.test.js` should cover scenarios through public exports.
- `test/types.test.ts` should verify TypeScript declarations.
- Cover success and failure cases for JWT parsing, signature verification,
  password hashing, saved-hash verification, key generation, and string parsing.
- `.husky/pre-commit` currently runs `npm run lint:fix`, `npm run format`, and
  `npm run test:All`.
