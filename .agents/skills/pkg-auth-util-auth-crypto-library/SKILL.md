---
name: pkg-auth-util-auth-crypto-library
description: Use when changing pkg-auth-util auth, password, JWT, crypto, key, exported API, types, or package validation behavior.
---

# Package Auth Util

## Purpose

CareCard auth utility package for JWT creation/verification primitives, password hashing, crypto helpers, key generation, and tests.

## When To Use

- Use when changing pkg-auth-util auth, password, JWT, crypto, key, exported API, types, or package validation behavior.
- Pair with `carecard-workspace-standards` when the task affects shared CareCard conventions or cross-repository contracts.

## When Not To Use

- Do not use for service-local behavior that should remain inside one API or app.
- Do not change package public APIs without updating consumers and compatibility tests.

## Relevant Files And Directories

- package entry files
- `src` when present
- `test`
- `package.json`
- `package-lock.json`
- `.husky`

## Coding Principles

- Preserve the repository structure, naming style, module system, and local helper patterns.
- Prefer readable, maintainable code with meaningful function, variable, file, and test names.
- Avoid new dependencies unless the existing stack cannot reasonably solve the task and the user confirms the tradeoff.
- Keep public exports stable and update CommonJS, ESM, TypeScript declaration, and compatibility surfaces together when present.

## Testing Expectations

- Write or update package tests before behavior or public API changes.
- Include type/export compatibility tests where the package already has them.
- Run package test, lint, type, and Husky validation commands required by the changed area.

## Safety Constraints

- Do not edit generated output, dependency folders, logs, coverage, dist, or build artifacts unless the task explicitly requires it.
- Do not revert or overwrite user changes; stage only files related to the requested skill or instruction update.
- Never suppress errors, lint failures, type failures, security failures, or failing tests; fix the underlying issue or report the blocker.
- Do not log or expose secrets, JWTs, passwords, credentials, private keys, sensitive personal data, SQL internals, or stack traces.

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
- `lib/jwtUtilAuth.js` owns JWT creation, service-to-service JWT creation,
  verification, and decomposition.
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
- Keep service-to-service JWT creation here, not in `@carecard/jwt-read`.
  Public service-token creation exports are `jwtCreateServiceToken` and
  `jwtCreateServiceAuthorizationHeader`.
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

## Remote Git Operations Guardrail

Do not run remote Git or GitHub operations unless the current user request explicitly asks for that remote operation. This includes `git fetch`, `git pull`, `git push`, `git push --delete`, remote branch cleanup, GitHub API calls, and any `gh pr` command that creates, updates, readies, merges, closes, or cleans up a pull request. Do not infer permission from branch names, validation needs, prior workflow habits, or convenience; ask first when remote state would be useful but was not requested.

## Agent Guidance Git Workflow

When this skill or any repository-owned `.agents` guidance changes, use the
repository's agents-only Git workflow:

1. Work from the affected repository root and confirm only intended `.agents`
   files changed.
2. Use `development` as the base branch when `origin/development` exists;
   otherwise use the repository's default base branch, usually `main`.
3. Create or update `feature/codex` from the updated remote base branch and
   commit all the changed `.agents` guidance files there.
4. Push `feature/codex`, create or reuse a pull request into the base branch,
   and mark the pull request ready for review with `gh pr ready <number>`.
5. Squash-merge with administrator privileges and delete the remote branch:

   ```sh
   gh pr merge <number> --squash --admin --delete-branch
   ```

6. After merge, update the local base branch and remove the local feature
   branch:

   ```sh
   git fetch origin <base> --prune
   git switch <base>
   git pull --ff-only origin <base>
   git branch -d feature/codex
   git ls-remote --heads origin feature/codex
   ```

Do not commit or push `.agents` guidance changes directly from `development`
or `main`. Do not stage unrelated files, generated output, dependency folders,
build artifacts, logs, or `.DS_Store`.
