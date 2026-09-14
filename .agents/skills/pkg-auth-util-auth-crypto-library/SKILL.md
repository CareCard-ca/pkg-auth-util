---
name: pkg-auth-util-auth-crypto-library
description: 'Use when changing pkg-auth-util auth, password, JWT, crypto, key, exported API, types, or package validation behavior.'
---

Non-negotiable root-cause solution rule: Always identify and solve the verified root cause, use the stronger solution, and deliver a correct, durable, production-quality result. Never treat a temporary workaround, resource increase, retry, suppression, bypass, or symptom-only patch as completion. Validate the root-cause fix against the real failing workflow and prove the end state.

# Package Auth Util

Non-negotiable TDD rule: Always write the failing test first, run it to confirm it fails for the intended reason, then implement the code and rerun the test until it passes. Test Driven Development is required for all coding work and must not be skipped. For documentation- or skill-only edits, run the relevant focused non-test
validation before changing the prose; do not add automated tests that inspect
prose, files, or repository structure.

Non-negotiable repository isolation rule: Every repository must run its Husky hooks and tests using only files, code, fixtures, dependencies, and services contained within that repository. Tests and Husky scripts must not import, require, read, execute, or otherwise depend on sibling repositories or paths outside the repository root. app-e2e-tests is the only exception because cross-repository end-to-end testing is its explicit responsibility.

Non-negotiable error and warning rule: Never suppress, silence, hide, downgrade, filter, ignore, skip, or bypass errors or warnings from code, tests, tools, compilers, linters, or validation. Fix the root cause, then rerun the affected check and require a clean result. Expected error-path tests may assert errors, but must not conceal unexpected failures.

Non-negotiable TypeScript type rule: Never use the TypeScript type `any`; always use specific domain types, generics, existing project types, or `unknown` with explicit narrowing in all TypeScript-family files (`.ts`, `.tsx`, `.mts`, `.cts`, and `.d.ts`).

Non-negotiable code organization rule: Functions with the same or equivalent behavior must use the same or clearly corresponding descriptive names across CareCard repositories, and equivalent functionality must live in files with the same names within each repository's established architecture. No backward compatibility names, aliases, or duplicate locations are allowed.

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

- Write a new failing consumer-facing test through the supported package root
  before behavior or public API changes. Modify a pre-existing test only after
  the user grants fresh, explicit permission for that exact change.
- Include consumer-facing runtime and compilation tests through the supported package root. Exercise public behavior and realistic type usage without inspecting export objects, source files, or module layout.
- Run package test, lint, type, and Husky validation commands required by the changed area.

## Safety Constraints

- Do not edit generated output, dependency folders, logs, coverage, dist, or build artifacts unless the task requires it.
- Do not revert or overwrite user changes; stage only requested skill or instruction files.
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
- Use Test-Driven Development. Add a new failing consumer-facing Mocha or type
  test through the supported package root before changing behavior or exported
  API. Modify a pre-existing test only after the user grants fresh, explicit
  permission for that exact change.
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
- `lib/jwkUtilAuth.js` owns strict signing-JWK and verification-JWKS parsing.
- `lib/pwdUtilAuth.js` owns password keyring parsing and versioned credential
  hashing and verification.
- `lib/cryptoUtilAuth.js` wraps Node.js `crypto` primitives for signing,
  verifying, generating HMACs, and salts.
- `lib/stringUtilAuth.js` owns legacy base64, base64-url-safe, and JWT string
  helpers. Password-hash parsing stays private to `lib/pwdUtilAuth.js`.
- Keep direct exports as the public package API. Do not add password aliases,
  nested password objects, or compatibility parsers.
- Preserve CommonJS exports unless the repository intentionally migrates module
  systems.

## JWT Layer

- Accept only parsed Ed25519 signing JWKs and verification JWKS values. Do not
  add PEM, RSA, algorithm-selection, missing-`kid`, or single-key fallbacks.
- Derive every `kid` as the RFC 7638 SHA-256 base64url thumbprint of canonical
  `{ "crv": "Ed25519", "kty": "OKP", "x": ... }` members.
- Require exact JWK metadata: `alg: "EdDSA"`, `use: "sig"`, and one `key_ops`
  value (`sign` for private keys, `verify` for public keys). Ensure private and
  public key material agree before accepting signing configuration.
- Create JWTs with the fixed `{ alg: "EdDSA", typ: "JWT", kid }` header and
  verify by selecting the exact public key named by `kid`.
- Keep service-to-service JWT creation here, not in `@carecard/jwt-read`.
  Public service-token creation exports are `jwtCreateServiceToken` and
  `jwtCreateServiceAuthorizationHeader`.
- Do not silently change token timing behavior, token formats, JWT string
  assembly, signature verification semantics, or decomposition return shapes.
- Preserve application JWT payload claims, including the `roles` array.
  `ms-auth` RLS treats `roles: ["ad"]` as the auth-service super-admin signal,
  so JWT helpers must not hide, rename, or drop that role data.
- Expected parse and verify failures should return `null` or `false` where the
  current public API does so.

## Password And Crypto Layer

- Create password credentials with Node.js `crypto.argon2` using Argon2id,
  version 19, 19,456 KiB memory, two passes, one degree of parallelism, a
  unique 16-byte random salt, a 32-byte tag, and a pepper of at least 32 UTF-8
  bytes.
- Persist only the strict unpadded PHC string:

  ```text
  $argon2id$v=19$m=19456,t=2,p=1$base64(salt)$base64(tag)
  ```

- `parsePasswordHashKeyring(activeKeyId, serializedKeyring)`,
  `createPasswordCredential(password, keyring)`, and
  `verifyPasswordCredential(password, credential, keyring)` are the only
  public password credential APIs. Keyring entries are comma-separated
  `key-id:canonical-base64-32-byte-key` values.
- Persist the returned `hash` and `hashKeyId` together. Verification returns
  `{ isValid, needsRehash }`; `needsRehash` is true only after a valid retiring
  key credential is verified.
- Generate salts internally for every credential. Never accept caller-selected
  salts and never persist or log the pepper.
- Normalize well-formed Unicode passwords to NFC before deriving the tag, but
  do not trim or impose password policy here. `@carecard/validate` owns policy,
  while login intentionally permits existing passwords of any length.
- Return an invalid verification result for unknown key IDs, malformed,
  non-canonical, differently parameterized, or legacy saved hashes. Throw for
  programmer/configuration errors such as an invalid keyring.
- Do not add legacy HMAC verification. Seeded accounts must be rehashed before
  the Argon2id-only service starts.
- Prefer Node.js `crypto` primitives over new dependencies.

## String Utilities

- Use `stringUtilAuth` for base64 and URL-safe string transformations to keep
  parsing and serialization consistent.
- Do not expose password-hash parsing through `stringUtilAuth`.
- Cover edge cases for malformed JWT strings, bad base64 input, missing
  segments, and unsupported algorithms when these paths change.

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
  errors in callers that expect throws.

## Types And Exports

- Keep `index.d.ts` in sync with every public export in `index.js`.
- Avoid new loose index signatures. If payloads need custom claims, type them as
  `Record<string, unknown>` or a named claim interface.
- Keep deprecated APIs marked as deprecated and prefer direct public-package
  usage examples in documentation.
- When public types, overloads, return values, payload shapes, or declaration
  behavior change, compile realistic consumer usage through the supported
  package root. Do not assert that a named export or declaration node exists.

## Tests

- Use Mocha for runtime tests under `test`.
- Exercise runtime scenarios only through the supported package root. Tests
  must not mirror `lib` modules, depend on internal file layout, or inspect
  named exports for existence.
- Compile realistic consumer code through the package root with `tsc` to
  verify externally visible declaration behavior.
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

Fetches needed to establish a fresh `origin/main` at task start and before a
source-branch push are authorized without a separate approval question. Commits,
pushes, PR mutations, and branch cleanup require an authorized task; a request
for local work alone does not authorize publication. An authorized squash merge
into `main` includes the merged-source cleanup, local `main` update, and
`development` synchronization below unless the user explicitly says otherwise.
Never delete local or remote `main`, or force-push to remote `main`, including
with `--force-with-lease`.

## Agent Guidance Git Workflow

Reuse the current working branch for every follow-up request, even when the
subject changes or the working tree is clean. Create a branch only when no
working branch exists or the checkout is on `main` or `development`. Otherwise,
fetch remote `main` HEAD and rebase the same working branch onto that fetched
commit, preserving its commits and uncommitted work.

Work from the owning repository root and stage only intended guidance changes.
Fetch fresh `origin/main` at task start. Create `<agent-name>/<branch-name>`
from it only when no working branch exists or the current branch is `main` or
`development`. Otherwise keep
and rebase the current branch onto it, preserving existing commits and
uncommitted changes. Build subsequent task commits on that same branch, even
for a different task or a clean working tree. Honor explicit user
working-branch instructions.

Fetch again before every source-branch push and rebase only when the branch
does not already contain the latest `origin/main`. Required fetches need no
separate approval; commits, pushes, PR mutations, and cleanup require an
authorized task. A local guidance edit does not authorize publishing it.

For an authorized merge, create or reuse the PR into `main`, run applicable
validation, and squash-merge; administrator privileges may be used without
GitHub reviews. Verify the merge and delete its source branch remotely and
locally after checking for newer unmerged work. Then fast-forward local `main`
and replace local and remote branches named exactly `development` with the
latest remote `main` commit, using an explicit observed-commit
`--force-with-lease` remotely. Create a missing development counterpart when
either existed; leave repositories with neither unchanged. If development was
the merged source, recreate it from the new main. Verify commit parity and
cleanup; preserve dirty worktrees and report conflicts or rejected leases.

Never delete local or remote `main` or force-push to remote `main`, including
with `--force-with-lease`. Guard exact destination refs before deleting or
forcing any branch. Do not amend commits or stage unrelated files.

## Fail-Closed Test Lifecycle Audit

The current package tests own no HTTP listener, database pool, Kafka client,
background timer, or child process after completion. Mocha's test timeout fails
a stalled async test, the suites run without bail or forced exit, and npm
preserves each command's nonzero status. Keep natural process exit as the open
handle regression check; validation must not hide failures with retries, forced
success, skipped tests, or output suppression.

Do not add unpublished executable validation code to a `pkg-*` repository. If a
future test owns a long-lived resource or demonstrates a post-suite hang, add a
contract-tested process watchdog through the coordinated package version,
publish, and consumer propagation workflow. That watchdog must return
immediately when no helper remains, allow only a bounded 250 ms settlement
window for already-stopping helpers, fail persistent descendants, preserve
failures and output, use exit code `124` only for a real outer deadline, and
remain a final guard rather than a substitute for explicit cleanup.

## TDD And Validation

Test Driven Development is a non-negotiable requirement.

The sole purpose of automated tests is to verify observable functionality and externally visible behavior.
Tests must validate what the system does through its public interfaces and expected outcomes.

Tests must not assert, inspect, or depend on implementation details, including but not limited to:

- The existence of specific lines of code, statements, functions, classes, files, or modules.
- Specific algorithms, control flow, variable names, method calls, code snippets, or internal implementation choices.
- Any internal structure that can change without changing externally observable behavior.

A correct implementation may be completely rewritten or refactored without requiring changes to functional tests, provided its externally observable behavior remains unchanged.

Any test that fails solely because the implementation changed while the externally observable behavior remained correct is incorrectly designed and must be rewritten or removed.

This requirement is mandatory for all new tests and must be applied whenever existing tests are modified.
