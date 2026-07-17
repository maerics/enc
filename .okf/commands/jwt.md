---
type: command
title: jwt
description: JWT sign/verify/dump command
resource: file://../../jwt.go
tags: [jwt, sign, jose]
timestamp: 2026-07-16
---

# jwt

`enc jwt` reads JSON claims from stdin, writes a signed compact JWT to
stdout. `dec jwt` reverses: reads a JWT, verifies, writes decoded claims
JSON.

- `-a/--alg string`: `none, HS256, HS384, HS512, RS256, RS384, RS512, EdDSA`.
  Sign default: `HS256`. Verify: if omitted, taken from the token's own
  `alg` header (or `HS256` if missing).
- `-k/--key string` HMAC secret filename, for `HS*`
- `--private-key`/`--public-key`: RSA PKCS1 PEM for `RS*` (same format as
  `enc rsa`), or Ed25519 PKCS8 PEM for `EdDSA` (same format as
  `enc ed25519 generate`)
- `--kid string` key ID header, when signing
- `--claim key=value` repeatable; value parsed as JSON when possible
  (`admin=true` → bool, `count=3` → number), else raw string
- `--expires-in duration` sets `exp` claim, e.g. `1h30m`
- `--omit-iat` skip automatic `iat` claim

## Algorithm-confusion risk

If `--alg` is omitted on verify, the algorithm comes from the *token's own*
header — convenient, but the classic JWT algorithm-confusion attack surface
(a malicious token dictates which key/algorithm the verifier trusts).
**Always pass `--alg` explicitly when verifying untrusted tokens.** Same
caveat applies to [jwe.md](./jwe.md)'s `--alg`/`--enc`.

## jwt dump

`enc jwt dump` == `dec jwt dump` (ignores `-d`/`-D`). Prints decoded header/
payload/signature (signature hex-encoded) as JSON without verifying and
without requiring a key. Takes no flags.

Known gaps: PS256/384/512 and ES256/384/512 not yet supported — see
[../known-gaps.md](../known-gaps.md).
