---
type: command
title: jwe
description: JWE encrypt/decrypt/dump command
resource: file://../../jwe.go
tags: [jwe, encryption, jose]
timestamp: 2026-07-16
---

# jwe

`enc jwe` reads plaintext from stdin, writes compact JWE to stdout. `dec jwe`
(or `enc -D jwe`) reverses.

- `-a/--alg string`: `dir, RSA-OAEP-256`. Encrypt default: `dir`. Decrypt: if
  omitted, taken from token's own `alg` header.
- `-e/--enc string`: `A128GCM, A192GCM, A256GCM`. Encrypt default: `A256GCM`.
  Decrypt: if omitted, taken from token's own `enc` header.
- `-k/--key string` raw symmetric CEK filename for `alg=dir`; must be
  exactly 16/24/32 bytes matching `--enc`
- `--private-key`/`--public-key`: RSA PKCS1 PEM for `alg=RSA-OAEP-256` (same
  format as `enc rsa`)
- `--kid string` key ID header, when encrypting
- `-n/--append-newline`

When decrypting, explicit `--alg`/`--enc` must match the token's header
(mismatch rejected); if omitted, both come from the header — same
algorithm-confusion caveat as [jwt.md](./jwt.md): **always pass explicitly
for untrusted tokens.** The IV is always fresh-random per encryption and
carried as its own token segment — there is no `--iv` flag (unlike
[symmetric-crypto.md](./symmetric-crypto.md)'s aes ctr mode).

## jwe dump

`enc jwe dump` == `dec jwe dump` (ignores `-d`/`-D`). Prints decoded
header/encryptedKey/iv/ciphertext/tag as JSON (hex-encoded fields;
`encryptedKey` empty for `alg=dir`), without decrypting and without
requiring a key. Takes no flags.

Known gaps: AES Key Wrap (`*KW`), ECDH-ES, PBES2, and CBC+HMAC composite
content encryption are all deferred — see [../known-gaps.md](../known-gaps.md).
