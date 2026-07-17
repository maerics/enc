---
type: reference
title: Known gaps / deferred features
description: Summary of TODO.md's deferred work, cross-linked from affected commands
resource: file://../TODO.md
tags: [todo, roadmap]
timestamp: 2026-07-16
---

# Known gaps

Authoritative detail lives in [TODO.md](../TODO.md); this is a summary so an
agent doesn't have to open it just to answer "does X support Y."

- **jwt**: PS256/384/512 (RSA-PSS) and ES256/384/512 (ECDSA) not supported.
  See [commands/jwt.md](./commands/jwt.md).
- **jwe**: AES Key Wrap (`A128/192/256KW`), ECDH-ES (+KW variants), PBES2
  password-based key management, and CBC+HMAC composite content encryption
  (`A*CBC-HS*`) not supported. See [commands/jwe.md](./commands/jwe.md).
- **otp**: no standalone `otp generate --size N` (pad-only, no plaintext
  yet). See [commands/otp.md](./commands/otp.md).
- **rsa sign/verify**: PKCS1v15 only, no RSA-PSS. See
  [commands/rsa.md](./commands/rsa.md).
- **crypto modes**: `cbc`, `cfb`, `ecb`, `ofb` are reserved flag values but
  not implemented for aes/des/des3. See
  [commands/symmetric-crypto.md](./commands/symmetric-crypto.md).
- **ed25519**: no OpenSSH key format or raw key input, PEM PKCS8/PKIX only.
  See [commands/ed25519.md](./commands/ed25519.md).
- **aes gcm**: no `--omit-iv`/custom `--iv` support (always random nonce
  prepended to ciphertext) — noted as a TODO for possible future support.
