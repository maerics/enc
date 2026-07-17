---
type: index
title: Commands
description: One concept doc per command family exposed by the enc/dec binary
---

# Commands

- [codecs.md](./codecs.md) — ascii85, base32, base58, base64, hex, rot13, xor
- [symmetric-crypto.md](./symmetric-crypto.md) — aes, des, des3
- [otp.md](./otp.md) — otp / perfect (one-time pad)
- [rsa.md](./rsa.md) — rsa generate/extract/sign/verify
- [ed25519.md](./ed25519.md) — ed25519 generate/extract/sign/verify
- [jwt.md](./jwt.md) — jwt sign/verify/dump
- [jwe.md](./jwe.md) — jwe encrypt/decrypt/dump

See [../architecture.md](../architecture.md) for how these are registered
and share global flags/`Options`.
