# Log

## 2026-07-16

**Initialization** — bootstrapped bundle from repo source (main.go, crypto.go,
crypto_modes.go, codec_streaming.go, codec_buffered.go, rsa.go, ed25519.go,
jwt.go, jwe.go, otp.go), README.md, and TODO.md. Concepts: architecture
(dual enc/dec binary, global flags, streaming vs buffered codecs, crypto
mode support matrix) and one command doc per family (codecs, symmetric
crypto, otp, rsa, ed25519, jwt, jwe), plus a known-gaps summary of TODO.md.
