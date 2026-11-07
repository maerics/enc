# Log

## 2026-11-06

**Update** — `commands/otp.md`: documented the new `otp generate` (alias
`gen`) subcommand (standalone `crypto/rand` pad, `--size`/`--out`,
refuses overwrite, mode 0600) and the `enc xor --strict` + `dec otp`
pre-shared-pad flow. Removed the otp item from `known-gaps.md` and noted
the subcommand in `architecture.md`. `--out` and the global `-o` are
mutually exclusive.

## 2026-08-03

**Update** — `commands/codecs.md`: documented the new `binary` (alias
`bin`) streaming codec (`binary/binary.go`) — ASCII `0`/`1` octet
encoding, `-w`-respecting decode with incomplete-octet and
invalid-character errors, and the `-p/--pretty` flag (`xxd -b`-style
grouping/wrapping with a trailing newline). Updated `commands/index.md`'s
codec list to match.

## 2026-07-16

**Initialization** — bootstrapped bundle from repo source (main.go, crypto.go,
crypto_modes.go, codec_streaming.go, codec_buffered.go, rsa.go, ed25519.go,
jwt.go, jwe.go, otp.go), README.md, and TODO.md. Concepts: architecture
(dual enc/dec binary, global flags, streaming vs buffered codecs, crypto
mode support matrix) and one command doc per family (codecs, symmetric
crypto, otp, rsa, ed25519, jwt, jwe), plus a known-gaps summary of TODO.md.
