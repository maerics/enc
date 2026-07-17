---
type: subsystem
title: CLI architecture
description: enc/dec dual-binary design, global flags, and command registration
resource: file://../main.go
tags: [go, cli, cobra]
timestamp: 2026-07-16
---

# CLI architecture

## Dual binary via argv[0]

There is one binary; behavior toggles on how it's invoked. `getDefaultOptions`
(`main.go`) checks `filepath.Base(os.Args[0])`: if it's `dec`, `Options.Decode`
starts `true` and the command description flips to "Decrypt and decode data."
A `dec` symlink/copy of the same binary is the intended distribution
mechanism — see `.goreleaser.yml`.

The `-d/--decode` and `-D/--decrypt` flags are two names bound to the *same*
`Options.Decode` field (`main.go` `newEncCmd`), so they're interchangeable —
this is a deliberate design choice, not an oversight.

## Command registration

`newEncCmd` wires all subcommands onto one root `cobra.Command` via:

- `addStreamingCodecs` (`codec_streaming.go`) — ascii85, base32, base64, hex,
  rot13 (+aliases `rot`/`caesar`), xor
- `addBufferedCodecs` (`codec_buffered.go`) — base58 (needs the whole input
  buffered because `btcutil/base58` isn't a streaming API, unlike the
  `encoding/*` packages used above)
- `addSymmetricCryptoCommands` (`crypto.go`) — aes, des, des3 (+aliases
  `3des`/`tripledes`/`triple-des`)
- `addRSACommands` (`rsa.go`) — rsa (+ generate/extract/sign/verify)
- `addEd25519Commands` (`ed25519.go`) — ed25519 (+ generate/extract/sign/verify)
- `addJWTCommand` (`jwt.go`)
- `addJWECommand` (`jwe.go`)
- `addOTPCommand` (`otp.go`) — otp (alias `perfect`)

The streaming/buffered split is an implementation detail of each codec's
underlying Go package, not a user-facing distinction — see
[commands/codecs.md](./commands/codecs.md).

## Global flags and shared `Options`

A single `Options` struct (`main.go`) is threaded through every subcommand
via closures over `*Options` set up in `newEncCmd`. Global persistent flags:
`-d/--decode`, `-D/--decrypt`, `-i/--input-file`, `-o/--output-file`.

`setFilenameOptions` (`main.go`) opens `--input-file`/`--output-file` before
each command runs. Notably, the output file is opened with
`os.O_WRONLY|os.O_CREATE|os.O_EXCL` — **it refuses to overwrite an existing
output file** and errors instead. This is easy to miss when scripting against
`enc`/`dec` and re-running with the same `-o` path.

## Crypto modes

`crypto_modes.go` defines a `cryptoMode` enum: `block, cbc, cfb, ctr, ecb,
ofb, gcm`. Only `block`, `ctr`, and `gcm` (aes only) are actually implemented
in `crypto.go`/`crypto_modes_test.go` — the rest exist as reserved
placeholders in the flag validator so future modes don't require a flag
schema change, but selecting them currently errors at runtime. See
[commands/symmetric-crypto.md](./commands/symmetric-crypto.md).
