---
type: command
title: Symmetric crypto (aes, des, des3)
description: Block cipher subcommands and their supported modes
resource: file://../../crypto.go
tags: [crypto, aes, des, symmetric]
timestamp: 2026-07-16
---

# aes, des, des3

Aliases: `des3` → `3des`, `tripledes`, `triple-des`.

- `-k/--key string` key filename (required)
- `-m/--mode mode` default `gcm` for aes, `ctr` for des/des3
- `--iv string` initialization vector filename (`ctr` mode only); random IV
  generated if omitted; not supported in `gcm` (always a random nonce,
  prepended to ciphertext)
- `--omit-iv` omit IV from output (`ctr` mode only)
- `-a/--additional-data string` (aes only) AAD filename, `gcm` mode only

## Modes: implemented vs reserved

`crypto_modes.go` enumerates `block, cbc, cfb, ctr, ecb, ofb, gcm` as valid
flag values, but only `block`, `ctr`, and `gcm` (aes only) are actually
implemented (`crypto.go`, `crypto_modes_test.go`). Selecting `cbc`, `cfb`,
`ecb`, or `ofb` passes flag validation but errors at runtime — they're
reserved for future work, not currently functional. See
[../known-gaps.md](../known-gaps.md).

`--iv`/`--omit-iv` in `gcm` mode are rejected outright (not silently
ignored) per a recent fix — previously they were silently ignored.
