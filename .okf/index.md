---
type: cli-app
title: enc
description: Go CLI for encoding, encrypting, signing, and tokenizing stdin/file data
tags: [go, cli, cryptography, encoding, jwt, jwe]
resource: file://../go.mod
timestamp: 2026-07-16
okf_version: "0.1"
---

# enc

A single Go binary (`enc`/`dec`) that encodes, decodes, encrypts, decrypts,
signs, and verifies data via subcommands, built on `spf13/cobra`.

## Contents

- [architecture.md](./architecture.md) — the enc/dec dual-binary design,
  global flags, and the streaming-vs-buffered codec split
- [commands/](./commands/index.md) — one concept per command family
  (codecs, symmetric crypto, otp, rsa, ed25519, jwt, jwe)
- [known-gaps.md](./known-gaps.md) — deferred features tracked in
  [TODO.md](../TODO.md), summarized so an agent doesn't have to re-derive
  "is X supported" from source each time

## Orientation

Start with [architecture.md](./architecture.md) for how the binary is put
together, then drill into [commands/](./commands/index.md) for a specific
subcommand.
