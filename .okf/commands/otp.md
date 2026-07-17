---
type: command
title: otp / perfect (one-time pad)
description: Vernam-cipher command that auto-generates a correctly sized pad
resource: file://../../otp.go
tags: [crypto, otp, vernam]
timestamp: 2026-07-16
---

# otp (alias: perfect)

Implements a one-time pad (Vernam cipher): on encrypt, reads plaintext,
generates a random pad the same length via `crypto/rand`, writes it to
`--pad`, and XORs. On decrypt, reads the pad and ciphertext and reverses.

- `-p/--pad string` pad file path (required): written on encrypt, read on
  decrypt
- `--force` allow overwriting an existing pad file when encrypting (refused
  by default — reusing a pad breaks one-time-pad security)
- `--delete-pad` delete the pad file after a successful decrypt

## Why this exists alongside `xor`

`enc xor --strict` is the manual building block: caller sizes the key/pad
by hand and XORs. `otp` automates the "size the pad to the message, use it
once" discipline. See [codecs.md](./codecs.md) for `xor`.

## Perfection depends on caller discipline

Only actually information-theoretically secure if: pad is truly random
(`crypto/rand` — satisfied), pad length matches message (enforced), pad used
exactly once and destroyed (`--force`/`--delete-pad` help but depend on the
caller), and the pad reaches the recipient over a channel as secure as the
message (out of scope — `otp` doesn't solve key distribution). There is also
no authentication: ciphertext is unauthenticated and malleable, unlike aes
`gcm` mode.

A standalone `otp generate --size N` (pad only, no plaintext yet) is a known
gap — see [../known-gaps.md](../known-gaps.md).
