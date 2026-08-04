---
type: command
title: Codecs (ascii85, base32, base58, base64, binary, hex, rot13, xor)
description: Encoding subcommands, streaming vs buffered implementations
resource: file://../../codec_streaming.go
tags: [codec, encoding]
timestamp: 2026-08-03
---

# Codecs

Every codec subcommand supports `-w/--ignore-whitespace` (decode-time) and
`-n/--append-newline`.

## Streaming codecs (`codec_streaming.go`)

ascii85, base32, base64, binary (alias `bin`), hex, rot13 (aliases
`rot`/`caesar`), xor — all wrap `io.Reader`/`io.Writer`, so input is
processed incrementally.

- `base64` adds `-u/--url` (URL-safe alphabet) plus `--pad`/`--no-pad`
  (`--no-pad` wins if both given)
- `base32` adds `--pad`/`--no-pad` (same precedence)
- `binary` encodes each byte as eight ASCII `0`/`1` characters (MSB first);
  decoding errors on an incomplete trailing octet (bit count not a multiple
  of 8), and on any character other than `0`/`1` (so undecoded whitespace
  without `-w` is also an error, matching the other codecs). Adds
  `-p/--pretty` (encode-only): groups octets with spaces, wraps every 6
  octets (`binary.OctetsPerLine`, `xxd -b` convention), and always ends the
  output in a trailing newline — pretty output still decodes cleanly with
  `-w`. Implemented in `binary/binary.go`, not `codec_streaming.go` itself.
- `rot13` adds `-r/--offset uint8` (default 13)
- `xor` adds `-k/--key string` (required, filename of key bytes) and
  `--strict` — by default a key shorter than the input is cycled/repeated;
  `--strict` errors instead. A cycled key is not information-theoretically
  secure; see [otp.md](./otp.md) for the one-time-pad-safe alternative that
  auto-sizes the key.

## Buffered codec (`codec_buffered.go`)

base58 — implemented via `github.com/btcsuite/btcd/btcutil/base58`, which
has no streaming API, so the whole input is read into memory before
encoding/decoding (unlike the `encoding/*`-backed streaming codecs above).
This is an implementation detail, not a documented user-facing limit.

- `--check string` version byte (`[0-255]`, decimal or `0x`-prefixed hex):
  switches to base58check encoding instead of plain base58
