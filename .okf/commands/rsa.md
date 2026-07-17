---
type: command
title: rsa
description: RSA generate/extract/encrypt/decrypt/sign/verify
resource: file://../../rsa.go
tags: [crypto, rsa, sign]
timestamp: 2026-07-16
---

# rsa

Top-level `enc rsa`/`dec rsa` encrypt/decrypt using PKCS1 PEM keys.

- `--private-key` / `--public-key string` key filenames
- `-k/--key string` shorthand for whichever of the above applies to context

## rsa generate (alias: gen)

- `-s/--size uint32` private key size in bits, default 2048
- `--private-key`/`--public-key` output filenames, default `-` (stdout)

## rsa extract (aliases: extract-public-key, extract-public, epk, ep, e)

Extracts public key from a private key. `--private-key` default `-` (stdin),
`--public-key` default `-` (stdout).

## rsa sign / rsa verify (`rsa_sign.go`)

PKCS1v15 padding only — RSA-PSS is a known gap
([../known-gaps.md](../known-gaps.md)).

- `sign`: reads stdin, writes raw signature bytes to stdout.
  `--private-key`/`-k`, `-a/--hash string` (default `sha256`; `sha256,
  sha384, sha512`)
- `verify`: reads stdin, checks against `-s/--signature string` (required)
  using `--public-key`/`-k`, `-a/--hash`. On success writes input back to
  stdout unchanged; on failure exits non-zero, writes nothing.
