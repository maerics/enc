# TODO

## jwt: additional algorithms

`enc/dec jwt` currently supports `none`, `HS256/384/512`, and `RS256/384/512`.
Deferred for a follow-up:

- **PS256/384/512** (RSA-PSS) — same RSA keys as `RS*`, swap
  `rsa.SignPKCS1v15`/`rsa.VerifyPKCS1v15` for `rsa.SignPSS`/`rsa.VerifyPSS` in
  `jwt.go`. Small addition.
- **ES256/384/512** (ECDSA) — needs:
  - A new EC key-pair generate path (`rsa.go`'s `addGenerateCmd` is RSA-only;
    either extend it or add a parallel `ecdsa` command).
  - JWT signatures are raw `r || s` (fixed-width, zero-padded to the curve's
    byte size), not the ASN.1 DER that `crypto/ecdsa.Sign` normally produces
    with `SignASN1` — needs manual encode/decode of `r`/`s` via `math/big`.

## jwe: additional algorithms

`enc/dec jwe` currently supports key management `dir`/`RSA-OAEP-256` and
content encryption `A128GCM/A192GCM/A256GCM`. Deferred for a follow-up:

- **A128KW/A192KW/A256KW** (AES Key Wrap) — no `crypto/*` stdlib support;
  needs a hand-rolled RFC 3394 key-wrap implementation (no existing building
  block for this anywhere in the repo).
- **ECDH-ES** (and `-A128KW`/`-A192KW`/`-A256KW` variants) — needs a new
  EC/OKP key type built on `crypto/ecdh` (`rsa.go`/`ed25519.go` are the only
  key-type precedents and neither fits), plus a hand-rolled Concat KDF
  (RFC 7518 §4.6.2) — no existing KDF code in the repo.
- **PBES2-HS256+A128KW** (and other PBES2 variants) — password-based key
  management; needs PBKDF2 (not currently a dependency) layered on top of
  the AES Key Wrap item above.
- **A128CBC-HS256/A192CBC-HS384/A256CBC-HS512** (composite CBC+HMAC content
  encryption, RFC 7518 §5.2) — needs a hand-rolled MAC-then-encrypt scheme;
  note plain CBC mode isn't even implemented yet for the existing `aes`/`des`
  commands (see `crypto_modes.go`'s reserved-but-unimplemented `cbc` mode),
  so this would be greenfield work on two fronts at once.

## rsa sign/verify: PSS padding

`enc rsa sign`/`enc rsa verify` (`rsa_sign.go`) currently only support
PKCS1v15 padding. RSA-PSS (`rsa.SignPSS`/`rsa.VerifyPSS`) is deferred; when
implemented, it should share the padding-mode choice with the PS256/384/512
item above (e.g. a common `--pss` flag or padding-mode convention) so the
two features don't diverge on RSA signing semantics.
