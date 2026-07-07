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

## rsa sign/verify: PSS padding

`enc rsa sign`/`enc rsa verify` (`rsa_sign.go`) currently only support
PKCS1v15 padding. RSA-PSS (`rsa.SignPSS`/`rsa.VerifyPSS`) is deferred; when
implemented, it should share the padding-mode choice with the PS256/384/512
item above (e.g. a common `--pss` flag or padding-mode convention) so the
two features don't diverge on RSA signing semantics.
