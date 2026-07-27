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

## otp: pre-generate a standalone pad

`enc otp` currently only generates a pad as a side effect of encrypting
(read plaintext, size the pad to match, write it to `--pad`). A standalone
`otp generate --size N --out pad.dat` subcommand — writing N random bytes
without encrypting anything, for cases where two parties need to exchange a
pad out-of-band before either has plaintext to send — was considered and
deferred to keep the initial implementation scoped to the encrypt/decrypt
path. Would mirror `ed25519 generate`'s shape if added.

## rsa sign/verify: PSS padding

`enc rsa sign`/`enc rsa verify` (`rsa_sign.go`) currently only support
PKCS1v15 padding. RSA-PSS (`rsa.SignPSS`/`rsa.VerifyPSS`) is deferred; when
implemented, it should share the padding-mode choice with the PS256/384/512
item above (e.g. a common `--pss` flag or padding-mode convention) so the
two features don't diverge on RSA signing semantics.

## x509: certificate command

There is no `enc x509` command yet. A full-fledged version, following the
subcommand shape of `ed25519.go`/`rsa.go` (`addGenerateCmd` etc.), was
considered:

- **generate** — self-signed cert from a fresh or existing keypair
  (`x509.CreateCertificate`), mirroring `ed25519 generate`'s flags.
- **csr** — create a PKCS#10 certificate signing request
  (`x509.CreateCertificateRequest`).
- **sign** — issue a leaf cert by signing a CSR with a separate CA cert/key
  (`x509.CreateCertificate` with a parent), so the command can act as a
  minimal CA, not just self-signed/inspect.
- **dump** — parse and pretty-print a cert or CSR (subject, issuer, SANs,
  validity, key usage), following `jwt_dump.go`'s parse-and-print pattern.

RSA and Ed25519 keys (`rsa.go`, `ed25519.go`) are the key-type precedents to
reuse rather than duplicating key generation logic.

## jwt: JWK/JWKS support

`enc jwt` has no JWK (RFC 7517) support. Deferred ideas:

- A `jwk` subcommand (or flag) to export an existing RSA/Ed25519 public key
  (from `rsa.go`/`ed25519.go`) as a JWK, and a JWKS (key set) wrapper.
- `jwt verify --jwks <file>` — verify against a **local** JWKS file (no HTTP
  fetch — the tool has no network calls today and adding one would be a
  real design departure, not something to bake in here), selecting the key
  by `kid`.
- `x5c` header support — embed/verify a cert chain in the JWT header,
  linking to the `x509` command above (`x509 dump`'s parsing).

## oidc: ID token validation

Scoped narrowly to validating an OIDC ID token (a JWT) against a local
JWKS/issuer public key — signature check via the JWKS work above, plus
OIDC-specific claim checks (`iss`, `aud`, `exp`, `iat`, optional `nonce`)
layered on top of `jwt verify`/`jwt_dump.go`.

Full OAuth flows (authorization code grant, token endpoint exchange, browser
redirect handling) were considered and rejected as out of scope — they
require a running server/browser interaction and don't fit the tool's
single-shot pipe model (economy of mechanism).
