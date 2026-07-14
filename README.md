# enc

Encode and encrypt data.

`enc` encodes/encrypts by default; the `-d`/`-D` flags decode.
A `dec` symlink (or copy) of the same binary decodes by default.

## Usage

```
Encrypt and encode data.

Usage:
  enc [flags]
  enc [command]

Available Commands:
  aes         Encrypt input using AES
  ascii85     Encode input using ASCII85
  base32      Encode input using BASE32
  base58      Encode input using BASE58
  base64      Encode input using BASE64
  des         Encrypt input using DES
  des3        Encrypt input using 3DES
  ed25519     Generate, sign, and verify using Ed25519 keys
  help        Help about any command
  hex         Encode input using HEX
  jwe         Encrypt input as a JWE
  jwt         Sign input claims as a JWT
  rot13       Encode input using ROT13
  rsa         Encrypt input using RSA public key
  xor         Encode input using XOR

Flags:
  -d, --decode               decode or decrypt input
  -D, --decrypt              decrypt or decode input
  -h, --help                 help for enc
  -i, --input-file string    the input filename, omit or use "-" for stdin
  -o, --output-file string   the output filename, omit or use "-" for stdout
  -v, --version              print the current version

Use "enc [command] --help" for more information about a command.
```

`-d/--decode` and `-D/--decrypt` are two names for the same flag.

## Commands

### Codecs (ascii85, base32, base58, base64, hex, rot13, xor)

Every codec subcommand supports:

- `-w, --ignore-whitespace` ignore whitespace characters when decoding
- `-n, --append-newline` append a trailing newline to the output

`base64` additionally supports `-u, --url` to use URL-safe encoding instead
of standard encoding.

`base64` and `base32` additionally support:

- `--pad string` padding character, default `=`
- `--no-pad` disable padding entirely (`--no-pad` wins if both are given)

`rot13` (aliases: `rot`, `caesar`) additionally supports:

- `-r, --offset uint8` rotation offset, default `13`

`xor` additionally supports:

- `-k, --key string` filename containing the XOR key bytes (required)

`base58` additionally supports:

- `--check string` version byte `[0-255]`, decimal or `0x`-prefixed hex; uses
  base58check encoding instead of plain base58

### aes, des, des3 (aliases: `3des`, `tripledes`, `triple-des`)

- `-k, --key string` key filename (required)
- `-m, --mode mode` encryption mode: `block, cbc, cfb, ctr, ecb, ofb, gcm`
  (default `gcm` for aes, `ctr` for des/des3). Only `block`, `ctr` and `gcm`
  (aes only) are currently implemented; the rest are reserved.
- `--iv string` initialization vector filename (`ctr` mode only); if omitted a
  random IV is generated. Not supported in `gcm` mode, which always generates
  a random nonce and prepends it to the ciphertext
- `--omit-iv` omit the initialization vector from encrypted output (`ctr`
  mode only; not supported in `gcm` mode)
- `-a, --additional-data string` (aes only) additional authenticated data
  filename, used in `gcm` mode

### rsa

- `--private-key string` private key filename
- `--public-key string` public key filename
- `-k, --key string` public or private key filename, depending on context;
  equivalent to whichever of the above applies

#### rsa generate (alias: `gen`)

- `-s, --size uint32` private key size in bits, default `2048`
- `--private-key string` file to write the private key, default `-` (stdout)
- `--public-key string` file to write the public key, default `-` (stdout)

#### rsa extract (aliases: `extract-public-key`, `extract-public`, `epk`, `ep`, `e`)

Extracts the public key from a private key.

- `--private-key string` file to read the private key, default `-` (stdin)
- `--public-key string` file to write the public key, default `-` (stdout)

#### rsa sign

Signs input from stdin using an RSA private key; writes the raw signature
bytes to stdout.

- `--private-key string` private key filename
- `-k, --key string` private key filename, equivalent to `--private-key`
- `-a, --hash string` hash algorithm, default `sha256`: `sha256, sha384,
  sha512`

#### rsa verify

Verifies input from stdin against a signature file using an RSA public key.
On success, writes the input back to stdout unchanged; on failure, exits
non-zero and writes nothing to stdout.

- `--public-key string` public key filename
- `-k, --key string` public key filename, equivalent to `--public-key`
- `-a, --hash string` hash algorithm, default `sha256`: `sha256, sha384,
  sha512`
- `-s, --signature string` signature filename (required)

### ed25519

Ed25519 has no standard encryption scheme, so unlike `rsa` there is no
top-level encrypt/decrypt behavior — only key generation and signing. Keys
are PEM-encoded PKCS8 (private) / PKIX (public), not RSA's PKCS1, so they
are much smaller than RSA keys.

#### ed25519 generate (alias: `gen`)

- `--private-key string` file to write the private key, default `-` (stdout)
- `--public-key string` file to write the public key, default `-` (stdout)

#### ed25519 extract (aliases: `extract-public-key`, `extract-public`, `epk`, `ep`, `e`)

Extracts the public key from a private key.

- `--private-key string` file to read the private key, default `-` (stdin)
- `--public-key string` file to write the public key, default `-` (stdout)

#### ed25519 sign

Signs input from stdin using an Ed25519 private key; writes the raw 64-byte
signature to stdout. There is no `--hash` flag: Ed25519 always hashes
internally and the hash is not user-selectable.

- `--private-key string` private key filename
- `-k, --key string` private key filename, equivalent to `--private-key`

#### ed25519 verify

Verifies input from stdin against a signature file using an Ed25519 public
key. On success, writes the input back to stdout unchanged; on failure,
exits non-zero and writes nothing to stdout.

- `--public-key string` public key filename
- `-k, --key string` public key filename, equivalent to `--public-key`
- `-s, --signature string` signature filename (required)

### jwe

`enc jwe` reads plaintext from stdin and writes a compact JWE to stdout.
`dec jwe` (or `enc -D jwe`) reads a compact JWE from stdin, decrypts it, and
writes the plaintext to stdout.

- `-a, --alg string` key management algorithm: `dir, RSA-OAEP-256`; when
  encrypting, defaults to `dir`; when decrypting, if omitted, it is taken
  from the token's own `alg` header
- `-e, --enc string` content encryption algorithm: `A128GCM, A192GCM,
  A256GCM`; when encrypting, defaults to `A256GCM`; when decrypting, if
  omitted, it is taken from the token's own `enc` header
- `-k, --key string` raw symmetric content-encryption key (CEK) filename,
  for `alg=dir`; must be exactly the byte size required by `--enc` (16/24/32
  bytes for A128/192/256GCM)
- `--private-key string` private key filename, for decrypting: RSA PKCS1
  PEM (same format as `enc rsa`/`enc rsa generate`) for `alg=RSA-OAEP-256`
- `--public-key string` public key filename, for encrypting: RSA PKCS1 PEM
  for `alg=RSA-OAEP-256`
- `--kid string` key ID to embed in the header when encrypting
- `-n, --append-newline` append a trailing newline to the output

When decrypting, if `--alg`/`--enc` are passed explicitly they must match
the token's own header `alg`/`enc`; a mismatch is rejected. If omitted, both
are taken from the token's header instead, which is convenient but exposes
the same kind of algorithm-confusion attack as `jwt`: a token can dictate
which RSA key or CEK size to trust. Always pass `--alg`/`--enc` explicitly
when decrypting tokens from an untrusted source. The IV is always freshly
random per encryption and is always carried as its own token segment; there
is no `--iv` flag to supply or omit one.

#### jwe dump

`enc jwe dump` (or `dec jwe dump`, identical either way — it ignores
`-d`/`-D`) reads a compact JWE from stdin and prints its decoded header,
encrypted key, IV, ciphertext, and tag as JSON, without decrypting anything
and without requiring a key:
```json
{
  "header": {"alg": "dir", "enc": "A256GCM"},
  "encryptedKey": "",
  "iv": "fc734b98f33107314dc87871",
  "ciphertext": "be5cab87b3",
  "tag": "86e9139be33b1e0665177a717230cfab"
}
```
`encryptedKey`/`iv`/`ciphertext`/`tag` are the raw bytes hex-encoded;
`encryptedKey` is empty for `alg=dir` tokens. Takes no flags.

### jwt

`enc jwt` reads a JSON claims object from stdin and writes a signed compact
JWT to stdout. `dec jwt` (or `enc -D jwt`) reads a compact JWT from stdin,
verifies its signature, and writes the decoded claims JSON to stdout. Pipe
either direction to/from `jq` for anything fancier (building claims,
inspecting `exp`/`nbf`, etc).

- `-a, --alg string` signing/verifying algorithm: `none, HS256, HS384, HS512,
  RS256, RS384, RS512, EdDSA`; when signing, defaults to `HS256`; when
  verifying, if omitted, it is taken from the token's own `alg` header (or
  `HS256` if that header is missing)
- `-k, --key string` HMAC secret key filename, for `HS*` algorithms
- `--private-key string` private key filename, for signing: RSA PKCS1 PEM
  (same format as `enc rsa`/`enc rsa generate`) for `RS*` algorithms, or
  Ed25519 PKCS8 PEM (same format as `enc ed25519 generate`) for `EdDSA`
- `--public-key string` public key filename, for verifying: RSA PKCS1 PEM
  for `RS*` algorithms, or Ed25519 PKIX PEM for `EdDSA`
- `--kid string` key ID to embed in the header when signing
- `--claim key=value` set a claim when signing, repeatable; the value is
  parsed as JSON when possible (e.g. `--claim admin=true` is boolean, `--claim
  count=3` is a number), otherwise used as a raw string
- `--expires-in duration` set the `exp` claim to now plus this duration when
  signing (e.g. `1h30m`)
- `--omit-iat` omit the automatic `iat` (issued at) claim when signing
- `-n, --append-newline` append a trailing newline to the output

When verifying, if `--alg` is passed explicitly it must match the token's own
header `alg`; a mismatch is rejected. If `--alg` is omitted, the algorithm is
taken from the token's header instead, which is convenient but exposes
algorithm-confusion attacks where a token claims a different or weaker
algorithm than the caller expects. Always pass `--alg` explicitly when
verifying tokens from an untrusted source.

#### jwt dump

`enc jwt dump` (or `dec jwt dump`, identical either way — it ignores
`-d`/`-D`) reads a compact JWT from stdin and prints its decoded header,
payload, and signature as JSON, without verifying anything and without
requiring a key:
```json
{
  "header": {"alg": "HS256", "typ": "JWT"},
  "payload": {"sub": "alice"},
  "signature": "c4734de3728923f73da616ebb72ae99e4156fbbc0703d760e201d55ed52f6461"
}
```
`signature` is the raw signature bytes hex-encoded. Takes no flags.

## Examples
```sh
# Common encodings.
$ echo OK | enc hex ; echo
# 4f4b0a
$ echo 4f4b0a | enc -D hex -w
# OK
$ echo QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD | enc caesar -r3
# THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
$ echo 'secret' > /tmp/secret.txt
$ echo 'Attack!' | enc xor --key=/tmp/secret.txt | enc base64 ; echo
# MhEXEwYfK3k=
$ echo MhEXEwYfK3k= | enc -D base64 | enc -D xor --key=/tmp/secret.txt
# Attack!

# RSA encryption.
$ enc rsa generate --private-key=priv.key --public-key=pub.key
$ echo 'Hello, RSA! 🔐' | enc rsa --key=pub.key | dec rsa --key=priv.key
# Hello, RSA! 🔐 

# RSA sign/verify.
$ echo 'Hello, RSA! 🔐' | enc rsa sign --key=priv.key > msg.sig
$ echo 'Hello, RSA! 🔐' | enc rsa verify --key=pub.key --signature=msg.sig
# Hello, RSA! 🔐

# Ed25519 sign/verify.
$ enc ed25519 generate --private-key=ed.priv --public-key=ed.pub
$ echo 'Hello, Ed25519! 🔐' | enc ed25519 sign --key=ed.priv > msg.sig
$ echo 'Hello, Ed25519! 🔐' | enc ed25519 verify --key=ed.pub --signature=msg.sig
# Hello, Ed25519! 🔐

# AES Encryption.
$ openssl rand 32 > aes.key
$ echo 'Hello, AES! 🔐' | enc aes --key=aes.key | dec aes --key=aes.key
# Hello, AES! 🔐

# DES/3DES Encryption.
$ openssl rand 24 > des3.key
$ echo 'Hello, 3DES! 🔐' | enc des3 --key=des3.key | dec des3 --key=des3.key
# Hello, 3DES! 🔐

# JWT signing/verification.
$ openssl rand 32 > hmac.key
$ echo '{"sub":"alice"}' | enc jwt --alg=HS256 --key=hmac.key --expires-in=1h \
  | dec jwt --alg=HS256 --key=hmac.key
# {"exp":...,"iat":...,"sub":"alice"}
$ enc rsa generate --private-key=priv.key --public-key=pub.key
$ echo '{"sub":"alice"}' | enc jwt --alg=RS256 --private-key=priv.key \
  | dec jwt --alg=RS256 --public-key=pub.key
# {"iat":...,"sub":"alice"}
$ enc ed25519 generate --private-key=ed.priv --public-key=ed.pub
$ echo '{"sub":"alice"}' | enc jwt --alg=EdDSA --private-key=ed.priv \
  | dec jwt --alg=EdDSA --public-key=ed.pub
# {"iat":...,"sub":"alice"}
$ echo '{"sub":"alice"}' | enc jwt --alg=HS256 --key=hmac.key | enc jwt dump
# {"header":{"alg":"HS256","typ":"JWT"},"payload":{"iat":...,"sub":"alice"},"signature":"..."}

# JWE encryption.
$ openssl rand 32 > cek.key
$ echo 'Hello, JWE! 🔐' | enc jwe --alg=dir --enc=A256GCM --key=cek.key \
  | dec jwe --alg=dir --enc=A256GCM --key=cek.key
# Hello, JWE! 🔐
$ echo 'Hello, JWE! 🔐' | enc jwe --alg=RSA-OAEP-256 --enc=A256GCM --public-key=pub.key \
  | dec jwe --alg=RSA-OAEP-256 --enc=A256GCM --private-key=priv.key
# Hello, JWE! 🔐
$ echo 'Hello, JWE! 🔐' | enc jwe --alg=dir --key=cek.key | enc jwe dump
# {"header":{"alg":"dir","enc":"A256GCM"},"encryptedKey":"","iv":"...","ciphertext":"...","tag":"..."}
```

## License

MIT, see [LICENSE](LICENSE).
