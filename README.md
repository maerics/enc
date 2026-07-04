# enc

Encode and encrypt data.

`enc` encodes/encrypts by default; the `-d`/`-D` flags decode/decrypt. A
`dec` symlink (or copy) of the same binary decodes/decrypts by default.

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
  help        Help about any command
  hex         Encode input using HEX
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
- `--iv string` initialization vector filename; if omitted a random IV is
  generated (`ctr` mode) or prepended automatically (`gcm` mode)
- `--omit-iv` omit the initialization vector from encrypted output
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

# AES Encryption.
$ openssl rand 32 > aes.key
$ echo 'Hello, AES! 🔐' | enc aes --key=aes.key | dec aes --key=aes.key
# Hello, AES! 🔐

# DES/3DES Encryption.
$ openssl rand 24 > des3.key
$ echo 'Hello, 3DES! 🔐' | enc des3 --key=des3.key | dec des3 --key=des3.key
# Hello, 3DES! 🔐
```

## License

MIT, see [LICENSE](LICENSE).
