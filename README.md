# enc

Encrypt and transcode using various formats between streams or files.

## Usage

```
Encrypt and transcode using various formats between streams or files.

Usage:
  enc [flags]
  enc [command]

Available Commands:
  aes         Encrypt data using AES
  ascii85     Encode input using "ascii85"
  base32      Encode input using "base32"
  base58      Encode input using "base58"
  base64      Encode input using "base64"
  help        Help about any command
  hex         Encode input using "hex"
  rot13       Encode input using "rot13"
  rsa         Encrypt data using RSA public key
  version     Print the current version
  xor         Encode input using "xor"

Flags:
  -D, --decode               decode or decrypt input
  -h, --help                 help for enc
  -i, --input-file string    the input filename, omit or use "-" for stdin
  -o, --output-file string   the output filename, omit or use "-" for stdout
  -v, --version              print the current version

Use "enc [command] --help" for more information about a command.
```

## Examples
```sh
# Common encodings.
$ echo OK | enc hex ; echo
# 4f4b0a
$ echo 4f4b0a | enc -D hex -w
# OK
$ echo QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD | enc caesar -r3
# THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
$ echo 'Attack!' | enc xor --key=secret | enc base64 ; echo
# MhEXEwYfUm8=
$ echo MhEXEwYfUm8= | enc -D base64 | enc -D xor --key=secret
# Attack!

# RSA encryption.
$ enc rsa generate --private-key=priv.key --public-key=pub.key
$ echo 'Hello, RSA! 🔐' | enc rsa --key=pub.key | dec rsa --key=priv.key
# Hello, RSA! 🔐 

# AES Encryption.
$ openssl rand 32 > aes.key
$ echo 'Hello, AES! 🔐' | enc aes --key=aes.key | dec aes --key=aes.key
# Hello, AES! 🔐
```
