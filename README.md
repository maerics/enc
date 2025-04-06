# enc

Transcode various formats between stdin and stdout.

## Usage

```
Transcode various formats between streams or files.

Usage:
  enc [command]

Available Commands:
  ascii85     Encode input as "ascii85"
  base32      Encode input as "base32"
  base58      Encode input as "base58"
  base64      Encode input as "base64"
  help        Help about any command
  hex         Encode input as "hex"
  rot13       Encode input as "rot13"
  rsa         Encrypt data using RSA public key
  xor         Encode input as "xor"

Flags:
  -n, --append-newline       append a trailing newline to the output
  -D, --decode               decode or decrypt input on stdin
  -h, --help                 help for enc
  -w, --ignore-whitespace    ignore whitespace characters when decoding
  -i, --input-file string    the input filename, omit or use "-" for stdin
  -o, --output-file string   the output filename, omit or use "-" for stdout

Use "enc [command] --help" for more information about a command.
```

## Examples
```sh
# Common encodings.
$ echo OK | enc hex ; echo
4f4b0a
$ echo 4f4b0a | enc -D hex -w
OK
$ echo QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD | enc caesar -r3
THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
$ echo 'Attack!' | enc xor --key=secret | enc base64 ; echo
MhEXEwYfUm8=
$ echo MhEXEwYfUm8= | enc -D base64 | enc -D xor --key=secret
Attack!

# RSA encryption.
$ enc rsa generate --private-key=priv.key --public-key=pub.key
$ echo "Hello, RSA!" | enc rsa --key=pub.key | dec rsa --key=priv.key
```
