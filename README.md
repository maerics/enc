# enc

Transcode various formats between stdin and stdout.

## Usage

```
Transcode various formats between stdin and stdout.

Usage:
  enc [command]

Available Commands:
  ascii85     Encode "ascii85" between stdin and stdout.
  base32      Encode "base32" between stdin and stdout.
  base58      Encode "base58" between stdin and stdout.
  base64      Encode "base64" between stdin and stdout.
  help        Help about any command
  hex         Encode "hex" between stdin and stdout.
  rot13       Encode "rot13" between stdin and stdout.
  xor         Encode "xor" between stdin and stdout.

Flags:
  -D, --decode              decode input from target encoding to binary
  -h, --help                help for enc
  -w, --ignore-whitespace   ignore whitespace characters when decoding

Use "enc [command] --help" for more information about a command.
```

## Examples
```sh
$ echo OK | enc hex ; echo
4f4b0a
$ echo 4f4b0a | enc -D hex -w
OK
$ echo OK | enc base58 --check=0x7b ; echo
MdG23SHmSJu
$ echo -n MdG23SHmSJu | enc -D base58
Version Byte: 123 (0x7b)
OK
$ echo 'Attack!' | enc xor --key=secret | enc base64 ; echo
MhEXEwYfUm8=
$ echo MhEXEwYfUm8= | enc -D base64 | enc -D xor --key=secret
Attack!
```
