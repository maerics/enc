# enc

Transcode various formats between stdin and stdout.

## Usage

```
Transcode various formats between stdin and stdout.

Usage:
  enc [command]

Available Commands:
  base32      Encode "base32" between stdin and stdout.
  base58      Encode "base58" between stdin and stdout.
  base64      Encode "base64" between stdin and stdout.
  help        Help about any command
  hex         Encode "hex" between stdin and stdout.

Flags:
  -D, --decode   decode input from target encoding to binary
  -h, --help     help for enc

Use "enc [command] --help" for more information about a command.
```

## Examples
```
$ echo OK | enc base58 --check=0x7b ; echo
MdG23SHmSJu
$ echo -n MdG23SHmSJu | enc -D base58
Version Byte: 123 (0x7b)
OK
```
