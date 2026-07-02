# Refactoring

Tracked improvements for `enc`/`dec`. Delete this file once everything below is
checked off, then merge to master and release.

## Bugs
- [x] Fix `decryptGCMAEAD` swallowing the `readAdditionalData` error (crypto.go)
- [x] Remove duplicated nil-check block in `rsaEncrypt` (rsa.go)

## Cleanup / coherence
- [ ] Fix `TestSymmetricCrypto` decrypt-error branch comparing `encryptErr` instead of
      `decryptErr` (crypto_test.go ~127-128) — copy-paste bug from the encrypt branch;
      `encryptErr` is guaranteed nil there so `.Error()` would panic if this branch is
      ever actually hit
- [ ] Remove commented-out dead flag registration (codec_streaming.go, codec_buffered.go)
- [ ] Reconcile `-D/--decrypt` vs `-d/--decode` duplication (main.go)
- [ ] Make `rsa generate`/`extract` reuse the shared private/public key flag constants (rsa.go)
- [ ] Resolve stale TODOs: crypto_modes.go shorthand-flag note, crypto.go GCM nonce comment

## Tests
- [ ] Add `xor/xor_test.go` (currently zero coverage; mirror rot13's pattern)
- [ ] Add unit tests for `cryptoMode`'s pflag.Value methods (crypto_modes.go)

## Efficiency
- [ ] Address O(n^2) whitespace-stripping note in `WhitespaceIgnoringReader` (helpers.go)

## Documentation
- [ ] Fix stale/incorrect xor+base64 example ciphertext in README
- [ ] Add des/des3 to README's command list and examples
- [ ] Document `-d/--decode` and per-subcommand flags (aes mode/iv/omit-iv/additional-data,
      base58 check, universal append-newline, rsa extract) in README
- [ ] Document that `caesar`/`rot` are aliases of `rot13`
- [ ] Add LICENSE (MIT), matching .goreleaser.yml's Homebrew formula

## Tooling
- [ ] Reconcile `enc version` vs `enc -v` into one path; follow JSON-default/--yaml convention
- [ ] Add `tidy` target to Makefile

## Deferred (explicitly out of scope for this branch)
- Implementing or removing the unadvertised-but-broken cbc/cfb/ecb/ofb crypto modes
  and the orphaned `padding/pkcs7` package
- CI (.github/workflows)
- Unifying codec/crypto/rsa patterns under one shared interface
