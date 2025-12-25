# bindecrypter

Tool for deobfuscating binaries wrapped with **bincrypter** (<= v1.3).

## Features

- Detects bincrypter wrappers
- Extracts embedded decryption logic
- Reconstructs AES-256-CBC keys
- Decompresses embedded gzip payload

## Install

```bash
pip install bindecrypter
```

## Usage

```bash
bindecrypter sample
```

### Output file:

sample.bindecrypted

## Limitations

- BC_LOCK protected samples are not supported
- Newer bincrypter versions may require updates
