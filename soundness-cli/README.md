# Soundness CLI

A command-line interface tool for interacting with Soundness Layer testnet.

## Installation

```bash
cargo install --path .
```

## Usage

### Generating a Key Pair to join testnet

To generate a new key pair for signing requests:

```bash
soundness-cli generate-key --name my-key
```

This will:

1. Generate a new Ed25519 key pair (save your mnemonic in a secure way and keep it for later)
2. Store the key pair securely in a local `key_store.json` file
3. Display the public key in base64 format

The public key will be displayed in the format:

```log
✅ Generated new key pair 'my-key'
🔑 Public key: <base64-encoded-public-key>
```

### Listing Key Pairs

To view all stored key pairs:

```bash
soundness-cli list-keys
```

This will display all available key pairs and their associated public keys.

### Sending Proofs

To send a proof and ELF file to the testnet server:

```bash
soundness-cli send --proof-file path/to/proof.proof --elf-file path/to/program.elf --key-name my-key
```

The request will be signed using the specified key pair.
