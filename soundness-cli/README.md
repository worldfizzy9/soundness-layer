# Soundness CLI

A command-line interface tool for interacting with Soundness Layer testnet.

## Testnet Registration

To join the testnet, head to our `testnet-access` channel in [Discord](https://discord.gg/F4cGbdqgw8) and request access using:

```bash
!access <base64-encoded-public-key>
```

## Installation

Install the CLI tool using Cargo:

```bash
cargo install --path .
```

## Usage

### Generating a Key Pair

To generate a new key pair for signing requests:

```bash
soundness-cli generate-key --name my-key
```

This command will:
1. Generate a new Ed25519 key pair (save your mnemonic securely for future use)
2. Store the key pair in a local `key_store.json` file
3. Display the public key in base64 format

The output will look like this:

```log
✅ Generated new key pair 'my-key'
🔑 Public key: <base64-encoded-public-key>
```

### Listing Key Pairs

To view all stored key pairs and their associated public keys:

```bash
soundness-cli list-keys
```

### Sending Proofs

To send a proof and ELF file to the testnet server:

```bash
soundness-cli send --proof-file path/to/proof.proof --elf-file path/to/program.elf --key-name my-key
```

The request will be automatically signed using the specified key pair.
