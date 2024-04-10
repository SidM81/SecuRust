# SecuRust

## About

SecuRust is a command-line tool built in Rust that allows you to encrypt and securely store your passwords. It employs RSA encryption to ensure the confidentiality of your sensitive information.

## Features

- Encrypt passwords before storing them.
- Securely save passwords in a local file.
- Retrieve passwords when needed.
- Remove passwords from storage when no longer required.

## Installation

To use SecuRust, you need to have Rust installed on your system. If you haven't already installed Rust, you can do so by following the instructions on the [official Rust website](https://www.rust-lang.org/learn/get-started).

Once Rust is installed, you can clone this repository and build the project locally.

```bash
git clone https://github.com/SidM81/SecuRust.git
cd SecuRust
cargo build --release
```
## Usage

SecuRust provides a set of commands to manage your passwords:

### Add

Add a new password entry.

```bash
secu_rust add [ACCOUNT_NAME]
```

### Get

Retrieve the password for a specific account.

```bash
secu_rust get [ACCOUNT_NAME]
```

### Remove

Remove the password entry for a specific account.

```bash
secu_rust remove [ACCOUNT_NAME]
```

### All

List all saved account names.

```bash
secu_rust all
```
