# Signup examples

You can use these examples to test signup to a provided homeserver using a keypair.


## Usage

This example defaults to `../../sample_recovery.key`, which has an empty passphrase.
Use `--recovery-file <PATH>` when you want to use your own recovery file.

### Signup

```bash
# use the local testnet homeserver and sample recovery file
cargo run --bin signup -- --testnet

# with a custom recovery file
cargo run --bin signup -- --testnet --recovery-file </path/to/recovery file>

# Signup to a mainnet homeserver
cargo run --bin signup <homeserver pubky>

# With a custom recovery file and signup code
cargo run --bin signup <homeserver pubky> --recovery-file </path/to/recovery file> --signup-code <code>
```
