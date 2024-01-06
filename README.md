# Rust Passthrough DNS

This is a simple DNS server that forwards all requests to a specified DNS server. It is intended to be used as a DNS-over-TLS proxy.

## Stack
It's built using Rust and Tokio with Clap for command line argument parsing.

## Usage

To build the project, run `cargo build --release`. The binary will be in `target/release/rust-dns`.
To run the project, run `./rust-dns --resolver <ip-address>:<port>`. Substitute the IP address and port of the DNS server you want to forward requests to.
