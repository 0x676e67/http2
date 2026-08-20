# http2

A Tokio aware, HTTP/2 client & server implementation for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/http2.svg)](https://crates.io/crates/http2)
[![Documentation](https://docs.rs/http2/badge.svg)][dox]

More information about this crate can be found in the [crate documentation][dox].

[dox]: https://docs.rs/http2

## Features

- Client and server HTTP/2 implementation.
- Implements the full HTTP/2 specification.
- Passes [h2spec](https://github.com/summerwind/h2spec).
- Focus on performance and correctness.
- Pseudo-header permutation for headers frame
- Experimental and permuted settings frame
- Priority frame (client-side only)
- Built on [Tokio](https://tokio.rs).

## Usage

To use `http2`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http2 = "0.5"
```

Next, add this to your crate:

```rust
use http2::server::Connection;

fn main() {
    // ...
}
```

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](./LICENSE) or http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.

## Accolades

The project is based on a fork of [h2](https://github.com/hyperium/h2).
