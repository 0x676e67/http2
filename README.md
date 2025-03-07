# http2

A Tokio aware, HTTP/2 client & server implementation for Rust.

[![CI](https://github.com/0x676e67/http2/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http2/actions/workflows/CI.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/http2.svg)](https://crates.io/crates/http2)
[![Documentation](https://docs.rs/http2/badge.svg)][dox]

More information about this crate can be found in the [crate documentation][dox].

[dox]: https://docs.rs/http2

## Features

* Client and server HTTP/2 implementation.
* Implements the full HTTP/2 specification.
* Passes [h2spec](https://github.com/summerwind/h2spec).
* Focus on performance and correctness.
* Built on [Tokio](https://tokio.rs).

## Non-goals

This package focuses solely on implementing the HTTP/2 specification. It supports client-side processing based on the original [h2](https://github.com/hyperium/h2) branch, including:

* Optional [tracing](https://github.com/hyperium/h2/issues/713)
* Headers frame priority and pseudo-header permutation
* Priority frame (client-side only)

For additional features, consider using [hyper2](https://github.com/0x676e67/hyper2), which builds on this package.

## Accolades

The project is based on a fork of [h2](https://github.com/hyperium/h2).
