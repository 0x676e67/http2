//! Entry points used by the `h2-fuzz` target.
//!
//! This module is only compiled under `--cfg fuzzing`.

#[cfg(fuzzing)]
pub mod fuzz_logic {
    //! Fuzzing harnesses for the HPACK codec.

    use crate::hpack;
    use bytes::BytesMut;
    use http::header::HeaderName;
    use std::io::Cursor;
    use std::ops::ControlFlow;

    /// Feeds arbitrary bytes through the HPACK decoder and encoder.
    pub fn fuzz_hpack(data_: &[u8]) {
        let mut decoder_ = hpack::Decoder::new(0);
        let mut buf = BytesMut::new();
        buf.extend(data_);
        let _dec_res = decoder_.decode(&mut Cursor::new(&mut buf), |_h| ControlFlow::Continue(()));

        fuzz_hpack_block(data_);

        if let Ok(s) = std::str::from_utf8(data_) {
            if let Ok(h) = http::Method::from_bytes(s.as_bytes()) {
                let m_ = hpack::Header::Method(h);
                let mut encoder = hpack::Encoder::new(0, 0);
                let _res = encode(&mut encoder, vec![m_]);
            }
        }
    }

    /// Drives the decoder the way `FramedRead` does in production: an explicit
    /// header block delimited by `begin_header_block` / `end_header_block`,
    /// preceded by a peer-acknowledged SETTINGS_HEADER_TABLE_SIZE that can arm
    /// the "must signal the lowest table size" requirement.
    ///
    /// The plain `decode` entry point above only reaches the implicit block
    /// mode, so it never exercises this state machine.
    fn fuzz_hpack_block(data_: &[u8]) {
        const SIZES: [usize; 5] = [0, 1, 64, 4096, 65536];

        if data_.is_empty() {
            return;
        }
        let seed_ = data_[0];
        let payload_ = &data_[1..];

        let mut decoder_ = hpack::Decoder::new(SIZES[usize::from(seed_) % SIZES.len()]);

        if seed_ & 1 != 0 {
            decoder_.queue_size_update(SIZES[usize::from(seed_ >> 4) % SIZES.len()]);
        }

        let mut buf = BytesMut::new();
        buf.extend(payload_);

        if decoder_.begin_header_block().is_err() {
            return;
        }

        let res_ =
            decoder_.decode_with_meta(&mut Cursor::new(&mut buf), |_h| ControlFlow::Continue(()));

        if res_.is_ok() {
            let _end_res = decoder_.end_header_block();
        }
    }

    fn encode(e: &mut hpack::Encoder, hdrs: Vec<hpack::Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(&mut hdrs.into_iter(), &mut dst);
        dst
    }
}
