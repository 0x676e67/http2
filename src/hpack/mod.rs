mod decoder;
mod encoder;
pub(crate) mod header;
pub(crate) mod huffman;
mod table;

#[cfg(test)]
mod test;

pub(crate) use self::decoder::DecodedHeader;
pub use self::decoder::{Decoder, DecoderError, NeedMore};
pub use self::encoder::Encoder;
pub use self::header::{BytesStr, Header};
