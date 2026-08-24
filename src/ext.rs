//! Extensions specific to the HTTP/2 protocol.

#[cfg(feature = "unstable")]
use crate::frame::{StreamDependency, StreamId};
use crate::hpack::BytesStr;

use bytes::Bytes;
use std::fmt;

/// Overrides the deprecated stream dependency fields in one request's
/// HEADERS frame.
///
/// Insert this value into [`http::Request::extensions_mut`] before calling
/// [`crate::client::SendRequest::send_request`]. If the extension is absent,
/// the request uses the default set by
/// [`crate::client::Builder::headers_stream_dependency`].
///
/// This controls the legacy fields described by [RFC 9113 section 5.3.2]. It
/// is unrelated to the HTTP `priority` header and PRIORITY_UPDATE frames.
///
/// # Examples
///
/// ```
/// use http2::{ext::HeadersStreamDependency, frame::StreamId};
///
/// let _request = http::Request::builder()
///     .extension(HeadersStreamDependency::depends_on(
///         StreamId::from(1),
///         146,
///         true,
///     ))
///     .body(())
///     .unwrap();
/// ```
///
/// [RFC 9113 section 5.3.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3.2
#[cfg(feature = "unstable")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadersStreamDependency(StreamDependency);

#[cfg(feature = "unstable")]
impl HeadersStreamDependency {
    /// Overrides the request to depend on the connection root, stream 0.
    ///
    /// `weight` is the encoded value in the range 0 through 255. Its effective
    /// HTTP/2 weight is one greater, in the range 1 through 256.
    pub fn root(weight: u8, is_exclusive: bool) -> Self {
        Self(StreamDependency::new(StreamId::ZERO, weight, is_exclusive))
    }

    /// Overrides the request to depend on an HTTP/2 stream.
    ///
    /// `weight` is the encoded value in the range 0 through 255. Its effective
    /// HTTP/2 weight is one greater, in the range 1 through 256.
    pub fn depends_on(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        Self(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    pub(crate) fn into_inner(self) -> StreamDependency {
        self.0
    }
}

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}
