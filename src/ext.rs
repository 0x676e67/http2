//! Extensions specific to the HTTP/2 protocol.

#[cfg(feature = "unstable")]
use crate::frame::{StreamDependency, StreamId};
use crate::hpack::BytesStr;

use bytes::Bytes;
use std::fmt;

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

/// Overrides the deprecated priority fields in one request's HEADERS frame.
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
/// use http2::{ext::HeadersPriority, frame::StreamId};
///
/// let _request = http::Request::builder()
///     .extension(HeadersPriority::new(StreamId::zero(), 146, true))
///     .body(())?;
/// # Ok::<(), http::Error>(())
/// ```
///
/// [RFC 9113 section 5.3.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3.2
#[cfg(feature = "unstable")]
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct HeadersPriority(StreamDependency);

#[cfg(feature = "unstable")]
impl HeadersPriority {
    /// Creates a priority override for one outgoing HEADERS frame.
    ///
    /// `dependency_id` can be stream 0, the connection root, or another HTTP/2
    /// stream. If it matches the stream ID later assigned to this request, the
    /// invalid self-dependency is omitted from the HEADERS frame.
    ///
    /// `weight` is the encoded value in the range 0 through 255. Its effective
    /// HTTP/2 weight is one greater, in the range 1 through 256.
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        Self(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    /// Consumes this request override and returns its wrapped [`StreamDependency`].
    pub(crate) fn into_inner(self) -> StreamDependency {
        self.0
    }
}

#[cfg(feature = "unstable")]
impl fmt::Debug for HeadersPriority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
