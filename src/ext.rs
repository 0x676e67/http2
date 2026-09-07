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

/// Overrides the deprecated priority fields in one request's `HEADERS` frame.
///
/// Add this value to a [`Request`](http::Request) through its extensions before
/// passing the request to
/// [`SendRequest::send_request`](crate::client::SendRequest::send_request).
/// Requests without this extension use the connection default set by
/// [`Builder::headers_stream_dependency`](crate::client::Builder::headers_stream_dependency).
///
/// [RFC 9113 §5.3.2] retains these deprecated fields for interoperability. The
/// HTTP `priority` header and `PRIORITY_UPDATE` frames are defined separately
/// by [RFC 9218].
///
/// # Examples
///
/// ```
/// use http2::{ext::HeadersPriority, frame::StreamId};
///
/// let request = http::Request::builder()
///     .extension(HeadersPriority::new(StreamId::zero(), 146, true))
///     .body(())?;
/// # let _ = request;
/// # Ok::<(), http::Error>(())
/// ```
///
/// [RFC 9113 §5.3.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3.2
/// [RFC 9218]: https://www.rfc-editor.org/rfc/rfc9218.html
#[cfg(feature = "unstable")]
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct HeadersPriority(StreamDependency);

#[cfg(feature = "unstable")]
impl HeadersPriority {
    /// Creates a priority override for one outgoing `HEADERS` frame.
    ///
    /// Stream 0 selects the connection root. Self-dependencies are omitted once
    /// the request stream ID is assigned. `weight` is the wire value `0..=255`
    /// (`1..=256` effective), and `is_exclusive` sets the exclusive flag.
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        Self(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    /// Converts this request override into its frame dependency.
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
