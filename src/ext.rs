//! Extensions specific to the HTTP/2 protocol.

use crate::StreamId;
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

// ===== impl Protocol =====

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

/// Selects the parent stream for a request's deprecated `HEADERS` priority fields.
///
/// A connection default is validated at handshake, and a request override when
/// the request is assigned a stream ID, so a request never names its own
/// stream, which [RFC 7540 §5.3.1] forbids. A `Chain` parent is selected when
/// the initial `HEADERS` is written.
///
/// [RFC 7540 §5.3.1]: https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.1
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeadersDependency {
    /// Depends on stream 0, the root of the dependency tree.
    Root,
    /// Depends on an idle stream declared through
    /// [`Builder::priorities`](crate::client::Builder::priorities).
    ///
    /// Sending fails if the stream is not declared or is the request's own stream.
    /// A connection default naming a client stream must stay below
    /// [`Builder::initial_stream_id`](crate::client::Builder::initial_stream_id).
    /// Opening a higher client stream closes lower idle client streams
    /// ([RFC 9113 §5.1.1]), so the parent relies on the server retaining its
    /// priority state ([RFC 7540 §5.3.4]).
    ///
    /// [RFC 9113 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1.1
    /// [RFC 7540 §5.3.4]: https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.4
    Declared(StreamId),
    /// Depends on the newest open `Chain` request at the nearest urgency that is
    /// the same or more urgent, or on stream 0 if there is none. The parent is
    /// chosen when the request's `HEADERS` is written, so a request queued by
    /// the concurrency limit skips streams that closed while it waited.
    ///
    /// Urgency 0 is the most urgent, and values above 7 are treated as 7.
    Chain {
        /// Request urgency in `0..=7`.
        urgency: u8,
    },
}

/// The deprecated priority fields of one request's `HEADERS` frame.
///
/// Set a connection default with
/// [`Builder::headers_priority`](crate::client::Builder::headers_priority).
/// A value in a [`Request`](http::Request)'s extensions replaces that default
/// for the request.
///
/// [RFC 9113 §5.3.2] retains these fields for interoperability. The HTTP
/// `priority` header and `PRIORITY_UPDATE` frames are defined separately by
/// [RFC 9218].
///
/// # Examples
///
/// ```
/// use http2::ext::{HeadersDependency, HeadersPriority};
///
/// let priority = HeadersPriority::new(HeadersDependency::Chain { urgency: 1 }, 219, true);
/// let request = http::Request::builder().extension(priority).body(())?;
/// # let _ = request;
/// # Ok::<(), http::Error>(())
/// ```
///
/// [RFC 9113 §5.3.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3.2
/// [RFC 9218]: https://www.rfc-editor.org/rfc/rfc9218.html
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct HeadersPriority {
    pub(crate) dependency: HeadersDependency,
    pub(crate) weight: u8,
    pub(crate) is_exclusive: bool,
}

// ===== impl HeadersPriority =====

impl HeadersPriority {
    /// Creates `HEADERS` priority fields.
    ///
    /// `weight` is the wire value `0..=255`, one less than the effective weight.
    pub const fn new(dependency: HeadersDependency, weight: u8, is_exclusive: bool) -> Self {
        Self {
            dependency,
            weight,
            is_exclusive,
        }
    }

    /// Returns the parent stream selection.
    pub const fn dependency(&self) -> HeadersDependency {
        self.dependency
    }

    /// Returns the wire weight in `0..=255`.
    pub const fn weight(&self) -> u8 {
        self.weight
    }

    /// Returns whether the dependency is exclusive.
    pub const fn is_exclusive(&self) -> bool {
        self.is_exclusive
    }
}
