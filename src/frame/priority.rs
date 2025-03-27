use crate::frame::*;
use crate::tracing;
use bytes::BufMut;

/// The PRIORITY frame (type=0x2) specifies the sender-advised priority
/// of a stream [Section 5.3].  It can be sent in any stream state,
/// including idle or closed streams.
/// [Section 5.3]: https://tools.ietf.org/html/rfc7540#section-5.3
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Priority {
    /// The stream ID of the stream that this priority frame is for
    stream_id: StreamId,

    /// The stream dependency target
    dependency: StreamDependency,
}

/// Represents a stream dependency in HTTP/2 priority frames.
///
/// A stream dependency consists of three components:
/// * A stream identifier that the stream depends on
/// * A weight value between 0 and 255 (representing 1-256 in the protocol)
/// * An exclusive flag indicating whether this is an exclusive dependency
///
/// # Stream Dependencies
///
/// In HTTP/2, stream dependencies form a dependency tree where each stream
/// can depend on another stream. This creates a priority hierarchy that helps
/// determine the relative order in which streams should be processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamDependency {
    /// The ID of the stream dependency target
    dependency_id: StreamId,

    /// The weight for the stream. The value exposed (and set) here is always in
    /// the range [0, 255], instead of [1, 256] (as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    weight: u8,

    /// True if the stream dependency is exclusive.
    is_exclusive: bool,
}

// ===== impl Priority =====

impl Priority {
    /// Create a new priority frame.
    ///
    /// # Parameters
    /// - `stream_id`: The ID of the stream. This can be any valid stream ID, including 0.
    /// - `dependency`: The stream dependency information.
    ///
    /// # Returns
    /// A new `Priority` frame.
    pub fn new(stream_id: StreamId, dependency: StreamDependency) -> Self {
        Priority {
            stream_id,
            dependency,
        }
    }

    /// Loads the priority frame but doesn't actually do HPACK decoding.
    pub fn load(head: Head, payload: &[u8]) -> Result<Self, Error> {
        tracing::trace!("loading priority frame; stream_id={:?}", head.stream_id());

        let dependency = StreamDependency::load(payload)?;

        if dependency.dependency_id() == head.stream_id() {
            return Err(Error::InvalidDependencyId);
        }

        Ok(Priority {
            stream_id: head.stream_id(),
            dependency,
        })
    }

    pub fn head(&self) -> Head {
        Head::new(Kind::Priority, 0, self.stream_id)
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let head = self.head();
        head.encode(5, dst);

        // Priority frame payload is exactly 5 bytes
        // Format:
        // +---------------+
        // |E|  Dep ID (31)|
        // +---------------+
        // |   Weight (8)  |
        // +---------------+
        self.dependency.encode(dst);
    }
}

impl<B> From<Priority> for Frame<B> {
    fn from(src: Priority) -> Self {
        Frame::Priority(src)
    }
}

// ===== impl StreamDependency =====

impl StreamDependency {
    /// Create a new stream dependency
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        StreamDependency {
            dependency_id,
            weight,
            is_exclusive,
        }
    }

    /// Loads the stream dependency from a buffer
    pub fn load(src: &[u8]) -> Result<Self, Error> {
        tracing::trace!("loading priority stream dependency; src={:?}", src);

        if src.len() != 5 {
            return Err(Error::InvalidPayloadLength);
        }

        // Parse the stream ID and exclusive flag
        let (dependency_id, is_exclusive) = StreamId::parse(&src[..4]);

        // Read the weight
        let weight = src[4];

        Ok(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    pub fn dependency_id(&self) -> StreamId {
        self.dependency_id
    }

    pub fn weight(&self) -> u8 {
        self.weight
    }

    pub fn is_exclusive(&self) -> bool {
        self.is_exclusive
    }

    pub fn encode<T: BufMut>(&self, dst: &mut T) {
        const STREAM_ID_MASK: u32 = 1 << 31;
        let mut dependency_id = self.dependency_id().into();
        if self.is_exclusive {
            dependency_id |= STREAM_ID_MASK;
        }
        dst.put_u32(dependency_id);
        dst.put_u8(self.weight);
    }
}

mod tests {

    #[test]
    fn test_priority_frame() {
        use crate::frame::{self, Priority, StreamDependency, StreamId};

        let mut dependency_buf = Vec::new();
        let dependency = StreamDependency::new(StreamId::zero(), 201, false);
        dependency.encode(&mut dependency_buf);
        let dependency = StreamDependency::load(&dependency_buf).unwrap();
        assert_eq!(dependency.dependency_id(), StreamId::zero());
        assert_eq!(dependency.weight(), 201);
        assert!(!dependency.is_exclusive());

        let priority = Priority::new(StreamId::from(3), dependency);
        let mut priority_buf = Vec::new();
        priority.encode(&mut priority_buf);
        let priority = Priority::load(priority.head(), &priority_buf[frame::HEADER_LEN..]).unwrap();
        assert_eq!(priority.stream_id(), StreamId::from(3));
        assert_eq!(priority.dependency.dependency_id(), StreamId::zero());
        assert_eq!(priority.dependency.weight(), 201);
        assert!(!priority.dependency.is_exclusive());
    }
}
