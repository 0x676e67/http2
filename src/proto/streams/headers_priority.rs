use std::collections::BTreeSet;

use super::stream::Stream;
use crate::codec::UserError;
use crate::ext::{HeadersDependency, HeadersPriority};
use crate::frame::{StreamDependency, StreamId};

/// Least urgent level accepted by [`HeadersDependency::Chain`].
const MAX_URGENCY: u8 = 7;

/// Connection-level inputs for request `HEADERS` priority fields.
#[derive(Debug)]
pub(super) struct HeadersPriorityConfig {
    /// Used by requests that carry no priority of their own.
    default: Option<HeadersPriority>,
    /// Idle streams declared by the initial PRIORITY frames.
    declared: Vec<StreamId>,
}

// ===== impl HeadersPriorityConfig =====

impl HeadersPriorityConfig {
    /// Creates a connection's request priority configuration.
    ///
    /// `default` is used when a request has no override. `declared` lists the
    /// stream IDs declared by the initial PRIORITY frames.
    /// The client handshake validates `default` before construction.
    pub(super) fn new(default: Option<HeadersPriority>, declared: Vec<StreamId>) -> Self {
        Self { default, declared }
    }

    /// Picks the request override or the connection default for `stream_id`.
    ///
    /// Runs before the stream ID is consumed, so a rejected request leaves the
    /// stream ID space untouched. The default was validated at handshake. An
    /// override is only rejected for an undeclared parent or a self-dependency
    /// ([RFC 7540 §5.3.1]); depending on a declared idle stream that a later
    /// request opens is allowed, unlike for the default.
    ///
    /// [RFC 7540 §5.3.1]: https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.1
    pub(super) fn select(
        &self,
        request: Option<HeadersPriority>,
        stream_id: StreamId,
    ) -> Result<Option<HeadersPriority>, UserError> {
        if let Some(HeadersPriority {
            dependency: HeadersDependency::Declared(id),
            ..
        }) = request
        {
            let id = StreamId::from(id);
            if id == stream_id || !self.declared.contains(&id) {
                return Err(UserError::InvalidHeadersDependency);
            }
        }
        Ok(request.or(self.default))
    }
}

/// Chain membership of one request stream.
#[derive(Debug, Default)]
pub(super) enum ChainState {
    #[default]
    None,
    /// Parent is chosen when the initial `HEADERS` is written. `urgency` is
    /// at most [`MAX_URGENCY`].
    Pending {
        urgency: u8,
        weight: u8,
        is_exclusive: bool,
    },
    /// A parent candidate at this urgency until the stream closes.
    Candidate { urgency: u8 },
}

// ===== impl ChainState =====

impl ChainState {
    /// Returns the dependency known before writing, or defers a `Chain` parent.
    pub(super) fn split(priority: HeadersPriority) -> (Option<StreamDependency>, Self) {
        let dependency_id = match priority.dependency {
            HeadersDependency::Root => StreamId::zero(),
            HeadersDependency::Declared(id) => id.into(),
            HeadersDependency::Chain { urgency } => {
                let chain = Self::Pending {
                    urgency: urgency.min(MAX_URGENCY),
                    weight: priority.weight,
                    is_exclusive: priority.is_exclusive,
                };
                return (None, chain);
            }
        };
        let dependency =
            StreamDependency::new(dependency_id, priority.weight, priority.is_exclusive);
        (Some(dependency), Self::None)
    }
}

/// Open `Chain` requests per urgency level.
///
/// Initial `HEADERS` frames leave `pending_open` in stream ID order, so the
/// largest ID at a level is its newest request.
#[derive(Debug, Default)]
pub(super) struct ChainParents {
    by_urgency: [BTreeSet<StreamId>; MAX_URGENCY as usize + 1],
}

// ===== impl ChainParents =====

impl ChainParents {
    /// Chooses the parent of a pending `Chain` stream whose initial `HEADERS`
    /// is being written, and registers the stream as a candidate.
    pub(super) fn attach(&mut self, stream: &mut Stream) -> Option<StreamDependency> {
        let ChainState::Pending {
            urgency,
            weight,
            is_exclusive,
        } = stream.priority_chain
        else {
            return None;
        };

        let index = usize::from(urgency);
        let parent = self.by_urgency[..=index]
            .iter()
            .rev()
            .find_map(|level| level.last().copied())
            .unwrap_or_else(StreamId::zero);
        self.by_urgency[index].insert(stream.id);
        stream.priority_chain = ChainState::Candidate { urgency };
        Some(StreamDependency::new(parent, weight, is_exclusive))
    }

    /// Stops offering a closed stream as a parent.
    pub(super) fn detach(&mut self, stream: &mut Stream) {
        if let ChainState::Candidate { urgency } = stream.priority_chain {
            self.by_urgency[usize::from(urgency)].remove(&stream.id);
            stream.priority_chain = ChainState::None;
        }
    }
}
