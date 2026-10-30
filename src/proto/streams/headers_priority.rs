use std::collections::BTreeSet;

use super::stream::Stream;
use crate::codec::UserError;
use crate::ext::{HeadersDependency, HeadersPriority};
use crate::frame::{Priorities, StreamDependency, StreamId};

/// Least urgent level accepted by [`HeadersDependency::Chain`].
const MAX_URGENCY: u8 = 7;

/// Connection-level rules for request `HEADERS` priority fields.
///
/// Holds the connection default and the stream IDs declared by the initial
/// PRIORITY frames. A client handshake builds it once; server connections use
/// the empty default.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeadersPriorityPolicy {
    /// Used by requests that carry no priority of their own.
    default: Option<HeadersPriority>,
    /// Idle streams declared by the initial PRIORITY frames.
    declared: Vec<StreamId>,
}

// ===== impl HeadersPriorityPolicy =====

impl HeadersPriorityPolicy {
    /// Validates the connection default and records the declared stream IDs.
    ///
    /// A default `Declared` parent must be declared. Since the default applies
    /// to every request, it must also not be a client stream at or above
    /// `initial_stream_id`, which a later request opens ([RFC 7540 §5.3.1]).
    ///
    /// [RFC 7540 §5.3.1]: https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.1
    pub(crate) fn new(
        default: Option<HeadersPriority>,
        priorities: Option<&Priorities>,
        initial_stream_id: StreamId,
    ) -> Result<Self, UserError> {
        let declared: Vec<StreamId> = priorities
            .into_iter()
            .flat_map(Priorities::stream_ids)
            .collect();
        if let Some(id) = default.and_then(declared_parent)
            && (!declared.contains(&id) || (id.is_client_initiated() && id >= initial_stream_id))
        {
            return Err(UserError::InvalidHeadersDependency);
        }
        Ok(Self { default, declared })
    }

    /// Returns the request override, else the connection default.
    ///
    /// Runs before the stream ID is consumed, so a rejected request leaves the
    /// stream ID space untouched. An override is only rejected for an
    /// undeclared parent or a self-dependency ([RFC 7540 §5.3.1]).
    ///
    /// [RFC 7540 §5.3.1]: https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.1
    pub(super) fn resolve(
        &self,
        request: Option<HeadersPriority>,
        stream_id: StreamId,
    ) -> Result<Option<HeadersPriority>, UserError> {
        if let Some(id) = request.and_then(declared_parent)
            && (id == stream_id || !self.declared.contains(&id))
        {
            return Err(UserError::InvalidHeadersDependency);
        }
        Ok(request.or(self.default))
    }
}

/// Returns the dependency of a `Root` or `Declared` priority, known before the
/// stream opens. A `Chain` parent waits for [`ChainParents::attach`].
pub(super) fn fixed_dependency(priority: HeadersPriority) -> Option<StreamDependency> {
    let parent = match priority.dependency {
        HeadersDependency::Root => StreamId::ZERO,
        HeadersDependency::Declared(id) => id.into(),
        HeadersDependency::Chain { .. } => return None,
    };
    Some(StreamDependency::new(
        parent,
        priority.weight,
        priority.is_exclusive,
    ))
}

/// Returns the parent of a `Declared` priority.
fn declared_parent(priority: HeadersPriority) -> Option<StreamId> {
    match priority.dependency {
        HeadersDependency::Declared(id) => Some(id.into()),
        HeadersDependency::Root | HeadersDependency::Chain { .. } => None,
    }
}

/// A request's place among `Chain` requests.
#[derive(Clone, Copy, Debug)]
pub(super) enum ChainLink {
    /// Parent not chosen yet. `urgency` is at most [`MAX_URGENCY`].
    Pending {
        urgency: u8,
        weight: u8,
        is_exclusive: bool,
    },
    /// Offered as a parent at `urgency` until the stream closes.
    Attached { urgency: u8 },
}

// ===== impl ChainLink =====

impl ChainLink {
    /// Returns the pending link of a `Chain` priority.
    pub(super) fn pending(priority: HeadersPriority) -> Option<Self> {
        match priority.dependency {
            HeadersDependency::Chain { urgency } => Some(Self::Pending {
                urgency: urgency.min(MAX_URGENCY),
                weight: priority.weight,
                is_exclusive: priority.is_exclusive,
            }),
            HeadersDependency::Root | HeadersDependency::Declared(_) => None,
        }
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
    /// Chooses the parent of a pending stream whose initial `HEADERS` is being
    /// written, and offers the stream as a parent in turn.
    pub(super) fn attach(&mut self, stream: &mut Stream) -> Option<StreamDependency> {
        let Some(ChainLink::Pending {
            urgency,
            weight,
            is_exclusive,
        }) = stream.chain_link
        else {
            return None;
        };

        let index = usize::from(urgency);
        let parent = self.by_urgency[..=index]
            .iter()
            .rev()
            .find_map(|ids| ids.last().copied())
            .unwrap_or(StreamId::ZERO);
        self.by_urgency[index].insert(stream.id);
        stream.chain_link = Some(ChainLink::Attached { urgency });
        Some(StreamDependency::new(parent, weight, is_exclusive))
    }

    /// Stops offering a stream as a parent once it is reset, or once it is
    /// closed and its final frame has been written.
    pub(super) fn detach(&mut self, stream: &mut Stream) {
        let Some(ChainLink::Attached { urgency }) = stream.chain_link else {
            return;
        };
        if stream.state.is_reset() || stream.is_closed() {
            self.by_urgency[usize::from(urgency)].remove(&stream.id);
            stream.chain_link = None;
        }
    }
}
