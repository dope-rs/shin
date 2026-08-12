use crate::wire::handshake::workspace;
use crate::wire::record;
use core::{error, fmt, mem};

/// Exact reservation plan for one client handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceLayout {
    fragmented_message: usize,
    outbound_flight: usize,
}

impl WorkspaceLayout {
    const fn new(fragmented_message: usize, outbound_flight: usize) -> Self {
        Self {
            fragmented_message,
            outbound_flight,
        }
    }

    pub(crate) fn prepared(maximum_certificate_message: usize, outbound_flight: usize) -> Self {
        Self::new(
            maximum_certificate_message.max(record::MAX_PLAINTEXT_BODY),
            outbound_flight.max(record::MAX_PLAINTEXT_BODY),
        )
    }

    /// Allocates every byte described by this plan before construction.
    pub fn allocate(self) -> Workspace {
        Workspace {
            reassembly: workspace::BoundedBuffer::with_capacity(self.fragmented_message),
            flight: workspace::BoundedBuffer::with_capacity(self.outbound_flight),
        }
    }

    pub const fn capacities(self) -> (usize, usize) {
        (self.fragmented_message, self.outbound_flight)
    }

    pub(in crate::client) fn admit(
        self,
        workspace: Workspace,
    ) -> Result<Workspace, WorkspaceRejection> {
        let actual = workspace.layout();
        if actual.fragmented_message < self.fragmented_message
            || actual.outbound_flight < self.outbound_flight
        {
            return Err(WorkspaceRejection {
                mismatch: WorkspaceMismatch {
                    required: self,
                    actual,
                },
                workspace,
            });
        }
        Ok(workspace)
    }
}

/// Capacity mismatch detected before a client can enter the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceMismatch {
    required: WorkspaceLayout,
    actual: WorkspaceLayout,
}

impl WorkspaceMismatch {
    pub const fn required(self) -> WorkspaceLayout {
        self.required
    }

    pub const fn actual(self) -> WorkspaceLayout {
        self.actual
    }
}

impl fmt::Display for WorkspaceMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (required_reassembly, required_flight) = self.required.capacities();
        let (actual_reassembly, actual_flight) = self.actual.capacities();
        write!(
            formatter,
            "client workspace capacities ({actual_reassembly}, {actual_flight}) are smaller than required ({required_reassembly}, {required_flight})"
        )
    }
}

impl error::Error for WorkspaceMismatch {}

/// Rejected workspace together with the allocation that remains reusable.
pub struct WorkspaceRejection {
    mismatch: WorkspaceMismatch,
    workspace: Workspace,
}

impl WorkspaceRejection {
    pub const fn mismatch(&self) -> WorkspaceMismatch {
        self.mismatch
    }

    pub fn into_parts(self) -> (WorkspaceMismatch, Workspace) {
        (self.mismatch, self.workspace)
    }
}

impl fmt::Debug for WorkspaceRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.mismatch.fmt(formatter)
    }
}

impl fmt::Display for WorkspaceRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.mismatch.fmt(formatter)
    }
}

impl error::Error for WorkspaceRejection {}

/// Opaque, fully reserved storage for one client handshake.
pub struct Workspace {
    pub(crate) reassembly: workspace::BoundedBuffer,
    pub(crate) flight: workspace::BoundedBuffer,
}

impl Workspace {
    pub(crate) fn from_buffers(
        mut reassembly: workspace::BoundedBuffer,
        mut flight: workspace::BoundedBuffer,
    ) -> Self {
        reassembly.clear();
        flight.clear();
        Self { reassembly, flight }
    }

    pub fn capacities(&self) -> (usize, usize) {
        (self.reassembly.capacity(), self.flight.capacity())
    }

    fn layout(&self) -> WorkspaceLayout {
        WorkspaceLayout::new(self.reassembly.capacity(), self.flight.capacity())
    }
}

const _: () =
    assert!(mem::size_of::<Workspace>() == 2 * mem::size_of::<workspace::BoundedBuffer>());
