use crate::connection;
use crate::server;

/// Allocation-free outcome retaining successful or rejected ownership inline.
#[must_use = "binding outcomes own either the connection or the rejected inputs"]
#[repr(transparent)]
pub struct Binding<T, R>(Result<T, server::Rejection<R>>);

impl<T, R> Binding<T, R> {
    pub(super) fn bound(bound: T) -> Self {
        Self(Ok(bound))
    }

    pub(super) fn rejected(error: connection::Error, rejected: R) -> Self {
        Self(Err(server::Rejection::new(error, rejected)))
    }

    /// Exposes the standard result where the outcome is consumed.
    pub fn into_result(self) -> Result<T, server::Rejection<R>> {
        self.0
    }
}
