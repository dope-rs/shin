use crate::connection;
use core::fmt;

/// Failed admission together with every owned input needed to retry it.
pub struct Rejection<T> {
    error: connection::Error,
    rejected: T,
}

impl<T> Rejection<T> {
    pub(super) fn new(error: connection::Error, rejected: T) -> Self {
        Self { error, rejected }
    }

    pub fn error(&self) -> &connection::Error {
        &self.error
    }

    pub fn into_parts(self) -> (connection::Error, T) {
        (self.error, self.rejected)
    }
}

impl<T> fmt::Debug for Rejection<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rejection")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
