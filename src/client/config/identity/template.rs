use alloc::rc;
use core::mem;
use core::ops;

/// Validated identity shared by connections from one mTLS endpoint.
#[derive(Clone)]
pub struct IdentityTemplate {
    source: rc::Rc<super::Identity>,
}

const _: () = assert!(mem::size_of::<IdentityTemplate>() == mem::size_of::<usize>());

impl IdentityTemplate {
    pub(super) fn new(source: super::Identity) -> Self {
        Self {
            source: rc::Rc::new(source),
        }
    }

    pub(crate) fn cert_type(&self) -> u8 {
        self.source.cert_type()
    }
}

impl ops::Deref for IdentityTemplate {
    type Target = super::Identity;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}
