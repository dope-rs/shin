use core::marker;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ThreadBound(marker::PhantomData<*mut ()>);

impl ThreadBound {
    pub(crate) const NEW: Self = Self(marker::PhantomData);
}
