use core::marker::PhantomData;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ThreadBound(PhantomData<*mut ()>);

impl ThreadBound {
    pub(crate) const NEW: Self = Self(PhantomData);
}
