use alloc::vec::Vec;
use core::convert::Infallible;
use core::mem::MaybeUninit;
use core::ptr::copy_nonoverlapping;
use core::slice::from_raw_parts_mut;

pub(crate) struct UninitWriter<'a> {
    buf: &'a mut [MaybeUninit<u8>],
    len: usize,
}

impl<'a> UninitWriter<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> Self {
        Self { buf, len: 0 }
    }

    pub(crate) fn from_mut_slice(buf: &'a mut [u8]) -> Self {
        // SAFETY: `MaybeUninit<u8>` has the layout of `u8`, and treating initialized
        // bytes as maybe-uninitialized only relaxes their validity invariant.
        let buf =
            unsafe { from_raw_parts_mut(buf.as_mut_ptr().cast::<MaybeUninit<u8>>(), buf.len()) };
        Self::new(buf)
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.buf[self.len].write(byte);
        self.len += 1;
    }

    pub(crate) fn extend_from_slice(&mut self, src: &[u8]) {
        let dst = &mut self.buf[self.len..][..src.len()];
        // SAFETY: both regions are valid for `src.len()` bytes; safe references
        // cannot overlap the exclusively borrowed destination.
        unsafe { copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr().cast::<u8>(), src.len()) };
        self.len += src.len();
    }

    pub(crate) fn initialized_mut(&mut self) -> &mut [u8] {
        Self::initialized(self.buf, self.len)
    }

    pub(crate) fn into_initialized(self) -> &'a mut [u8] {
        Self::initialized(self.buf, self.len)
    }

    fn initialized(buf: &mut [MaybeUninit<u8>], len: usize) -> &mut [u8] {
        // SAFETY: `len` advances only after `push` or `extend_from_slice` initializes
        // the corresponding prefix, and both writers bounds-check against `buf`.
        unsafe { from_raw_parts_mut(buf.as_mut_ptr().cast(), len) }
    }

    fn initialized_len(&self) -> usize {
        self.len
    }
}

pub(crate) trait VecUninitExt {
    fn extend_uninit(&mut self, len: usize, fill: impl FnOnce(&mut UninitWriter<'_>));
    fn try_extend_uninit<E>(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut UninitWriter<'_>) -> Result<(), E>,
    ) -> Result<(), E>;
}

impl VecUninitExt for Vec<u8> {
    fn extend_uninit(&mut self, len: usize, fill: impl FnOnce(&mut UninitWriter<'_>)) {
        match self.try_extend_uninit(len, |writer| {
            fill(writer);
            Ok::<_, Infallible>(())
        }) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    fn try_extend_uninit<E>(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut UninitWriter<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        self.reserve(len);
        let start = self.len();
        let mut writer = UninitWriter::new(&mut self.spare_capacity_mut()[..len]);
        fill(&mut writer)?;
        let initialized = writer.initialized_len();
        debug_assert_eq!(initialized, len);
        // SAFETY: the writer covers spare capacity beginning at the old length and
        // reports only the prefix initialized by its bounds-checked write methods.
        unsafe { self.set_len(start + initialized) };
        Ok(())
    }
}
