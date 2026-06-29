use alloc::vec::Vec;

pub(crate) trait VecUninitExt {
    /// Extends the vec by `len` bytes written by `fill`.
    ///
    /// # Safety
    /// `fill` must write every byte of its slice; any byte left unwritten is
    /// published as initialized by the trailing `set_len`.
    unsafe fn extend_uninit(&mut self, len: usize, fill: impl FnOnce(&mut [u8]));
}

impl VecUninitExt for Vec<u8> {
    unsafe fn extend_uninit(&mut self, len: usize, fill: impl FnOnce(&mut [u8])) {
        self.reserve(len);
        let start = self.len();
        // SAFETY: `reserve` guarantees the capacity; the caller's contract has
        // `fill` initialize all `len` bytes; `set_len` publishes them only after.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(self.as_mut_ptr().add(start), len);
            fill(dst);
            self.set_len(start + len);
        }
    }
}
