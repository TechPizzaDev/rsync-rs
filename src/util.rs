use std::mem::MaybeUninit;

/// Replica of [`MaybeUninit::copy_from_slice`].
#[inline]
pub fn copy_from_slice<'a, T: Copy>(dst: &'a mut [MaybeUninit<T>], src: &[T]) -> &'a mut [T] {
    unsafe {
        // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout
        let uninit_src: &[MaybeUninit<T>] = std::mem::transmute(src);

        dst.copy_from_slice(uninit_src);
        
        // SAFETY: Valid elements have just been copied into `dst`
        std::mem::transmute(dst)
    }
}