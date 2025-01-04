//! A SIMD-ized implementation of MD4 designed to hash many blocks in parallel.
//! The base implementation is derived from https://github.com/RustCrypto/hashes/tree/master/md4.
#![allow(clippy::ptr_offset_with_cast)]

use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};

#[cfg(target_arch = "aarch64")]
mod aarch64_simd_transpose;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_simd_transpose;

// initial values for Md4State
const S: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

macro_rules! md4 {
    (
        ($($prefix:tt)*),
        $u32:ty,
        add = $add:path,
        and = $and:path,
        or = $or:path,
        andnot = $andnot:path,
        xor = $xor:path,
        rol = ($($rol:tt)*),
        splat = $splat:path,
    ) => {
        #[derive(Copy, Clone)]
        pub struct Md4State {
            s: [$u32; 4],
        }

        #[allow(unused_parens)]
        impl Md4State {
            $($prefix)*
            fn process_block(&mut self, data: &[$u32; 16]) {
                macro_rules! f {
                    ($x:expr, $y:expr, $z:expr) => ($or($and($x, $y), $andnot($x, $z)));
                }
                macro_rules! g {
                    ($x:expr, $y:expr, $z:expr) => ($or($or($and($x, $y), $and($x, $z)), $and($y, $z)));
                }
                macro_rules! h {
                    ($x:expr, $y:expr, $z:expr) => ($xor($xor($x, $y), $z));
                }
                macro_rules! op1 {
                    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
                        $($rol)*($add($add($a, f!($b, $c, $d)), $k), $s)
                    );
                }
                macro_rules! op2 {
                    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
                        $($rol)*($add($add($add($a, g!($b, $c, $d)), $k), $splat(0x5A82_7999)), $s)
                    );
                }
                macro_rules! op3 {
                    ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => (
                        $($rol)*($add($add($add($a, h!($b, $c, $d)), $k), $splat(0x6ED9_EBA1)), $s)
                    );
                }

                let mut a = self.s[0];
                let mut b = self.s[1];
                let mut c = self.s[2];
                let mut d = self.s[3];

                // Manually unrolling these loops avoids bounds checking on `data` accesses.
                macro_rules! round1 {
                    ($i:expr) => {
                        a = op1!(a, b, c, d, data[$i], 3);
                        d = op1!(d, a, b, c, data[$i + 1], 7);
                        c = op1!(c, d, a, b, data[$i + 2], 11);
                        b = op1!(b, c, d, a, data[$i + 3], 19);
                    }
                }
                round1!(0);
                round1!(4);
                round1!(8);
                round1!(12);

                macro_rules! round2 {
                    ($i:expr) => {
                        a = op2!(a, b, c, d, data[$i], 3);
                        d = op2!(d, a, b, c, data[$i + 4], 5);
                        c = op2!(c, d, a, b, data[$i + 8], 9);
                        b = op2!(b, c, d, a, data[$i + 12], 13);
                    }
                }
                round2!(0);
                round2!(1);
                round2!(2);
                round2!(3);

                macro_rules! round3 {
                    ($i:expr) => {
                        a = op3!(a, b, c, d, data[$i], 3);
                        d = op3!(d, a, b, c, data[$i + 8], 9);
                        c = op3!(c, d, a, b, data[$i + 4], 11);
                        b = op3!(b, c, d, a, data[$i + 12], 15);
                    }
                }
                round3!(0);
                round3!(2);
                round3!(1);
                round3!(3);

                self.s[0] = $add(self.s[0], a);
                self.s[1] = $add(self.s[1], b);
                self.s[2] = $add(self.s[2], c);
                self.s[3] = $add(self.s[3], d);
            }
        }
    };
}

use std::convert::identity;
use std::ops::{BitAnd, BitOr, BitXor};

use crate::sum_hash::SumHash;

fn andnot(x: u32, y: u32) -> u32 {
    !x & y
}
md4!(
    (),
    u32,
    add = u32::wrapping_add,
    and = u32::bitand,
    or = u32::bitor,
    andnot = andnot,
    xor = u32::bitxor,
    rol = (u32::rotate_left),
    splat = identity,
);

fn load_block(input: &[u8; 64]) -> [u32; 16] {
    macro_rules! split {
        ($($name: ident $(. $dummy:tt)*)*) => ({
            let ($($name),*) = array_refs![input, $(4 $($dummy)*),*];
            [$(u32::from_le_bytes(*$name)),*]
        });
    }
    split!(x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15)
}

pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut state = Md4State::default();
    state.update(data);
    state.finish().into()
}

impl Default for Md4State {
    fn default() -> Self {
        Md4State { s: S }
    }
}
impl SumHash for Md4State {
    type Sum = [u8; 16];

    fn update(&mut self, data: &[u8]) -> &mut Self {
        let mut chunks = data.chunks_exact(64);
        for block in &mut chunks {
            self.process_block(&load_block(array_ref![block, 0, 64]));
        }
        let remainder = chunks.remainder();
        let mut last_blocks = [0; 128];
        last_blocks[..remainder.len()].copy_from_slice(remainder);
        last_blocks[remainder.len()] = 0x80;
        let end = if remainder.len() >= 56 { 128 } else { 64 };
        *array_mut_ref![&mut last_blocks, end - 8, 8] = (data.len() as u64 * 8).to_le_bytes();
        let (last_block_0, last_block_1) = array_refs![&last_blocks, 64, 64];
        self.process_block(&load_block(last_block_0));
        if end == 128 {
            self.process_block(&load_block(last_block_1));
        }
        self
    }

    fn finish(&self) -> Self::Sum {
        let mut output = [0; 16];
        let (a, b, c, d) = mut_array_refs!(&mut output, 4, 4, 4, 4);
        *a = self.s[0].to_le_bytes();
        *b = self.s[1].to_le_bytes();
        *c = self.s[2].to_le_bytes();
        *d = self.s[3].to_le_bytes();
        output.into()
    }
}

pub(crate) mod simd {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub const MAX_LANES: usize = 8;
    #[cfg(any(target_arch = "aarch64"))]
    pub const MAX_LANES: usize = 4;
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    pub const MAX_LANES: usize = 0;

    pub struct Md4xN {
        lanes: usize,
        fun: fn(&mut [(&mut super::Md4State, &[u8])]),
    }

    impl Md4xN {
        /// The number of digests this implementation calculates at once.
        pub fn lanes(&self) -> usize {
            self.lanes
        }

        /// Calculate the digest of `self.lanes()` equally-sized blocks of data.
        pub fn md4(&self, pairs: &mut [(&mut super::Md4State, &[u8])]) {
            (self.fun)(pairs)
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    mod real_impl {
        #[cfg(target_arch = "aarch64")]
        use std::arch::aarch64 as arch;
        #[cfg(target_arch = "x86")]
        use std::arch::x86 as arch;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64 as arch;

        macro_rules! n_lanes {
            (
                $u32xN:path,
                $feature:tt,
                $feature_enabled:expr,
                load = $load:path,
                add = $add:path,
                and = $and:path,
                or = $or:path,
                andnot = $andnot:path,
                xor = $xor:path,
                rol = $rol:tt,
                splat = $splat:path,
            ) => (
                use crate::md4::simd::Md4xN;
                use arrayref::{array_ref, array_mut_ref};
                use std::mem;

                #[allow(non_camel_case_types)]
                type u32xN = $u32xN;
                pub const LANES: usize = mem::size_of::<u32xN>() / mem::size_of::<u32>();

                md4!(
                    (#[target_feature(enable = $feature)] unsafe),
                    u32xN,
                    add = $add,
                    and = $and,
                    or = $or,
                    andnot = $andnot,
                    xor = $xor,
                    rol = $rol,
                    splat = $splat,
                );

                /// Compute the MD4 sum of multiple equally-sized blocks of data.
                /// Unsafety: This function requires $feature to be available.
                #[allow(non_snake_case)]
                #[target_feature(enable = $feature)]
                unsafe fn md4xN(pairs: &mut [(&mut crate::md4::Md4State, &[u8]); LANES]) {
                    let mut init_state = [[0; LANES]; 4];
                    for i in 0..LANES {
                        let pair = &pairs[i].0;
                        init_state[0][i] = pair.s[0];
                        init_state[1][i] = pair.s[1];
                        init_state[2][i] = pair.s[2];
                        init_state[3][i] = pair.s[3];
                    }
                    let mut state = mem::transmute::<[[u32; LANES]; 4], Md4State>(init_state);

                    let len = pairs[0].1.len();
                    for ix in 1..LANES {
                        assert_eq!(len, pairs[ix].1.len());
                    }
                    for block in 0..(len / 64) {
                        let blocks = $load(|lane| array_ref![&(pairs[lane].1), 64 * block, 64]);
                        state.process_block(&blocks);
                    }
                    let remainder = len % 64;
                    let bit_len = len as u64 * 8;

                    let mut padded = [[0; 64]; LANES];
                    for lane in 0..LANES {
                        padded[lane][..remainder].copy_from_slice(&(pairs[lane].1)[len - remainder..]);
                        padded[lane][remainder] = 0x80;
                    }
                    let mut blocks = $load(|lane| &padded[lane]);
                    if remainder < 56 {
                        blocks[14] = $splat(bit_len as u32);
                        blocks[15] = $splat((bit_len >> 32) as u32);
                    }
                    state.process_block(&blocks);

                    if remainder >= 56 {
                        let mut blocks = [$splat(0); 16];
                        blocks[14] = $splat(bit_len as u32);
                        blocks[15] = $splat((bit_len >> 32) as u32);
                        state.process_block(&blocks);
                    }
                    // Safety: `u32xN` and `[u32; LANES]` are always safely transmutable
                    let final_state = mem::transmute::<[u32xN; 4], [[u32; LANES]; 4]>(state.s);
                    for lane in 0..LANES {
                        let state = &mut pairs[lane].0.s;
                        state[0] = final_state[0][lane];
                        state[1] = final_state[1][lane];
                        state[2] = final_state[2][lane];
                        state[3] = final_state[3][lane];
                    }
                }

                pub fn select() -> Option<Md4xN> {
                    if $feature_enabled {
                        Some(Md4xN {
                            lanes: LANES,
                            fun: |pairs| {
                                // Safety: We just checked that $feature is available.
                                unsafe { md4xN(array_mut_ref![pairs, 0, LANES]) };
                            }
                        })
                    } else {
                        None
                    }
                }
                );
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        mod lanes_4 {
            #[inline(always)]
            unsafe fn splat(x: u32) -> super::arch::__m128i {
                super::arch::_mm_set1_epi32(x as i32)
            }
            macro_rules! rotate_left {
                ($x: expr, $shift: expr) => {{
                    let x = $x;
                    // (x << shift) | (x >> (32 - shift))
                    super::arch::_mm_or_si128(
                        super::arch::_mm_slli_epi32(x, $shift as i32),
                        super::arch::_mm_srli_epi32(x, 32 - $shift as i32),
                    )
                }};
            }
            n_lanes!(
                super::arch::__m128i,
                "sse2",
                is_x86_feature_detected!("sse2"),
                load = crate::md4::x86_simd_transpose::load_16x4_sse2,
                add = super::arch::_mm_add_epi32,
                and = super::arch::_mm_and_si128,
                or = super::arch::_mm_or_si128,
                andnot = super::arch::_mm_andnot_si128,
                xor = super::arch::_mm_xor_si128,
                rol = (rotate_left!),
                splat = splat,
            );
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        mod lanes_8 {
            #[inline(always)]
            unsafe fn splat(x: u32) -> super::arch::__m256i {
                super::arch::_mm256_set1_epi32(x as i32)
            }
            macro_rules! rotate_left {
                ($x: expr, $shift: expr) => {{
                    let x = $x;
                    // (x << shift) | (x >> (32 - shift))
                    super::arch::_mm256_or_si256(
                        super::arch::_mm256_slli_epi32(x, $shift as i32),
                        super::arch::_mm256_srli_epi32(x, 32 - $shift as i32),
                    )
                }};
            }
            n_lanes!(
                super::arch::__m256i,
                "avx2",
                is_x86_feature_detected!("avx2"),
                load = crate::md4::x86_simd_transpose::load_16x8_avx2,
                add = super::arch::_mm256_add_epi32,
                and = super::arch::_mm256_and_si256,
                or = super::arch::_mm256_or_si256,
                andnot = super::arch::_mm256_andnot_si256,
                xor = super::arch::_mm256_xor_si256,
                rol = (rotate_left!),
                splat = splat,
            );
        }
        #[cfg(target_arch = "aarch64")]
        mod lanes_4 {
            macro_rules! rotate_left {
                ($x: expr, $shift: expr) => {{
                    let x = $x;
                    // (x << shift) | (x >> (32 - shift))
                    super::arch::vorrq_u32(
                        super::arch::vshlq_n_u32::<{ $shift as i32 }>(x),
                        super::arch::vshrq_n_u32::<{ 32 - $shift as i32 }>(x),
                    )
                }};
            }
            #[inline(always)]
            unsafe fn andnot(
                a: super::arch::uint32x4_t,
                b: super::arch::uint32x4_t,
            ) -> super::arch::uint32x4_t {
                // "bit clear", order of arguments is reversed compared to Intel
                super::arch::vbicq_u32(b, a)
            }
            n_lanes!(
                super::arch::uint32x4_t,
                "neon",
                std::arch::is_aarch64_feature_detected!("neon"),
                load = crate::md4::aarch64_simd_transpose::load_16x4,
                add = super::arch::vaddq_u32,
                and = super::arch::vandq_u32,
                or = super::arch::vorrq_u32,
                andnot = andnot,
                xor = super::arch::veorq_u32,
                rol = (rotate_left!),
                splat = super::arch::vdupq_n_u32,
            );
        }

        use super::Md4xN;

        impl Md4xN {
            /// Returns a SIMD implementation if one is available.
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pub fn select() -> Option<Md4xN> {
                lanes_8::select().or_else(lanes_4::select)
            }
            #[cfg(target_arch = "aarch64")]
            pub fn select() -> Option<Md4xN> {
                lanes_4::select()
            }
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    mod no_simd {
        use super::Md4xN;

        impl Md4xN {
            /// Returns a SIMD implementation if one is available.
            pub fn select() -> Option<Md4xN> {
                None
            }
        }
    }
}

pub fn md4_many<'a>(pairs: impl Iterator<Item = (&'a mut Md4State, &'a [u8])>) {
    if let Some(simd_impl) = simd::Md4xN::select() {
        let lanes = simd_impl.lanes();
        let mut buf = Vec::with_capacity(lanes);
        for pair in pairs {
            buf.push(pair);
            if buf.len() == lanes {
                simd_impl.md4(&mut buf);
                buf.clear();
            }
        }

        for (state, data) in buf {
            state.update(data);
        }
    } else {
        for (state, data) in pairs {
            state.update(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        md4::{md4, simd, Md4State},
        sum_hash::SumHash,
    };

    #[test]
    fn tests() {
        let test_vectors: &[(&[u8], [u8; 16])] = &[
            (
                b"",
                *b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0",
            ),
            (
                b"a",
                *b"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24",
            ),
            (
                b"abc",
                *b"\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d",
            ),
            (
                b"message digest",
                *b"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                *b"\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                *b"\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                *b"\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36",
            ),
        ];

        for &(msg, expected) in test_vectors {
            assert_eq!(md4(msg), expected);

            if let Some(simd_impl) = simd::Md4xN::select() {
                let mut states = vec![Md4State::default(); simd_impl.lanes()];
                let mut pairs: Vec<_> = states.iter_mut().map(|s| (s, msg)).collect();
                simd_impl.md4(&mut pairs);
                assert_eq!(
                    states.iter().map(|s| s.finish()).collect::<Vec<_>>(),
                    vec![expected; simd_impl.lanes()][..]
                );
            }

            if msg.is_empty() {
                return;
            }
            // make sure it also works for unaligned input
            let tail = &msg[1..];
            let tail_digest = md4(tail);

            if let Some(simd_impl) = simd::Md4xN::select() {
                let mut states = vec![Md4State::default(); simd_impl.lanes()];
                let mut pairs: Vec<_> = states.iter_mut().map(|s| (s, msg)).collect();
                simd_impl.md4(&mut pairs);
                assert_eq!(
                    states.iter().map(|s| s.finish()).collect::<Vec<_>>(),
                    vec![tail_digest; simd_impl.lanes()][..]
                );
            }
        }
    }
}
