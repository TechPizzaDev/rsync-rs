use crate::sum_hash::{RollingHash, SumHash};

const CRC_MAGIC: u16 = 31;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Crc(u32);

impl Crc {
    pub const SIZE: usize = 4;

    #[inline]
    fn split(self) -> (u16, u16) {
        (self.0 as u16, (self.0 >> 16) as u16)
    }

    #[inline]
    fn combine(s1: u16, s2: u16) -> Crc {
        Crc(s1 as u32 | ((s2 as u32) << 16))
    }
}

impl RollingHash for Crc {
    fn rollout(&mut self, size: usize, old_byte: u8) -> &mut Self {
        let size = size as u16;
        let old_byte = old_byte as u16;
        let (mut s1, mut s2) = self.split();
        s1 = s1.wrapping_sub(old_byte.wrapping_add(CRC_MAGIC));
        s2 = s2.wrapping_sub(size.wrapping_mul(old_byte + CRC_MAGIC));
        *self = Crc::combine(s1, s2);
        self
    }

    #[inline]
    fn rotate(&mut self, size: usize, old_byte: u8, new_byte: u8) -> &mut Self {
        let size = size as u16;
        let old_byte = old_byte as u16;
        let new_byte = new_byte as u16;
        let (mut s1, mut s2) = self.split();
        s1 = s1.wrapping_add(new_byte).wrapping_sub(old_byte);
        s2 = s2
            .wrapping_add(s1)
            .wrapping_sub(size.wrapping_mul(old_byte.wrapping_add(CRC_MAGIC)));
        *self = Crc::combine(s1, s2);
        self
    }

    fn rollin(&mut self, new_byte: u8) -> &mut Self {
        let (mut s1, mut s2) = self.split();
        s1 = s1.wrapping_add(new_byte as u16);
        s2 = s2.wrapping_add(s1);
        s1 = s1.wrapping_add(CRC_MAGIC);
        s2 = s2.wrapping_add(CRC_MAGIC);
        *self = Crc::combine(s1, s2);
        self
    }
}
impl SumHash for Crc {
    type Sum = [u8; 4];

    #[inline]
    fn finish(&self) -> Self::Sum {
        self.0.to_be_bytes().into()
    }

    fn update(&mut self, buf: &[u8]) -> &mut Self {
        macro_rules! imp {
            ($($x:tt)*) => {$($x)* <'a>(init: &'a mut Crc, buf: &[u8]) -> &'a mut Crc {
                let (mut s1, mut s2) = init.split();
                let len = buf.len() as u32;
                s2 = s2.wrapping_add(s1.wrapping_mul(len as u16));
                for (idx, &byte) in buf.iter().enumerate() {
                    s1 = s1.wrapping_add(byte as u16);
                    s2 = s2.wrapping_add(
                        (byte as u16).wrapping_mul((len as u16).wrapping_sub(idx as u16)),
                    );
                }
                s1 = s1.wrapping_add((len as u16).wrapping_mul(CRC_MAGIC));
                s2 = s2.wrapping_add(
                    ((len.wrapping_mul(len.wrapping_add(1)) / 2) as u16).wrapping_mul(CRC_MAGIC),
                );
                *init = Crc::combine(s1, s2);
                init
            }};
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            if is_x86_feature_detected!("avx2") {
                imp!(#[target_feature(enable = "avx2")] unsafe fn imp_avx2);
                return imp_avx2(self, buf);
            }
            if is_x86_feature_detected!("sse2") {
                imp!(#[target_feature(enable = "sse2")] unsafe fn imp_sse2);
                return imp_sse2(self, buf);
            }
        }
        imp!(fn imp_baseline);
        imp_baseline(self, buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::sum_hash::SumHash;

    use super::{Crc, RollingHash, CRC_MAGIC};
    use quickcheck_macros::quickcheck;

    /// Like `Crc::update`, but not autovectorizable.
    pub fn basic_update(init: Crc, buf: &[u8]) -> Crc {
        let (mut s1, mut s2) = init.split();
        for &byte in buf {
            s1 = s1.wrapping_add(byte as u16);
            s2 = s2.wrapping_add(s1);
        }
        let len = buf.len() as u32;
        s1 = s1.wrapping_add((len as u16).wrapping_mul(CRC_MAGIC));
        s2 = s2.wrapping_add(
            ((len.wrapping_mul(len.wrapping_add(1)) / 2) as u16).wrapping_mul(CRC_MAGIC),
        );
        Crc::combine(s1, s2)
    }

    #[quickcheck]
    fn rollin_one(initial: u32, buf: Vec<u8>) -> bool {
        let sum1 = Crc(initial).update(&buf).finish();
        let sum2 = buf
            .into_iter()
            .fold(Crc(initial), |mut s: Crc, new: u8| {
                s.rollin(new);
                s
            })
            .finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn optimized_update(initial: u32, buf: Vec<u8>) -> bool {
        let sum1 = Crc(initial).update(&buf).finish();
        let sum2 = basic_update(Crc(initial), &buf).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn update_twice(initial: u32, mut buf1: Vec<u8>, buf2: Vec<u8>) -> bool {
        let sum1 = Crc(initial).update(&buf1).update(&buf2).finish();
        buf1.extend(&buf2);

        let sum2 = Crc(initial).update(&buf1).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn rotate_one(mut buf: Vec<u8>, byte: u8) -> bool {
        if buf.is_empty() {
            return true;
        }
        let sum1 = Crc::default()
            .update(&buf)
            .rotate(buf.len(), buf[0], byte)
            .finish();
        buf.push(byte);

        let sum2 = Crc::default().update(&buf[1..]).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn rollout_one(buf: Vec<u8>) -> bool {
        if buf.is_empty() {
            return true;
        }
        let sum1 = Crc::default()
            .update(&buf)
            .rollout(buf.len(), buf[0])
            .finish();
        let sum2 = Crc::default().update(&buf[1..]).finish();
        sum1 == sum2
    }
}
