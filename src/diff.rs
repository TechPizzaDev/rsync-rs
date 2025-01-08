use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};

use crate::consts::{
    DELTA_MAGIC, RS_OP_COPY_N1_N1, RS_OP_END, RS_OP_LITERAL_1, RS_OP_LITERAL_N1, RS_OP_LITERAL_N2,
    RS_OP_LITERAL_N4, RS_OP_LITERAL_N8,
};
use crate::crc::Crc;
use crate::hasher::BuildDiffuseHasher;
use crate::rabinkarp::RabinKarpHash;
use crate::signature::IndexedSignature;
use crate::sum_hash::{Blake2Hash, Blake3Hash, CryptoHash, Md4Hash, RollingHash};
use crate::{CryptoHashType, HashType, RollingHashType};

/// This controls how many times we will allow ourselves to fail at matching a
/// given crc before permanently giving up on it (essentially removing it from
/// the signature).
const MAX_CRC_COLLISIONS: u32 = 1024;

/// Indicates that a delta could not be calculated
#[derive(Debug)]
pub enum DiffError {
    /// Indicates the signature is invalid or unsupported
    InvalidSignature,

    /// Indicates an IO error occured when writing the delta
    Io(io::Error),
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("invalid or unsupported signature for diff"),
            Self::Io(source) => write!(f, "IO error while calculating diff (source={})", source),
        }
    }
}

impl Error for DiffError {}

impl From<io::Error> for DiffError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

fn insert_command(len: u64, out: &mut impl Write) -> io::Result<()> {
    assert!(len != 0);
    if len <= 64 {
        out.write_all(&[RS_OP_LITERAL_1 + (len - 1) as u8])?;
    } else if len <= u8::max_value() as u64 {
        out.write_all(&[RS_OP_LITERAL_N1, len as u8])?;
    } else if len <= u16::max_value() as u64 {
        let [v1, v2] = (len as u16).to_be_bytes();
        out.write_all(&[RS_OP_LITERAL_N2, v1, v2])?;
    } else if len <= u32::max_value() as u64 {
        let [v1, v2, v3, v4] = (len as u32).to_be_bytes();
        out.write_all(&[RS_OP_LITERAL_N4, v1, v2, v3, v4])?;
    } else {
        let [v1, v2, v3, v4, v5, v6, v7, v8] = len.to_be_bytes();
        out.write_all(&[RS_OP_LITERAL_N8, v1, v2, v3, v4, v5, v6, v7, v8])?;
    }

    Ok(())
}

fn copy_command(offset: u64, len: u64, out: &mut impl Write) -> io::Result<()> {
    fn u64_size_class(val: u64) -> u8 {
        if val <= u8::max_value() as u64 {
            0
        } else if val <= u16::max_value() as u64 {
            1
        } else if val <= u32::max_value() as u64 {
            2
        } else {
            3
        }
    }

    fn size_class_marker(offset: u64, len: u64) -> u8 {
        let offset_len = u64_size_class(offset);
        let len_len = u64_size_class(len);

        RS_OP_COPY_N1_N1 + offset_len * 4 + len_len
    }

    fn write_varint(val: u64, out: &mut impl Write) -> io::Result<()> {
        if val <= u8::max_value() as u64 {
            out.write_all(&[val as u8])?;
        } else if val <= u16::max_value() as u64 {
            out.write_all(&(val as u16).to_be_bytes())?;
        } else if val <= u32::max_value() as u64 {
            out.write_all(&(val as u32).to_be_bytes())?;
        } else {
            out.write_all(&val.to_be_bytes())?;
        }

        Ok(())
    }

    let marker = size_class_marker(offset, len);
    out.write_all(&[marker])?;
    write_varint(offset, out)?;
    write_varint(len, out)?;

    Ok(())
}

struct OutputState {
    emitted: usize,
    queued_copy: Option<(u64, usize)>,
}

impl OutputState {
    fn emit(&mut self, until: usize, data: &[u8], mut out: impl Write) -> io::Result<()> {
        if self.emitted == until {
            return Ok(());
        }
        if let Some((offset, len)) = self.queued_copy {
            copy_command(offset as u64, len as u64, &mut out)?;
            self.emitted += len as usize;
        }
        if self.emitted < until {
            let to_emit = &data[self.emitted..until];
            insert_command(to_emit.len() as u64, &mut out)?;
            out.write_all(to_emit)?;
            self.emitted = until;
        }

        Ok(())
    }

    fn copy(
        &mut self,
        offset: u64,
        len: usize,
        here: usize,
        data: &[u8],
        out: &mut impl Write,
    ) -> io::Result<()> {
        if let Some((queued_offset, queued_len)) = self.queued_copy {
            if self.emitted + queued_len == here && queued_offset + queued_len as u64 == offset {
                // just extend the copy
                self.queued_copy = Some((queued_offset, queued_len + len));
                return Ok(());
            }
        }
        self.emit(here, data, out)?;
        self.queued_copy = Some((offset, len));

        Ok(())
    }
}

/// Calculate a delta and write it to `out`.
/// This delta can be applied to the base data represented by `signature` to
/// attempt to reconstruct `data`.
///
/// # Security
/// Since `fast_rsync` uses the insecure MD4 hash algorithm, the resulting delta must not be
/// trusted to correctly reconstruct `data`. The delta might fail to apply or produce the wrong
/// data entirely. Always use another mechanism, like a cryptographic hash function, to validate
/// the final reconstructed data.
pub fn diff(
    signature: &IndexedSignature<'_>,
    data: &[u8],
    out: impl Write,
) -> Result<(), DiffError> {
    match (signature.rolling_hash, signature.crypto_hash) {
        (RollingHashType::Rollsum, CryptoHashType::Md4) => {
            diff_core(Crc::default(), Md4Hash::default(), signature, data, out)
        }
        (RollingHashType::Rollsum, CryptoHashType::Blake2) => {
            diff_core(Crc::default(), Blake2Hash::default(), signature, data, out)
        }
        (RollingHashType::Rollsum, CryptoHashType::Blake3) => {
            diff_core(Crc::default(), Blake3Hash::default(), signature, data, out)
        }
        (RollingHashType::RabinKarp, CryptoHashType::Md4) => diff_core(
            RabinKarpHash::default(),
            Md4Hash::default(),
            signature,
            data,
            out,
        ),
        (RollingHashType::RabinKarp, CryptoHashType::Blake2) => diff_core(
            RabinKarpHash::default(),
            Blake2Hash::default(),
            signature,
            data,
            out,
        ),
        (RollingHashType::RabinKarp, CryptoHashType::Blake3) => diff_core(
            RabinKarpHash::default(),
            Blake3Hash::default(),
            signature,
            data,
            out,
        ),
    }
}

fn diff_core<R: RollingHash<Sum = [u8; 4]>, C: CryptoHash>(
    r_seed: R,
    c_seed: C,
    signature: &IndexedSignature<'_>,
    data: &[u8],
    mut out: impl Write,
) -> Result<(), DiffError> {
    let block_size = signature.block_size as usize;
    let crypto_hash_size = signature.crypto_hash_size as usize;
    if crypto_hash_size > signature.crypto_hash.sum_len() {
        return Err(DiffError::InvalidSignature);
    }

    out.write_all(&DELTA_MAGIC.to_be_bytes())?;
    let mut state = OutputState {
        emitted: 0,
        queued_copy: None,
    };
    let mut here = 0;
    let mut collisions: HashMap<u32, u32, BuildDiffuseHasher> =
        HashMap::with_hasher(BuildDiffuseHasher::default());

    while data.len() - here > 0 {
        let block_len = block_size.min(data.len() - here);
        let mut r_hash = r_seed.clone();
        r_hash.update(&data[here..here + block_len]);
        loop {
            let r_sum = u32::from_be_bytes(r_hash.finish());
            // if we detect too many collisions, blacklist the hash to avoid DoS
            if collisions
                .get(&r_sum)
                .map_or(true, |&count| count < MAX_CRC_COLLISIONS)
            {
                if let Some(blocks) = signature.blocks.get(&r_sum) {
                    let digest = c_seed
                        .clone()
                        .update(&data[here..here + block_len])
                        .finish();
                    if let Some(&idx) = blocks.get(&&digest.as_ref()[..crypto_hash_size]) {
                        // match found
                        state.copy(
                            idx as u64 * block_size as u64,
                            block_len,
                            here,
                            data,
                            &mut out,
                        )?;
                        here += block_len;
                        break;
                    }
                    // collision occured
                    *collisions.entry(r_sum).or_insert(0) += 1;
                }
            }
            // no match, try to extend
            here += 1;
            if here + block_len > data.len() {
                break;
            }
            r_hash.rotate(block_len, data[here - 1], data[here + block_len - 1]);
        }
    }
    state.emit(data.len(), data, &mut out)?;
    out.write_all(&[RS_OP_END])?;
    Ok(())
}
