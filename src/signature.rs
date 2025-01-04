use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::num::NonZeroUsize;

use arrayref::array_ref;
use futures::SinkExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, FramedWrite};

use crate::codec::{Codec, DynCodec};
use crate::consts::*;
use crate::crc::Crc;
use crate::hasher::BuildDiffuseHasher;
use crate::hashmap_variant::SecondLayerMap;
use crate::rabinkarp::RabinKarpHash;
use crate::sum_hash::*;
use crate::util::copy_from_slice;
use crate::{CryptoHashType, HashType, RollingHashType};

type IoError = std::io::Error;

/// An rsync signature.
///
/// A signature contains hashed information about a block of data. It is used to compute a delta
/// against that data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    crypto_hash: CryptoHashType,
    rolling_hash: RollingHashType,
    block_size: u32,
    crypto_hash_size: u32,
}

/// A signature with a block index, suitable for calculating deltas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedSignature<'a> {
    pub(crate) crypto_hash: CryptoHashType,
    pub(crate) rolling_hash: RollingHashType,
    pub(crate) block_size: u32,
    pub(crate) crypto_hash_size: u32,
    /// crc -> crypto hash -> block index
    pub(crate) blocks: HashMap<u32, SecondLayerMap<&'a [u8], u32>, BuildDiffuseHasher>,
}

/// The hash type used with within the signature.
/// Note that this library generally only supports MD4 signatures.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SignatureType {
    Md4,
    Blake2,
    RabinKarpMd4,
    RabinKarpBlake2,
}

impl SignatureType {
    const SIZE: usize = size_of::<u32>();

    pub fn from_types(crypto: CryptoHashType, rolling: RollingHashType) -> Option<SignatureType> {
        let sig_type = match (crypto, rolling) {
            (CryptoHashType::Md4, RollingHashType::Rollsum) => Self::Md4,
            (CryptoHashType::Md4, RollingHashType::RabinKarp) => Self::RabinKarpMd4,
            (CryptoHashType::Blake2, RollingHashType::Rollsum) => Self::Blake2,
            (CryptoHashType::Blake2, RollingHashType::RabinKarp) => Self::RabinKarpBlake2,
            _ => return None,
        };
        Some(sig_type)
    }

    pub fn from_magic(bytes: [u8; Self::SIZE]) -> Result<Self, u32> {
        let magic = u32::from_be_bytes(bytes);
        let sig_type = match magic {
            BLAKE2_MAGIC => Self::Blake2,
            MD4_MAGIC => Self::Md4,
            RK_BLAKE2_MAGIC => Self::RabinKarpBlake2,
            RK_MD4_MAGIC => Self::RabinKarpMd4,
            _ => return Err(magic),
        };
        Ok(sig_type)
    }

    pub fn to_magic(&self) -> [u8; Self::SIZE] {
        match self {
            Self::Md4 => MD4_MAGIC,
            Self::Blake2 => BLAKE2_MAGIC,
            Self::RabinKarpMd4 => RK_MD4_MAGIC,
            Self::RabinKarpBlake2 => RK_BLAKE2_MAGIC,
        }
        .to_be_bytes()
    }

    pub fn crypto_hash(&self) -> CryptoHashType {
        match self {
            Self::Md4 => CryptoHashType::Md4,
            Self::Blake2 => CryptoHashType::Blake2,
            Self::RabinKarpMd4 => CryptoHashType::Md4,
            Self::RabinKarpBlake2 => CryptoHashType::Blake2,
        }
    }

    pub fn rolling_hash(&self) -> RollingHashType {
        match self {
            Self::Md4 => RollingHashType::Rollsum,
            Self::Blake2 => RollingHashType::Rollsum,
            Self::RabinKarpMd4 => RollingHashType::RabinKarp,
            Self::RabinKarpBlake2 => RollingHashType::RabinKarp,
        }
    }
}

/// Indicates that a signature was not valid.
#[derive(Debug)]
pub enum SignatureParseError {
    /// The signature started with an unknown magic.
    UnknownMagic {
        /// The magic number encountered.
        magic: u32,
    },

    Io(IoError),
}

impl fmt::Display for SignatureParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMagic { magic } => write!(f, "unknown magic (0x{:08x})", magic),
            Self::Io(source) => write!(f, "IO error while parsing sig (source={})", source),
        }
    }
}

impl Error for SignatureParseError {}

impl From<IoError> for SignatureParseError {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

/// Options for [Signature::calculate].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureOptions {
    pub crypto_hash: CryptoHashType,

    pub rolling_hash: RollingHashType,

    /// The granularity of the signature.
    /// Smaller block sizes yield larger, but more precise, signatures.
    pub block_size: u32,

    /// The number of bytes to use from the hash.
    /// The larger this is, the less likely that a delta will be mis-applied.
    pub crypto_hash_size: u32,
}

impl SignatureOptions {
    pub fn new(
        rolling_hash: RollingHashType,
        crypto_hash: CryptoHashType,
        block_size: u32,
        crypto_hash_size: u32,
    ) -> Self {
        Self {
            rolling_hash,
            crypto_hash,
            block_size,
            crypto_hash_size,
        }
    }

    pub fn with_type(sig_type: SignatureType, block_size: u32, crypto_hash_size: u32) -> Self {
        let rolling_hash = sig_type.rolling_hash();
        let crypto_hash = sig_type.crypto_hash();
        Self::new(rolling_hash, crypto_hash, block_size, crypto_hash_size)
    }

    pub fn signature_type(&self) -> Option<SignatureType> {
        SignatureType::from_types(self.crypto_hash, self.rolling_hash)
    }

    /// Attempts to write an `librsync` header,
    /// returning `true` when the magic is compatible.
    ///
    /// Hashes not supported by `librsync` are written as magic `0x00_00_00_00`.
    pub fn write_header<W: Write>(&self, mut output: W) -> Result<bool, IoError> {
        let magic = self.signature_type().map(|s| s.to_magic());
        let magic_bytes = magic.unwrap_or([0u8; SignatureType::SIZE]);

        output.write_all(&magic_bytes)?;
        output.write_all(&self.block_size.to_be_bytes())?;
        output.write_all(&self.crypto_hash_size.to_be_bytes())?;

        Ok(magic.is_some())
    }
}

#[derive(Debug)]
pub enum SigCodecError {
    /// The signature started with an unknown magic.
    UnknownMagic {
        /// The magic number encountered.
        magic: u32,
    },
    IncompleteFrame {
        actual: usize,
        expected: usize,
    },
    Io(IoError),
}

impl fmt::Display for SigCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMagic { magic } => {
                write!(f, "Unknown magic at start of sig (magic={:#010x})", magic)
            }
            Self::IncompleteFrame { actual, expected } => write!(
                f,
                "Incomplete frame while reading sig (actual={}, expected={})",
                actual, expected
            ),
            Self::Io(source) => write!(f, "IO error while calculating sig (source={})", source),
        }
    }
}

impl Error for SigCodecError {}

impl From<IoError> for SigCodecError {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

pub struct SigBlockCodec<R, C> {
    r_seed: R,
    c_seed: C,
    block_size: NonZeroUsize,
    crypto_size: u32,
}

impl<R, C> Codec<Bytes, (), SigCodecError> for SigBlockCodec<R, C>
where
    R: RollingHash,
    C: CryptoHash,
{
    fn encoder_degree(&self) -> Option<usize> {
        let r = self.r_seed.degree_of_many();
        let c = self.c_seed.degree_of_many();
        r.max(c)
    }
}

impl<R, C> SigBlockCodec<R, C>
where
    R: RollingHash,
    C: CryptoHash,
{
    pub fn new(rolling_seed: R, crypto_seed: C, block_size: usize, crypto_size: u32) -> Self {
        let block_size = NonZeroUsize::new(block_size).unwrap();
        Self {
            c_seed: crypto_seed,
            r_seed: rolling_seed,
            block_size,
            crypto_size,
        }
    }

    pub fn with_default(block_size: usize, crypto_size: u32) -> Self
    where
        R: Default,
        C: Default,
    {
        Self::new(
            Default::default(),
            Default::default(),
            block_size,
            crypto_size,
        )
    }
}

pub fn new_builtin_codec(
    rolling: RollingHashType,
    crypto: CryptoHashType,
    block_size: usize,
    crypto_size: u32,
) -> impl Codec<Bytes, (), SigCodecError> {
    use RollingHashType::*;
    macro_rules! new {
        ($c_ty:ty) => {{
            match rolling {
                Rollsum => Box::new(SigBlockCodec::<Crc, $c_ty>::with_default(
                    block_size,
                    crypto_size,
                )),
                RabinKarp => Box::new(SigBlockCodec::<RabinKarpHash, $c_ty>::with_default(
                    block_size,
                    crypto_size,
                )),
            }
        }};
    }
    use CryptoHashType::*;
    let codec: DynCodec<Box<dyn Codec<_, _, _>>, _, _, _> = DynCodec::new(match crypto {
        Md4 => new!(Md4Hash),
        Blake2 => new!(Blake2Hash),
        Blake3 => new!(Blake3Hash),
    });
    codec
}

impl<R, C> Encoder<Bytes> for SigBlockCodec<R, C>
where
    R: RollingHash,
    C: CryptoHash,
{
    type Error = SigCodecError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let r_sum_size = size_of::<R::Sum>();
        let r_desired_size = r_sum_size;
        assert!(r_desired_size <= r_sum_size);

        let c_sum_size = size_of::<C::Sum>();
        let c_desired_size = self.crypto_size as usize;
        assert!(c_desired_size <= c_sum_size);

        let chunks = item.chunks(self.block_size.get());
        if chunks.len() == 0 {
            return Ok(());
        }

        let frame_size = r_desired_size + c_desired_size;
        let total_frame_size = chunks.len() * frame_size;
        let pad_frame_size = r_sum_size.max(r_desired_size + c_sum_size);
        let additional = total_frame_size + pad_frame_size;
        dst.reserve(additional);
        // Slice to make sure we have enough space for the loop.
        let reserved = &mut dst.spare_capacity_mut()[..additional];

        let mut r_seeds = vec![self.r_seed.clone(); chunks.len()];
        R::update_many(r_seeds.iter_mut().zip(chunks.clone()));
        let r_hashes = R::finish_many(r_seeds.iter());

        let mut c_seeds = vec![self.c_seed.clone(); chunks.len()];
        C::update_many(c_seeds.iter_mut().zip(chunks));
        let c_hashes = C::finish_many(c_seeds.iter());

        for (i, (r_hash, c_hash)) in r_hashes.zip(c_hashes).enumerate() {
            let dst_start = i * frame_size;
            let dst_index = dst_start..(dst_start + pad_frame_size);
            let dst = unsafe {
                // SAFETY: `reserved` is long enough for all chunks.
                reserved.get_unchecked_mut(dst_index)
            };

            // Writing all bytes to `dst` and overwriting excess uses SIMD writes,
            // otherwise we'd get memcpy calls since `c_desired_size` is variable.
            //
            // Example with two 6B-frames, 4B-`R::Sum` and 8B-`C::Sum`:
            //  f : bytes
            // ---:------ f1 end
            // r1 : rrrr  |
            // c1 : rrcccc|cccc  f2 end
            // R2 : rrcccc|RRRR  |
            // C2 : rrcccc|RRCCCC|CCCC

            let r_dst = &mut dst[..r_sum_size];
            copy_from_slice(r_dst, r_hash.as_ref());

            let c_dst = &mut dst[r_desired_size..][..c_sum_size];
            copy_from_slice(c_dst, c_hash.as_ref());
        }
        unsafe {
            // SAFETY: Loops write *at least* `total_frame_size` bytes.
            dst.set_len(dst.len() + total_frame_size)
        };
        Ok(())
    }
}

impl<R, C> Decoder for SigBlockCodec<R, C> {
    type Item = ();
    type Error = SigCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame_size = Crc::SIZE + self.crypto_size as usize;
        if src.len() < frame_size {
            return Ok(None);
        }

        todo!()
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let frame_size = Crc::SIZE + self.crypto_size as usize;
        if buf.len() >= frame_size {
            return self.decode(buf);
        }

        let rem_size = buf.len() % frame_size;
        if rem_size != 0 {
            return Err(SigCodecError::IncompleteFrame {
                actual: rem_size,
                expected: frame_size,
            });
        }
        Ok(None)
    }
}

impl Signature {
    const HEADER_SIZE: usize = SignatureType::SIZE + 2 * 4; // magic, block_size, then crypto_hash_size

    /// Compute a signature for the given data.
    //
    /// Panics if the provided options are invalid.
    pub async fn calculate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        input: &mut R,
        output: &mut W,
        options: &SignatureOptions,
    ) -> Result<Signature, SigCodecError> {
        let block_size = options.block_size as usize;
        let crypto_size = options.crypto_hash_size as usize;
        let crypto_hash = options.crypto_hash;
        let rolling_hash = options.rolling_hash;

        assert!(block_size > 0);
        assert!(crypto_size <= crypto_hash.sum_len());

        let mut header_buf = Vec::with_capacity(Self::HEADER_SIZE);
        options.write_header(&mut header_buf)?;
        output.write_all(&header_buf).await?;

        let codec = new_builtin_codec(
            options.rolling_hash,
            options.crypto_hash,
            block_size,
            crypto_size as u32,
        );
        let encoder_degree = codec.encoder_degree().unwrap_or(1).max(1);
        let mut writer = FramedWrite::new(output, codec);

        // Hash all the blocks with buffering.
        let buf_cap = (block_size * encoder_degree)
            .next_power_of_two()
            .clamp(1 << 10, 1 << 16);
        let mut buf = BytesMut::with_capacity(buf_cap);

        while input.read_buf(&mut buf).await? > 0 {
            let block_count = buf.len() / block_size;
            if block_count > 0 {
                let blocks = buf.split_to(block_count * block_size).freeze();
                writer.feed(blocks).await?;
            } else {
                // Try reserving enough space for at least one full block.
                buf.reserve(buf.remaining().saturating_sub(block_size));
            }
        }
        debug_assert!(buf.len() < block_size);

        if !buf.is_empty() {
            writer.feed(buf.freeze()).await?;
        }
        writer.close().await?;

        Ok(Signature {
            crypto_hash,
            rolling_hash,
            block_size: block_size as u32,
            crypto_hash_size: crypto_size as u32,
        })
    }

    /// Read a binary signature.
    pub async fn deserialize<R: AsyncRead + Unpin>(
        input: &mut R,
    ) -> Result<Signature, SignatureParseError> {
        let mut header_buf = [0; Self::HEADER_SIZE];
        input.read_exact(&mut header_buf).await?;

        let signature_type = SignatureType::from_magic(*array_ref![header_buf, 0, 4])
            .map_err(|magic| SignatureParseError::UnknownMagic { magic })?;

        let block_size = u32::from_be_bytes(*array_ref![header_buf, 4, 4]);
        let crypto_hash_size = u32::from_be_bytes(*array_ref![header_buf, 8, 4]);

        // TODO: verify len per block elsewhere?
        //let block_signature_size = Crc::SIZE + crypto_hash_size as usize;
        //if (blocks.len() - Self::HEADER_SIZE) % block_signature_size != 0 {
        //    return Err(SignatureParseError::IncompleteBlock);
        //}

        Ok(Signature {
            crypto_hash: signature_type.crypto_hash(),
            rolling_hash: signature_type.rolling_hash(),
            block_size,
            crypto_hash_size,
        })
    }

    fn blocks<'a>(&self, bytes: &'a [u8]) -> impl ExactSizeIterator<Item = (u32, &'a [u8])> {
        bytes[Self::HEADER_SIZE..]
            .chunks_exact(Crc::SIZE + self.crypto_hash_size as usize)
            .map(|b| {
                (
                    u32::from_be_bytes(*array_ref!(b, 0, Crc::SIZE)),
                    &b[size_of::<u32>()..],
                )
            })
    }

    /// Convert a signature to a form suitable for computing deltas.
    pub fn index<'a>(&self, bytes: &'a [u8]) -> IndexedSignature<'a> {
        let blocks = self.blocks(bytes);
        IndexedSignature::new(
            blocks,
            &SignatureOptions {
                crypto_hash: self.crypto_hash,
                rolling_hash: self.rolling_hash,
                block_size: self.block_size,
                crypto_hash_size: self.crypto_hash_size,
            },
        )
    }
}

impl<'a> IndexedSignature<'a> {
    pub fn new(
        blocks: impl ExactSizeIterator<Item = (u32, &'a [u8])>,
        options: &SignatureOptions,
    ) -> IndexedSignature<'a> {
        let mut block_index: HashMap<u32, SecondLayerMap<&[u8], u32>, BuildDiffuseHasher> =
            HashMap::with_capacity_and_hasher(blocks.len(), BuildDiffuseHasher::default());

        for (idx, (rolling_hash, crypto_hash)) in blocks.enumerate() {
            block_index
                .entry(rolling_hash)
                .or_default()
                .insert(crypto_hash, idx as u32);
        }

        // Multiple blocks having the same rolling hash means that the hashmap will reserve more
        // capacity than needed. This is particularly noticable when `self.blocks` contains a very
        // large number of values
        block_index.shrink_to_fit();

        IndexedSignature {
            crypto_hash: options.crypto_hash,
            rolling_hash: options.rolling_hash,
            block_size: options.block_size,
            crypto_hash_size: options.crypto_hash_size,
            blocks: block_index,
        }
    }
}
