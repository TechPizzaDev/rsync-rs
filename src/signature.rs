use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Write;

use arrayref::array_ref;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crc::Crc;
use crate::hasher::BuildCrcHasher;
use crate::hashmap_variant::SecondLayerMap;
use crate::md4::{md4, md4_many};
use crate::{consts::*, CryptoHashType, RollingHashType};

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
    pub(crate) blocks: HashMap<Crc, SecondLayerMap<&'a [u8], u32>, BuildCrcHasher>,
}

/// The hash type used with within the signature.
/// Note that this library generally only supports MD4 signatures.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SignatureType {
    ///
    Md4,
    ///
    Blake2,
    ///
    RabinKarpMd4,
    ///
    RabinKarpBlake2,
}

impl SignatureType {
    const SIZE: usize = size_of::<u32>();

    ///
    pub fn from_types(crypto: CryptoHashType, rolling: RollingHashType) -> Option<SignatureType> {
        let sig_type = match (crypto, rolling) {
            (CryptoHashType::Md4, RollingHashType::Adler32) => Self::Md4,
            (CryptoHashType::Md4, RollingHashType::RabinKarp) => Self::Md4,
            (CryptoHashType::Blake2, RollingHashType::Adler32) => Self::Blake2,
            (CryptoHashType::Blake2, RollingHashType::RabinKarp) => Self::Blake2,
            _ => return None,
        };
        Some(sig_type)
    }

    ///
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

    ///
    pub fn to_magic(&self) -> [u8; Self::SIZE] {
        match self {
            Self::Md4 => MD4_MAGIC,
            Self::Blake2 => BLAKE2_MAGIC,
            Self::RabinKarpMd4 => RK_MD4_MAGIC,
            Self::RabinKarpBlake2 => RK_BLAKE2_MAGIC,
        }
        .to_be_bytes()
    }

    ///
    pub fn crypto_hash(&self) -> CryptoHashType {
        match self {
            Self::Md4 => CryptoHashType::Md4,
            Self::Blake2 => CryptoHashType::Blake2,
            Self::RabinKarpMd4 => CryptoHashType::Md4,
            Self::RabinKarpBlake2 => CryptoHashType::Blake2,
        }
    }

    ///
    pub fn rolling_hash(&self) -> RollingHashType {
        match self {
            Self::Md4 => RollingHashType::Adler32,
            Self::Blake2 => RollingHashType::Adler32,
            Self::RabinKarpMd4 => RollingHashType::RabinKarp,
            Self::RabinKarpBlake2 => RollingHashType::RabinKarp,
        }
    }
}

/// Indicates that a signature was not valid.
#[derive(Debug)]
pub enum SignatureParseError {
    ///
    IoError(IoError),

    /// The signature started with an unknown magic.
    UnknownMagic {
        /// The magic number encountered.
        magic: u32,
    },
}

impl fmt::Display for SignatureParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unsupported signature")
    }
}

impl Error for SignatureParseError {}

impl From<IoError> for SignatureParseError {
    fn from(value: IoError) -> Self {
        Self::IoError(value)
    }
}

/// Options for [Signature::calculate].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureOptions {
    ///
    pub crypto_hash: CryptoHashType,

    ///
    pub rolling_hash: RollingHashType,

    /// The granularity of the signature.
    /// Smaller block sizes yield larger, but more precise, signatures.
    pub block_size: u32,

    /// The number of bytes to use from the hash.
    /// The larger this is, the less likely that a delta will be mis-applied.
    pub crypto_hash_size: u32,
}

impl SignatureOptions {
    ///
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

impl Signature {
    const HEADER_SIZE: usize = SignatureType::SIZE + 2 * 4; // magic, block_size, then crypto_hash_size

    /// Compute a signature for the given data.
    //
    /// Panics if the provided options are invalid.
    pub async fn calculate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        input: &mut R,
        output: &mut W,
        options: &SignatureOptions,
    ) -> Result<Signature, IoError> {
        let block_size = options.block_size as usize;
        let hash_size = options.crypto_hash_size as usize;
        let crypto_hash = options.crypto_hash;
        let rolling_hash = options.rolling_hash;

        assert!(block_size > 0);
        assert!(hash_size <= crypto_hash.sum_len());

        let mut header_buf = Vec::with_capacity(Self::HEADER_SIZE);
        options.write_header(&mut header_buf)?;
        output.write_all(&header_buf).await?;

        // Hash all the blocks with buffering.
        let buf_cap = block_size.clamp(1024, 1024 * 16);
        let mut buf = Vec::with_capacity(buf_cap);
        loop {
            // Buffer at most one block if it's larger than `buf_cap`.
            let limit = (buf_cap.max(block_size) - buf.len()) as u64;
            let n = input.take(limit).read_to_end(&mut buf).await?;

            let blocks = buf.chunks_exact(block_size);
            let blocks_exact_len = blocks.len() * block_size;

            match crypto_hash {
                CryptoHashType::Md4 => {
                    for (block, md4_hash) in md4_many(blocks) {
                        let hash = &md4_hash[..hash_size];
                        write_block(output, rolling_hash, block, hash).await?;
                    }
                }
                CryptoHashType::Blake2 => {
                    for block in blocks {
                        let hash = &blake_hash(block)[..hash_size];
                        write_block(output, rolling_hash, block, hash).await?;
                    }
                }
                _ => unimplemented!(),
            }

            buf.drain(0..blocks_exact_len);
            if n == 0 {
                break;
            }
        }
        debug_assert!(buf.len() < block_size);

        if !buf.is_empty() {
            // Manually tack on the last block if necessary, since `md4_many`
            // requires every block to be identical in size
            match crypto_hash {
                CryptoHashType::Md4 => {
                    let hash = &md4(&buf)[..hash_size];
                    write_block(output, rolling_hash, &buf, hash).await?;
                }
                CryptoHashType::Blake2 => {
                    let hash = &blake_hash(&buf)[..hash_size];
                    write_block(output, rolling_hash, &buf, hash).await?;
                }
                _ => unimplemented!(),
            }
        }

        fn blake_hash(block: &[u8]) -> [u8; MAX_STRONG_SUM_LENGTH as usize] {
            blake2b_simd::Params::new()
                .hash_length(MAX_STRONG_SUM_LENGTH as usize)
                .hash(block)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        async fn write_block<W: AsyncWrite + Unpin>(
            output: &mut W,
            rolling_hash: RollingHashType,
            block: &[u8],
            hash: &[u8],
        ) -> Result<(), IoError> {
            if rolling_hash != RollingHashType::Adler32 {
                unimplemented!();
            }

            let crc = Crc::new().update(block);
            output.write_all(&crc.to_bytes()).await?;
            output.write_all(hash).await?;
            Ok(())
        }

        Ok(Signature {
            crypto_hash,
            rolling_hash,
            block_size: block_size as u32,
            crypto_hash_size: hash_size as u32,
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

    fn blocks<'a>(&self, bytes: &'a [u8]) -> impl ExactSizeIterator<Item = (Crc, &'a [u8])> {
        bytes[Self::HEADER_SIZE..]
            .chunks_exact(Crc::SIZE + self.crypto_hash_size as usize)
            .map(|b| {
                (
                    Crc::from_bytes(*array_ref!(b, 0, Crc::SIZE)),
                    &b[Crc::SIZE..],
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
    ///
    pub fn new(
        blocks: impl ExactSizeIterator<Item = (Crc, &'a [u8])>,
        options: &SignatureOptions,
    ) -> IndexedSignature<'a> {
        if options.rolling_hash != RollingHashType::Adler32 {
            unimplemented!();
        }

        let mut block_index: HashMap<Crc, SecondLayerMap<&[u8], u32>, BuildCrcHasher> =
            HashMap::with_capacity_and_hasher(blocks.len(), BuildCrcHasher::default());

        for (idx, (crc, crypto_hash)) in blocks.enumerate() {
            block_index
                .entry(crc)
                .or_default()
                .insert(crypto_hash, idx as u32);
        }

        // Multiple blocks having the same `Crc` value means that the hashmap will reserve more
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
