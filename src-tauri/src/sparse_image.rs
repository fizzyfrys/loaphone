use crc32fast::Hasher;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

pub const MAGIC: [u8; 4] = 0xed26ff3au32.to_le_bytes();

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn add_zeros(crc: &mut Hasher, mut len: u64) {
    let mut power = Hasher::new();
    power.update(&[0]);
    while len != 0 {
        if len & 1 != 0 {
            crc.combine(&power);
        }
        len >>= 1;
        if len != 0 {
            power.combine(&power.clone());
        }
    }
}

pub fn expand(mut input: impl Read, output: &mut File) -> io::Result<u64> {
    let mut header = [0; 28];
    input.read_exact(&mut header)?;
    let header_len = usize::from(u16_at(&header, 8));
    let chunk_header_len = usize::from(u16_at(&header, 10));
    let block_size = u64::from(u32_at(&header, 12));
    if !header.starts_with(&MAGIC)
        || u16_at(&header, 4) != 1
        || header_len < header.len()
        || chunk_header_len < 12
        || block_size == 0
        || block_size % 4 != 0
    {
        return Err(invalid("Invalid Android sparse header"));
    }
    let expected_len = block_size * u64::from(u32_at(&header, 16));
    let mut buffer = vec![0; 64 * 1024];
    input.read_exact(&mut buffer[..header_len - header.len()])?;
    let mut chunk = vec![0; chunk_header_len];
    let mut crc = Hasher::new();
    let mut written = 0u64;
    for _ in 0..u32_at(&header, 20) {
        input.read_exact(&mut chunk)?;
        let kind = u16_at(&chunk, 0);
        let len = block_size * u64::from(u32_at(&chunk, 4));
        let next = written
            .checked_add(len)
            .filter(|&end| end <= expected_len)
            .ok_or_else(|| invalid("Sparse chunks exceed declared image size"))?;
        let payload = u64::from(u32_at(&chunk, 8))
            .checked_sub(chunk_header_len as u64)
            .ok_or_else(|| invalid("Invalid sparse chunk size"))?;
        match (kind, payload) {
            (0xcac1, size) if size == len => {
                let mut remaining = len;
                while remaining != 0 {
                    let n = remaining.min(buffer.len() as u64) as usize;
                    input.read_exact(&mut buffer[..n])?;
                    output.write_all(&buffer[..n])?;
                    crc.update(&buffer[..n]);
                    remaining -= n as u64;
                }
            }
            (0xcac2, 4) => {
                let mut pattern = [0; 4];
                input.read_exact(&mut pattern)?;
                for bytes in buffer.as_chunks_mut::<4>().0 {
                    *bytes = pattern;
                }
                let mut remaining = len;
                while remaining != 0 {
                    let n = remaining.min(buffer.len() as u64) as usize;
                    output.write_all(&buffer[..n])?;
                    crc.update(&buffer[..n]);
                    remaining -= n as u64;
                }
            }
            (0xcac3, 0) => {
                output.seek(SeekFrom::Start(next))?;
                add_zeros(&mut crc, len);
            }
            (0xcac4, 4) if len == 0 => {
                let mut checksum = [0; 4];
                input.read_exact(&mut checksum)?;
                if u32::from_le_bytes(checksum) != crc.clone().finalize() {
                    return Err(invalid("Sparse CRC chunk does not match expanded bytes"));
                }
            }
            _ => return Err(invalid("Unknown or malformed sparse chunk")),
        }
        written = next;
    }
    if written != expected_len {
        return Err(invalid("Sparse image has fewer blocks than declared"));
    }
    let checksum = u32_at(&header, 24);
    if checksum != 0 && checksum != crc.finalize() {
        return Err(invalid(
            "Sparse image checksum does not match expanded bytes",
        ));
    }
    output.set_len(written)?;
    Ok(written)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
        assert_eq!(raw.len() % 4, 0);
        let mut expanded = raw.to_vec();
        expanded.extend([1, 2, 3, 4, 1, 2, 3, 4]);
        expanded.extend([0; 12]);
        let crc = crc32fast::hash(&expanded).to_le_bytes();
        let mut sparse = Vec::from(MAGIC);
        for field in [1u16, 0, 32, 16] {
            sparse.extend(field.to_le_bytes());
        }
        for field in [4u32, (expanded.len() / 4) as u32, 4] {
            sparse.extend(field.to_le_bytes());
        }
        sparse.extend(crc);
        sparse.extend([0; 4]);
        for (kind, blocks, payload) in [
            (0xcac1u16, (raw.len() / 4) as u32, raw),
            (0xcac2, 2, &[1, 2, 3, 4]),
            (0xcac3, 3, &[]),
            (0xcac4, 0, &crc),
        ] {
            sparse.extend(kind.to_le_bytes());
            sparse.extend([0; 2]);
            sparse.extend(blocks.to_le_bytes());
            sparse.extend((16 + payload.len() as u32).to_le_bytes());
            sparse.extend([0; 4]);
            sparse.extend(payload);
        }
        (sparse, expanded)
    }

    #[test]
    fn expands_all_chunk_types_and_checks_crc() {
        let (mut sparse, expected) = sample(b"ABCD");
        let mut output = tempfile::tempfile().unwrap();
        assert_eq!(expand(&sparse[..], &mut output).unwrap(), 24);
        output.rewind().unwrap();
        let mut raw = Vec::new();
        output.read_to_end(&mut raw).unwrap();
        assert_eq!(raw, expected);
        let last = sparse.len() - 1;
        sparse[last] ^= 1;
        assert!(expand(&sparse[..], &mut tempfile::tempfile().unwrap()).is_err());
        assert!(expand(&sparse[..last], &mut tempfile::tempfile().unwrap()).is_err());
    }
}
