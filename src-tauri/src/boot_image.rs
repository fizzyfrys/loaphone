use crate::fdt;
use flate2::read::{GzDecoder, ZlibDecoder};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    path::Path,
};

const BOOT: &[u8] = b"ANDROID!";
const VENDOR: &[u8] = b"VNDRBOOT";
const DTBO: [u8; 4] = 0xd7b7ab1eu32.to_be_bytes();
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const MAX_KERNEL: usize = 256 * 1024 * 1024;
const MAX_CONFIG: usize = 8 * 1024 * 1024;
const MAX_TREE: usize = 32 * 1024 * 1024;
const LZ4_BLOCK: usize = 8 * 1024 * 1024;

pub fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(BOOT) || bytes.starts_with(VENDOR) || bytes.starts_with(&DTBO)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn region(bytes: &[u8], offset: usize, size: usize) -> io::Result<&[u8]> {
    bytes
        .get(offset..)
        .and_then(|b| b.get(..size))
        .ok_or_else(|| invalid("Truncated image section"))
}

fn word(bytes: &[u8], offset: usize) -> io::Result<usize> {
    Ok(u32::from_le_bytes(region(bytes, offset, 4)?.try_into().unwrap()) as usize)
}

fn be_word(bytes: &[u8], offset: usize) -> io::Result<usize> {
    Ok(u32::from_be_bytes(region(bytes, offset, 4)?.try_into().unwrap()) as usize)
}

fn padded(size: usize, page: usize) -> io::Result<usize> {
    size.checked_next_multiple_of(page)
        .ok_or_else(|| invalid("Image section offset overflow"))
}

struct Sections<'a> {
    image: &'a [u8],
    offset: usize,
    page: usize,
}

impl<'a> Sections<'a> {
    fn new(image: &'a [u8], header_size: usize, page: usize) -> io::Result<Self> {
        region(image, 0, header_size)?;
        if !page.is_power_of_two() {
            return Err(invalid("Invalid boot image page size"));
        }
        Ok(Self {
            image,
            offset: padded(header_size, page)?,
            page,
        })
    }

    fn take(&mut self, size: usize) -> io::Result<&'a [u8]> {
        if size == 0 {
            return Ok(&[]);
        }
        let bytes = region(self.image, self.offset, size)?;
        self.offset = self
            .offset
            .checked_add(padded(size, self.page)?)
            .ok_or_else(|| invalid("Image section offset overflow"))?;
        Ok(bytes)
    }
}

fn save(out: &Path, file: &str, bytes: &[u8]) -> io::Result<()> {
    if !bytes.is_empty() {
        fs::write(out.join(file), bytes)?;
    }
    Ok(())
}

fn tree(out: &Path, name: &str, bytes: &[u8]) -> io::Result<usize> {
    let mut dts = BufWriter::new(File::create(out.join(format!("{name}.dts")))?);
    let size = fdt::decompile(bytes, &mut dts)?;
    dts.flush()?;
    save(out, &format!("{name}.dtb"), &bytes[..size])?;
    Ok(size)
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

fn embedded_trees(out: &Path, prefix: &str, mut bytes: &[u8]) -> io::Result<usize> {
    let mut count = 0;
    while let Some(start) = find(bytes, &fdt::MAGIC) {
        let candidate = &bytes[start..];
        if fdt::decompile(candidate, io::sink()).is_ok() {
            bytes = &candidate[tree(out, &format!("{prefix}-{count}"), candidate)?..];
            count += 1;
        } else {
            bytes = &candidate[4..];
        }
    }
    Ok(count)
}

fn dt_table(image: &[u8], out: &Path, prefix: &str) -> io::Result<usize> {
    let image = region(image, 0, be_word(image, 4)?)?;
    let header = be_word(image, 8)?;
    let entry = be_word(image, 12)?;
    let count = be_word(image, 16)?;
    let offset = be_word(image, 20)?;
    let version = be_word(image, 28)?;
    if header < 32 || offset < header || entry < 32 || version > 1 {
        return Err(invalid("Unsupported or malformed Android DT table"));
    }
    let table = region(
        image,
        offset,
        entry
            .checked_mul(count)
            .ok_or_else(|| invalid("DT table size overflow"))?,
    )?;
    let first_data = offset + table.len();
    for (index, row) in table.chunks_exact(entry).enumerate() {
        let size = be_word(row, 0)?;
        let offset = be_word(row, 4)?;
        if offset < first_data {
            return Err(invalid("DT table entry overlaps its header"));
        }
        let blob = region(image, offset, size)?;
        let compression = if version == 1 {
            be_word(row, 16)? & 0xf
        } else {
            0
        };
        let decoded = match compression {
            0 => None,
            1 => Some(limited(ZlibDecoder::new(blob), MAX_TREE)),
            2 => Some(limited(GzDecoder::new(blob), MAX_TREE)),
            _ => return Err(invalid("Unsupported DTBO entry compression")),
        };
        let dtb = match &decoded {
            None => blob,
            Some(data) => data
                .as_deref()
                .ok_or_else(|| invalid("Invalid compressed DTBO entry"))?,
        };
        tree(out, &format!("{prefix}-{index}"), dtb)?;
    }
    Ok(count)
}

fn limited(reader: impl Read, limit: usize) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut result)
        .ok()?;
    (result.len() <= limit).then_some(result)
}

fn ikconfig(bytes: &[u8]) -> Option<Vec<u8>> {
    let start = b"IKCFG_ST";
    let end = b"IKCFG_ED";
    let mut input = bytes;
    while let Some(index) = find(input, start) {
        input = &input[index + start.len()..];
        if let Some(size) = find(&input[..input.len().min(MAX_CONFIG)], end)
            && input.starts_with(&[0x1f, 0x8b, 8])
            && let Some(config) = limited(GzDecoder::new(&input[..size]), MAX_CONFIG)
        {
            return Some(config);
        }
    }
    None
}

fn legacy_lz4(mut bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut block = vec![0; LZ4_BLOCK];
    while let Ok(len) = word(bytes, 0) {
        if len == 0 || bytes.len() == 4 {
            break;
        }
        let end = 4usize.checked_add(len)?;
        let Some(compressed) = bytes.get(4..end) else {
            break;
        };
        let n = lz4_flex::block::decompress_into(compressed, &mut block).ok()?;
        if n > MAX_KERNEL - decoded.len() {
            return None;
        }
        decoded.extend_from_slice(&block[..n]);
        bytes = &bytes[end..];
    }
    (!decoded.is_empty()).then_some(decoded)
}

fn kernel_config(kernel: &[u8]) -> Option<Vec<u8>> {
    if let Some(config) = ikconfig(kernel) {
        return Some(config);
    }
    for (offset, prefix) in kernel.windows(4).enumerate() {
        let bytes = &kernel[offset..];
        let decoded = match prefix {
            [0x1f, 0x8b, 8, flags] if flags & 0xe0 == 0 => {
                limited(GzDecoder::new(bytes), MAX_KERNEL)
            }
            [0x04, 0x22, 0x4d, 0x18] => {
                limited(lz4_flex::frame::FrameDecoder::new(bytes), MAX_KERNEL)
            }
            [0x02, 0x21, 0x4c, 0x18] => legacy_lz4(&bytes[4..]),
            _ => continue,
        };
        if let Some(config) = decoded.as_deref().and_then(ikconfig) {
            return Some(config);
        }
    }
    None
}

fn cmdline(out: &Path, parts: &[&[u8]]) -> io::Result<()> {
    let joined: Vec<_> = parts
        .iter()
        .flat_map(|part| part.iter().take_while(|&&b| b != 0).copied())
        .collect();
    save(out, "cmdline.txt", &joined)
}

fn boot(image: &[u8], out: &Path) -> io::Result<String> {
    let version = word(image, 40)?;
    let header = match version {
        0 => 1632,
        1 => 1648,
        2 => 1660,
        3 => 1580,
        4 => 1584,
        _ => return Err(invalid("Unsupported Android boot header version")),
    };
    let modern = version >= 3;
    let page = if modern { 4096 } else { word(image, 36)? };
    let mut sections = Sections::new(image, header, page)?;
    let header_field = match version {
        0 => None,
        1 | 2 => Some(1644),
        _ => Some(20),
    };
    if let Some(offset) = header_field
        && word(image, offset)? != header
    {
        return Err(invalid("Invalid Android boot header size"));
    }
    let kernel = sections.take(word(image, 8)?)?;
    let ramdisk = sections.take(word(image, if modern { 12 } else { 16 })?)?;
    save(out, "kernel", kernel)?;
    save(out, "ramdisk", ramdisk)?;
    let mut dts = embedded_trees(out, "kernel-dtb", kernel)?;
    if modern {
        cmdline(out, &[region(image, 44, 1536)?])?;
        if version == 4 {
            save(out, "boot-signature", sections.take(word(image, 1580)?)?)?;
        }
    } else {
        cmdline(out, &[region(image, 64, 512)?, region(image, 608, 1024)?])?;
        save(out, "second-stage", sections.take(word(image, 24)?)?)?;
        if version >= 1 {
            let size = word(image, 1632)?;
            if size != 0 {
                let offset = u64::from_le_bytes(region(image, 1636, 8)?.try_into().unwrap());
                if offset != sections.offset as u64 {
                    return Err(invalid("Invalid recovery DTBO section offset"));
                }
            }
            let recovery = sections.take(size)?;
            save(out, "recovery-dtbo", recovery)?;
            if recovery.starts_with(&DTBO) {
                dts += dt_table(recovery, out, "recovery-dtbo")?;
            } else {
                dts += embedded_trees(out, "recovery-dtb", recovery)?;
            }
        }
        if version >= 2 {
            let dtb = sections.take(word(image, 1648)?)?;
            save(out, "boot-dtb", dtb)?;
            dts += embedded_trees(out, "boot-dtb", dtb)?;
        }
    }
    let config = kernel_config(kernel);
    if let Some(config) = &config {
        save(out, "kernel.config", config)?;
    }
    Ok(format!(
        "boot v{version}; {} DTS; kernel config {}",
        dts,
        if config.is_some() {
            "recovered"
        } else {
            "not found"
        }
    ))
}

fn vendor_boot(image: &[u8], out: &Path) -> io::Result<String> {
    let version = word(image, 8)?;
    let header = match version {
        3 => 2112,
        4 => 2128,
        _ => return Err(invalid("Unsupported Android vendor_boot header version")),
    };
    let mut sections = Sections::new(image, header, word(image, 12)?)?;
    if word(image, 2096)? != header {
        return Err(invalid("Invalid Android vendor_boot header size"));
    }
    let ramdisk = sections.take(word(image, 24)?)?;
    save(out, "vendor-ramdisk", ramdisk)?;
    cmdline(out, &[region(image, 28, 2048)?])?;
    let dtb = sections.take(word(image, 2100)?)?;
    save(out, "vendor-dtb", dtb)?;
    let dts = embedded_trees(out, "vendor-dtb", dtb)?;
    if version == 4 {
        let table = sections.take(word(image, 2112)?)?;
        let count = word(image, 2116)?;
        let entry = word(image, 2120)?;
        if entry.checked_mul(count) != Some(table.len()) || (count != 0 && entry < 108) {
            return Err(invalid("Invalid vendor ramdisk table size"));
        }
        if count != 0 {
            for (index, row) in table.chunks_exact(entry).enumerate() {
                let data = region(ramdisk, word(row, 4)?, word(row, 0)?)?;
                save(out, &format!("vendor-ramdisk-{index}"), data)?;
            }
        }
        save(out, "vendor-ramdisk-table", table)?;
        save(out, "bootconfig", sections.take(word(image, 2124)?)?)?;
    }
    Ok(format!("vendor_boot v{version}; {dts} DTS"))
}

pub fn unpack(image: &Path, out: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(image)?
        .take(MAX_IMAGE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMAGE {
        return Err(invalid("Boot or DTBO image exceeds 512 MiB"));
    }
    if bytes.starts_with(BOOT) {
        boot(&bytes, out)
    } else if bytes.starts_with(VENDOR) {
        vendor_boot(&bytes, out)
    } else if bytes.starts_with(&DTBO) {
        let count = dt_table(&bytes, out, "dtbo")?;
        Ok(format!("Android DTBO table; {count} DTS"))
    } else {
        Err(invalid("Unknown boot image format"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flate2::{
        Compression,
        write::{GzEncoder, ZlibEncoder},
    };

    const PAGE: usize = 4096;
    const CONFIG: &[u8] = b"CONFIG_IKCONFIG=y\nCONFIG_ARCH_QCOM=y\n";

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn marked_kernel() -> Vec<u8> {
        let mut bytes = Vec::from(&b"demo kernel\0IKCFG_ST"[..]);
        bytes.extend(gzip(CONFIG));
        bytes.extend(b"IKCFG_ED\0");
        bytes
    }

    fn le_at(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }

    fn append(image: &mut Vec<u8>, section: &[u8]) {
        image.extend(section);
        image.resize(image.len().next_multiple_of(PAGE), 0);
    }

    pub(crate) fn dtbo_sample() -> Vec<u8> {
        let dtb = fdt::tests::sample();
        dtbo_image(&dtb, 0, 0)
    }

    fn dtbo_image(payload: &[u8], version: u32, flags: u32) -> Vec<u8> {
        let mut image = Vec::from(DTBO);
        for w in [
            64 + payload.len() as u32,
            32,
            32,
            1,
            32,
            2048,
            version,
            payload.len() as u32,
            64,
            0,
            0,
            flags,
            0,
            0,
            0,
        ] {
            image.extend(w.to_be_bytes());
        }
        image.extend(payload);
        image
    }

    pub(crate) fn boot_sample(version: usize) -> Vec<u8> {
        let mut image = vec![0; PAGE];
        image[..8].copy_from_slice(BOOT);
        let dtb = fdt::tests::sample();
        let mut kernel = gzip(&marked_kernel());
        if version == 0 {
            kernel.extend(&dtb);
        }
        let ramdisk = b"ramdisk";
        le_at(&mut image, 8, kernel.len());
        le_at(&mut image, 40, version);
        if version >= 3 {
            le_at(&mut image, 12, ramdisk.len());
            le_at(&mut image, 20, if version == 3 { 1580 } else { 1584 });
        } else {
            le_at(&mut image, 16, ramdisk.len());
            le_at(&mut image, 24, b"second".len());
            le_at(&mut image, 36, PAGE);
        }
        append(&mut image, &kernel);
        append(&mut image, ramdisk);
        if version <= 2 {
            append(&mut image, b"second");
            if version >= 1 {
                let recovery = dtbo_sample();
                let offset = image.len();
                le_at(&mut image, 1632, recovery.len());
                image[1636..1644].copy_from_slice(&(offset as u64).to_le_bytes());
                le_at(&mut image, 1644, if version == 1 { 1648 } else { 1660 });
                append(&mut image, &recovery);
            }
            if version == 2 {
                le_at(&mut image, 1648, dtb.len());
                append(&mut image, &dtb);
            }
        } else if version == 4 {
            le_at(&mut image, 1580, b"signature".len());
            append(&mut image, b"signature");
        }
        image
    }

    pub(crate) fn vendor_sample(version: usize) -> Vec<u8> {
        vendor_sample_with_page(version, PAGE)
    }

    fn vendor_sample_with_page(version: usize, page: usize) -> Vec<u8> {
        let header_size = if version == 3 { 2112usize } else { 2128 };
        let mut image = vec![0; header_size.next_multiple_of(page)];
        let append = |image: &mut Vec<u8>, section: &[u8]| {
            image.extend_from_slice(section);
            image.resize(image.len().next_multiple_of(page), 0);
        };
        image[..8].copy_from_slice(VENDOR);
        let ramdisk = b"one two";
        let dtb = fdt::tests::sample();
        let trees = [dtb.as_slice(), dtb.as_slice()].concat();
        le_at(&mut image, 8, version);
        le_at(&mut image, 12, page);
        le_at(&mut image, 24, ramdisk.len());
        le_at(&mut image, 2096, header_size);
        le_at(&mut image, 2100, trees.len());
        append(&mut image, ramdisk);
        append(&mut image, &trees);
        if version == 4 {
            let mut table = vec![0; 216];
            le_at(&mut table, 0, 3);
            le_at(&mut table, 108, 3);
            le_at(&mut table, 112, 4);
            le_at(&mut image, 2112, table.len());
            le_at(&mut image, 2116, 2);
            le_at(&mut image, 2120, 108);
            le_at(&mut image, 2124, 3);
            append(&mut image, &table);
            append(&mut image, b"x=y");
        }
        image
    }

    #[test]
    fn boot_versions_zero_through_four_unpack_components_and_config() {
        for version in 0..=4 {
            let out = tempfile::tempdir().unwrap();
            let bytes = boot_sample(version);
            assert!(
                boot(&bytes, out.path())
                    .unwrap()
                    .contains("kernel config recovered")
            );
            for (file, expected) in [
                ("ramdisk", b"ramdisk".as_slice()),
                ("kernel.config", CONFIG),
            ] {
                assert_eq!(fs::read(out.path().join(file)).unwrap(), expected);
            }
            for file in match version {
                0 => &["second-stage", "kernel-dtb-0.dts"][..],
                1 => &["second-stage", "recovery-dtbo-0.dts"],
                2 => &["second-stage", "recovery-dtbo-0.dts", "boot-dtb-0.dts"],
                3 => &[],
                _ => &["boot-signature"],
            } {
                assert!(out.path().join(file).is_file());
            }
            assert!(boot(&bytes[..2 * PAGE], out.path()).is_err());
        }
    }

    #[test]
    fn vendor_boot_and_dtbo_unpack_trees_and_fragments() {
        for version in [3, 4] {
            let out = tempfile::tempdir().unwrap();
            let mut bytes = vendor_sample(version);
            assert!(vendor_boot(&bytes, out.path()).unwrap().contains("2 DTS"));
            assert_eq!(
                fs::read(out.path().join("vendor-ramdisk")).unwrap(),
                b"one two"
            );
            assert!(out.path().join("vendor-dtb-1.dts").is_file());
            if version == 4 {
                assert_eq!(
                    fs::read(out.path().join("vendor-ramdisk-1")).unwrap(),
                    b"two"
                );
                assert_eq!(fs::read(out.path().join("bootconfig")).unwrap(), b"x=y");
                le_at(&mut bytes, 3 * PAGE + 112, usize::MAX);
                assert!(vendor_boot(&bytes, out.path()).is_err());
            }
        }
        let out = tempfile::tempdir().unwrap();
        let mut bytes = dtbo_sample();
        assert_eq!(dt_table(&bytes, out.path(), "dtbo").unwrap(), 1);
        assert_eq!(
            fs::read(out.path().join("dtbo-0.dtb")).unwrap(),
            fdt::tests::sample()
        );
        bytes[36..40].copy_from_slice(&0u32.to_be_bytes());
        assert!(dt_table(&bytes, out.path(), "dtbo").is_err());
    }

    #[test]
    fn review_regression_vendor_boot_header_spans_two_pages() {
        for version in [3, 4] {
            let out = tempfile::tempdir().unwrap();
            let bytes = vendor_sample_with_page(version, 2048);
            assert!(vendor_boot(&bytes, out.path()).unwrap().contains("2 DTS"));
            assert_eq!(
                fs::read(out.path().join("vendor-ramdisk")).unwrap(),
                b"one two"
            );
            assert!(out.path().join("vendor-dtb-1.dts").is_file());
            if version == 4 {
                assert_eq!(
                    fs::read(out.path().join("vendor-ramdisk-1")).unwrap(),
                    b"two"
                );
                assert_eq!(fs::read(out.path().join("bootconfig")).unwrap(), b"x=y");
            }
        }
    }

    #[test]
    fn retrieves_config_from_raw_gzip_and_both_lz4_formats() {
        let kernel = marked_kernel();
        let mut framed = lz4_flex::frame::FrameEncoder::new(Vec::new());
        framed.write_all(&kernel).unwrap();
        let framed = framed.finish().unwrap();
        let mut legacy = vec![0x02, 0x21, 0x4c, 0x18];
        let compressed = lz4_flex::block::compress(&kernel);
        legacy.extend((compressed.len() as u32).to_le_bytes());
        legacy.extend(&compressed);
        legacy.extend((kernel.len() as u32).to_le_bytes());
        let wrapped = [b"wrapper".as_slice(), &gzip(&kernel)].concat();
        for sample in [&kernel, &wrapped, &framed, &legacy] {
            assert_eq!(kernel_config(sample).unwrap(), CONFIG);
        }
        assert!(kernel_config(b"IKCFG_STno gzipIKCFG_ED").is_none());
    }

    #[test]
    fn version_one_dtbo_decompresses_zlib_and_gzip_entries() {
        let dtb = fdt::tests::sample();
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::fast());
        zlib.write_all(&dtb).unwrap();
        for (flag, compressed) in [(1, zlib.finish().unwrap()), (2, gzip(&dtb))] {
            let out = tempfile::tempdir().unwrap();
            let image = dtbo_image(&compressed, 1, flag);
            assert_eq!(dt_table(&image, out.path(), "dtbo").unwrap(), 1);
            assert_eq!(fs::read(out.path().join("dtbo-0.dtb")).unwrap(), dtb);
        }
    }
}
