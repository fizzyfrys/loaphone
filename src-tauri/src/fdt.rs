use std::io::{self, Write};

pub const MAGIC: [u8; 4] = 0xd00dfeedu32.to_be_bytes();

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Malformed flattened device tree",
    )
}

fn word(bytes: &[u8], offset: usize) -> io::Result<usize> {
    let bytes = bytes
        .get(offset..)
        .and_then(|b| b.get(..4))
        .ok_or_else(invalid)?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
}

fn region(bytes: &[u8], offset: usize, length: usize) -> io::Result<&[u8]> {
    bytes
        .get(offset..)
        .and_then(|b| b.get(..length))
        .ok_or_else(invalid)
}

fn string(bytes: &[u8]) -> io::Result<&[u8]> {
    bytes
        .split_inclusive(|&b| b == 0)
        .next()
        .and_then(|s| s.strip_suffix(&[0]))
        .ok_or_else(invalid)
}

fn name(bytes: &[u8], node: bool) -> io::Result<&str> {
    if bytes.is_empty()
        || bytes.iter().any(|&b| {
            !b.is_ascii_alphanumeric() && !b",._+?#-".contains(&b) && !(node && b == b'@')
        })
    {
        return Err(invalid());
    }
    std::str::from_utf8(bytes).map_err(|_| invalid())
}

fn value(mut out: impl Write, bytes: &[u8]) -> io::Result<()> {
    let strings = bytes.strip_suffix(&[0]).filter(|content| {
        content
            .split(|&b| b == 0)
            .all(|s| !s.is_empty() && s.iter().all(|b| (0x20..=0x7e).contains(b)))
    });
    if let Some(strings) = strings {
        for (i, s) in strings.split(|&b| b == 0).enumerate() {
            if i != 0 {
                write!(out, ", ")?;
            }
            write!(out, "\"")?;
            for &b in s {
                if b == b'\\' || b == b'"' {
                    write!(out, "\\")?;
                }
                write!(out, "{}", char::from(b))?;
            }
            write!(out, "\"")?;
        }
    } else {
        write!(out, "[")?;
        for (i, b) in bytes.iter().enumerate() {
            if i != 0 {
                write!(out, " ")?;
            }
            write!(out, "{b:02x}")?;
        }
        write!(out, "]")?;
    }
    Ok(())
}

pub fn decompile(bytes: &[u8], mut out: impl Write) -> io::Result<usize> {
    if !bytes.starts_with(&MAGIC) {
        return Err(invalid());
    }
    let size = word(bytes, 4)?;
    let bytes = region(bytes, 0, size)?;
    let structure = word(bytes, 8)?;
    let strings = word(bytes, 12)?;
    let reserve = word(bytes, 16)?;
    let version = word(bytes, 20)?;
    let header_size = if version == 16 { 36 } else { 40 };
    if version < 16
        || word(bytes, 24)? > 17
        || structure % 4 != 0
        || reserve % 8 != 0
        || [structure, strings, reserve]
            .iter()
            .any(|&offset| offset < header_size)
    {
        return Err(invalid());
    }
    let structure_length = if version == 16 {
        [strings, reserve, size]
            .into_iter()
            .filter(|&offset| offset > structure)
            .min()
            .ok_or_else(invalid)?
            - structure
    } else {
        word(bytes, 36)?
    };
    let structure_bytes = region(bytes, structure, structure_length)?;
    let strings_length = word(bytes, 32)?;
    let strings_bytes = region(bytes, strings, strings_length)?;
    if structure < strings + strings_length && strings < structure + structure_length {
        return Err(invalid());
    }
    if (structure..structure + structure_length).contains(&reserve)
        || (strings..strings + strings_length).contains(&reserve)
    {
        return Err(invalid());
    }
    let end = [structure, strings, size]
        .into_iter()
        .filter(|&offset| offset > reserve)
        .min()
        .ok_or_else(invalid)?;
    writeln!(out, "/dts-v1/;")?;
    let (entries, _) = region(bytes, reserve, end - reserve)?.as_chunks::<16>();
    for entry in entries {
        let address = u64::from_be_bytes(entry[..8].try_into().unwrap());
        let length = u64::from_be_bytes(entry[8..].try_into().unwrap());
        if address == 0 && length == 0 {
            return emit_structure(structure_bytes, strings_bytes, out).map(|()| size);
        }
        writeln!(out, "/memreserve/ 0x{address:x} 0x{length:x};")?;
    }
    Err(invalid())
}

fn emit_structure(structure: &[u8], strings: &[u8], mut out: impl Write) -> io::Result<()> {
    let mut remaining = structure;
    let mut depth = 0usize;
    let mut root = false;
    while !remaining.is_empty() {
        let token = word(remaining, 0)?;
        remaining = &remaining[4..];
        match token {
            1 => {
                let raw_name = string(remaining)?;
                remaining = remaining
                    .get((raw_name.len() + 1).next_multiple_of(4)..)
                    .ok_or_else(invalid)?;
                let label = if depth == 0 {
                    if root || !raw_name.is_empty() {
                        return Err(invalid());
                    }
                    root = true;
                    "/"
                } else {
                    name(raw_name, true)?
                };
                writeln!(out, "{:width$}{label} {{", "", width = 4 * depth.min(16))?;
                depth += 1;
            }
            2 if depth > 0 => {
                depth -= 1;
                writeln!(out, "{:width$}}};", "", width = 4 * depth.min(16))?;
            }
            3 if depth > 0 => {
                let len = word(remaining, 0)?;
                let offset = word(remaining, 4)?;
                let property = name(string(strings.get(offset..).ok_or_else(invalid)?)?, false)?;
                let bytes = region(remaining, 8, len)?;
                remaining = remaining
                    .get(8 + len.next_multiple_of(4)..)
                    .ok_or_else(invalid)?;
                write!(out, "{:width$}{property}", "", width = 4 * depth.min(16))?;
                if !bytes.is_empty() {
                    write!(out, " = ")?;
                    value(&mut out, bytes)?;
                }
                writeln!(out, ";")?;
            }
            4 => {}
            9 if root && depth == 0 => return Ok(()),
            _ => return Err(invalid()),
        }
    }
    Err(invalid())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> Vec<u8> {
        let strings = b"compatible\0reg\0enabled\0";
        let mut structure = Vec::new();
        for w in [1u32, 0, 3, 9, 0] {
            structure.extend(w.to_be_bytes());
        }
        structure.extend(b"test,rom\0\0\0\0");
        structure.extend(1u32.to_be_bytes());
        structure.extend(b"node@0\0\0");
        for w in [3u32, 4, 11, 0x01020304, 3, 0, 15, 2, 2, 9] {
            structure.extend(w.to_be_bytes());
        }
        let struct_offset = 72;
        let strings_offset = struct_offset + structure.len() as u32;
        let mut dtb = Vec::from(MAGIC);
        for w in [
            strings_offset + strings.len() as u32,
            struct_offset,
            strings_offset,
            40,
            17,
            16,
            0,
            strings.len() as u32,
            structure.len() as u32,
        ] {
            dtb.extend(w.to_be_bytes());
        }
        for w in [0x1000u64, 0x100, 0, 0] {
            dtb.extend(w.to_be_bytes());
        }
        dtb.extend(structure);
        dtb.extend(strings);
        dtb
    }

    #[test]
    fn decompiles_fdt_with_reservations_nodes_and_properties() {
        let dtb = sample();
        let mut dts = Vec::new();
        assert_eq!(decompile(&dtb, &mut dts).unwrap(), dtb.len());
        assert_eq!(
            String::from_utf8(dts).unwrap(),
            "/dts-v1/;\n/memreserve/ 0x1000 0x100;\n/ {\n    compatible = \"test,rom\";\n    node@0 {\n        reg = [01 02 03 04];\n        enabled;\n    };\n};\n",
        );
        assert!(decompile(&dtb[..dtb.len() - 1], io::sink()).is_err());
    }
}
