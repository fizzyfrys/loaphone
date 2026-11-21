use crate::common::{command, log, workspace};
use std::{fs, path::Path};
use std::io::{Read, Result as IoResult};

fn import_zip<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    images: &Path,
    blobs: &Path,
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut imported = 0;
    let mut payloads = Vec::new();
    let mut destinations = std::collections::BTreeSet::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let safe = entry.enclosed_name().ok_or("Unsafe archive path")?.to_owned();
        if entry.is_dir() {
            continue;
        }
        let name = safe.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let partition = name.ends_with(".img") || name == "payload.bin" || name == "proprietary-files.txt";
        let extension = safe.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let firmware = ["mbn", "bin", "fw", "mdt", "ucode", "dtb"].contains(&extension.as_str())
            || (extension.len() == 3 && extension.starts_with('b') && extension[1..].chars().all(|c| c.is_ascii_hexdigit()));
        let mut header = Vec::new();
        (&mut entry).take(4).read_to_end(&mut header).map_err(|e| e.to_string())?;
        if !partition && extension != "so" && !header.starts_with(b"\x7fELF") && !firmware {
            continue;
        }
        let root = if partition { images } else { blobs };
        let relative = if !partition && firmware && !header.starts_with(b"\x7fELF")
            && !safe.components().any(|part| part.as_os_str() == "firmware")
        {
            Path::new("loose-firmware").join(&safe)
        } else {
            safe.clone()
        };
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let dest = root.join(&relative);
        let mut current = root;
        for component in relative.components() {
            current.push(component);
            if fs::symlink_metadata(&current).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                return Err("Unsafe archive destination: symbolic link".into());
            }
        }
        fs::create_dir_all(dest.parent().ok_or("Invalid archive path")?).map_err(|e| e.to_string())?;
        let destination = if dest.exists() {
            dest.canonicalize().map_err(|e| e.to_string())?
        } else {
            dest.parent().ok_or("Invalid archive path")?.canonicalize().map_err(|e| e.to_string())?
                .join(dest.file_name().ok_or("Invalid archive path")?)
        };
        if !destinations.insert(destination) {
            return Err(format!("Duplicate archive destination: {}", dest.display()));
        }
        let mut output = fs::File::create(&dest).map_err(|e| e.to_string())?;
        std::io::copy(&mut std::io::Cursor::new(header).chain(&mut entry), &mut output).map_err(|e| e.to_string())?;
        imported += 1;
        if name == "payload.bin" {
            payloads.push(dest);
        }
    }
    if imported == 0 {
        return Err("No importable files found in ROM ZIP. Expected partition images, payload.bin, proprietary-files.txt, loose .so/ELF libraries or firmware.".into());
    }
    Ok(payloads)
}

fn image_header(reader: impl Read) -> IoResult<Vec<u8>> {
    let mut header = Vec::with_capacity(1082);
    reader.take(1082).read_to_end(&mut header)?;
    Ok(header)
}

fn extract_image(app: &tauri::AppHandle, image: &Path, out: &Path) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let data = image_header(fs::File::open(image).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let image = image.to_str().ok_or("Invalid image path")?;
    let out = out.to_str().ok_or("Invalid output path")?;
    let result = if data.get(1024..1028) == Some(&[0xe2, 0xe1, 0xf5, 0xe0]) {
        command("fsck.erofs", &[&format!("--extract={out}"), image])
    } else if data.get(1080..1082) == Some(&[0x53, 0xef]) {
        if out.contains('"') {
            return Err("Output path cannot contain quotes".into());
        }
        command("debugfs", &["-R", &format!("rdump / \"{out}\""), image])
    } else {
        log(
            app,
            "ingest",
            format!(
                "Retained {image}; not an ext4 or erofs filesystem (boot and sparse images need external unpacking)"
            ),
        );
        return Ok(());
    };
    log(app, "ingest", result?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    struct ArchiveTest(std::path::PathBuf);
    impl ArchiveTest {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!("loaphone-ingest-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn import(&self, entries: &[(&str, &[u8])]) -> Result<Vec<std::path::PathBuf>, String> {
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            for (name, data) in entries {
                writer.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                writer.write_all(data).unwrap();
            }
            let mut zip = zip::ZipArchive::new(writer.finish().unwrap()).unwrap();
            import_zip(&mut zip, &self.0.join("images"), &self.0.join("blobs"))
        }
    }
    impl Drop for ArchiveTest {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn loose_libraries_and_firmware() {
        let test = ArchiveTest::new();
        let entries: &[(&str, &[u8])] = &[
            ("vendor/lib64/libcamera.so", b"\x7fELFcamera"),
            ("vendor/lib/libversion.so.1", b"\x7fELFversion"),
            ("vendor/bin/helper", b"\x7fELFhelper"),
            ("vendor/firmware/radio.mbn", b"firmware"),
            ("vendor/firmware/modem.b01", b"segment"),
            ("README.txt", b"unsupported"),
        ];
        assert!(test.import(entries).unwrap().is_empty());
        for (name, data) in &entries[..5] {
            assert_eq!(fs::read(test.0.join("blobs").join(name)).unwrap(), *data);
        }
        assert!(!test.0.join("blobs/README.txt").exists());
    }

    #[test]
    fn empty_and_unsupported_archives_warn() {
        let test = ArchiveTest::new();
        fs::create_dir_all(test.0.join("images")).unwrap();
        fs::write(test.0.join("images/stale.img"), b"old image").unwrap();
        for entries in [vec![], vec![("README.txt", &b"unsupported"[..])]] {
            assert!(test.import(&entries).unwrap_err().contains("No importable files found in ROM ZIP"));
        }
    }

    #[test]
    fn root_firmware_is_recognized_by_rea() {
        let test = ArchiveTest::new();
        test.import(&[("modem.bin", b"modem firmware")]).unwrap();
        let relative = Path::new("loose-firmware/modem.bin");
        assert_eq!(fs::read(test.0.join("blobs").join(relative)).unwrap(), b"modem firmware");
        assert!(crate::rea::firmware(relative.to_str().unwrap()));
        assert!(!test.0.join("blobs/modem.bin").exists());
    }

    #[test]
    fn root_and_nested_firmware_do_not_collide() {
        let test = ArchiveTest::new();
        test.import(&[("modem.bin", b"loose modem"), ("firmware/modem.bin", b"nested modem")]).unwrap();
        assert_eq!(fs::read(test.0.join("blobs/loose-firmware/modem.bin")).unwrap(), b"loose modem");
        assert_eq!(fs::read(test.0.join("blobs/firmware/modem.bin")).unwrap(), b"nested modem");
    }

    #[test]
    fn duplicate_destinations_are_rejected_before_overwrite() {
        let test = ArchiveTest::new();
        let error = test.import(&[("modem.bin", b"first"), ("./modem.bin", b"second")]).unwrap_err();
        assert!(error.contains("Duplicate archive destination"));
        assert_eq!(fs::read(test.0.join("blobs/loose-firmware/modem.bin")).unwrap(), b"first");
    }

    #[test]
    fn unsafe_archive_paths_are_rejected() {
        let test = ArchiveTest::new();
        assert!(test.import(&[("../escape.so", b"\x7fELF")]).unwrap_err().contains("Unsafe archive path"));
        assert!(!test.0.join("escape.so").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_destinations_are_rejected() {
        let test = ArchiveTest::new();
        let outside = test.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(test.0.join("blobs")).unwrap();
        std::os::unix::fs::symlink(&outside, test.0.join("blobs/vendor")).unwrap();
        assert!(test.import(&[("vendor/escape.so", b"\x7fELF")]).unwrap_err().contains("symbolic link"));
        assert!(!outside.join("escape.so").exists());
    }

    #[test]
    fn partition_files_keep_image_destination() {
        let test = ArchiveTest::new();
        let payloads = test.import(&[("rom/payload.bin", b"payload"), ("vendor.img", b"image")]).unwrap();
        assert_eq!(payloads, vec![test.0.join("images/rom/payload.bin").canonicalize().unwrap()]);
        assert_eq!(fs::read(test.0.join("images/vendor.img")).unwrap(), b"image");
    }

    #[test]
    fn bounded_header() {
        let mut bytes = vec![0; 4096];
        bytes[1080..1082].copy_from_slice(&[0x53, 0xef]);
        let mut reader = std::io::Cursor::new(bytes);
        let header = image_header(&mut reader).unwrap();
        assert_eq!(header.len(), 1082);
        assert_eq!(reader.position(), 1082);
        assert_eq!(&header[1080..], &[0x53, 0xef]);
        assert!(image_header(&b""[..]).unwrap().is_empty());
        assert_eq!(image_header(&b"short"[..]).unwrap(), b"short");
        struct Broken;
        impl Read for Broken { fn read(&mut self, _: &mut [u8]) -> IoResult<usize> { Err(std::io::Error::other("read failure")) } }
        assert!(image_header(Broken).is_err());
    }
}
#[tauri::command]
pub async fn ingest_archive(
    app: tauri::AppHandle,
    path: String,
    codename: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &codename)?;
        let images = w.join("images");
        fs::create_dir_all(&images).map_err(|e| e.to_string())?;
        let p = Path::new(&path);
        let mut extracted = vec![];
        log(&app, "ingest", format!("Opening {}", p.display()));
        if p.extension().and_then(|s| s.to_str()) == Some("zip") {
            let mut zip = zip::ZipArchive::new(fs::File::open(p).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            let payloads = import_zip(&mut zip, &images, &w.join("blobs")).map_err(|warning| {
                log(&app, "ingest", &warning);
                warning
            })?;
            for dest in payloads {
                log(&app, "ingest", "Extracting payload partitions");
                log(
                    &app,
                    "ingest",
                    command(
                        "payload-dumper-go",
                        &[
                            "-p",
                            "vendor,system,odm,boot",
                            "-o",
                            images.to_str().ok_or("Invalid path")?,
                            dest.to_str().ok_or("Invalid path")?,
                        ],
                    )?,
                );
            }
            for e in walkdir::WalkDir::new(&images)
                .into_iter()
                .filter_map(Result::ok)
            {
                if e.path().extension().and_then(|s| s.to_str()) == Some("img") {
                    extracted.push(e.path().to_owned());
                }
            }
        } else if p.extension().and_then(|s| s.to_str()) == Some("img") {
            let dest = images.join(p.file_name().ok_or("Invalid filename")?);
            fs::copy(p, &dest).map_err(|e| e.to_string())?;
            extracted.push(dest);
        } else {
            return Err("Select a ROM .zip or raw .img file".into());
        }
        for image in extracted {
            let name = image.file_stem().ok_or("Invalid filename")?;
            extract_image(&app, &image, &w.join("blobs").join(name))?;
        }
        log(&app, "ingest", "Source ingestion complete");
        Ok(w.display().to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn pull_from_device(
    app: tauri::AppHandle,
    serial: String,
    codename: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w=workspace(&app,&codename)?;let mut successes=0;
        for source in ["/vendor/lib","/vendor/lib64","/vendor/firmware","/vendor/etc","/firmware","/odm"] {
            let dest=w.join("blobs").join(source.trim_start_matches('/'));fs::create_dir_all(dest.parent().unwrap()).map_err(|e|e.to_string())?;
            log(&app,"pull",format!("Pulling {source}"));
            match command("adb", &["-s",&serial,"pull",source,dest.to_str().ok_or("Invalid path")?]) {Ok(s)=>{successes+=1;log(&app,"pull",s)},Err(e)=>log(&app,"pull",e)}
        }
        if command("adb", &["-s",&serial,"shell","su","-c","id"]).map(|s|s.contains("uid=0")).unwrap_or(false) {
            let slot=command("adb", &["-s",&serial,"shell","getprop","ro.boot.slot_suffix"])?;
            if !["","_a","_b"].contains(&slot.trim()) {return Err("Invalid device slot".into());}
            command("adb", &["-s",&serial,"shell",&format!("su -c 'dd if=/dev/block/by-name/boot{} of=/data/local/tmp/loaphone-boot.img'",slot.trim())])?;
            command("adb", &["-s",&serial,"pull","/data/local/tmp/loaphone-boot.img",w.join("boot.img").to_str().ok_or("Invalid path")?])?;
        } else {log(&app,"pull","Boot image skipped: root unavailable");}
        if successes==0 {return Err("No directories could be pulled. Check USB debugging and device authorization.".into());}
        Ok(w.display().to_string())
    }).await.map_err(|e|e.to_string())?
}
