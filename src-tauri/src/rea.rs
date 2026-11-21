use crate::common::{command, workspace};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
#[derive(Serialize)]
pub struct Blob {
    path: String,
    arch: String,
    machine: u16,
    elf_class: u8,
    soname: Option<String>,
    needed: Vec<String>,
    rpath: Vec<String>,
    undefined: usize,
    bionic: bool,
    category: String,
    missing: Vec<String>,
}
pub fn category(path: &str) -> String {
    let p = path.to_lowercase();
    for (name, words) in [
        ("GPU", vec!["adreno", "mali", "libgles", "kgsl"]),
        ("Camera", vec!["camera.", "libmmcamera"]),
        ("Audio", vec!["audio.primary", "audio"]),
        ("Sensors", vec!["sensor"]),
        ("Wi-Fi/BT", vec!["wifi", "wlan", "bluetooth"]),
        ("Modem/RIL", vec!["modem", "ril"]),
    ] {
        if words.iter().any(|w| p.contains(w)) {
            return name.into();
        }
    }
    "Other".into()
}
fn firmware(path: &str) -> bool {
    let p = path.to_lowercase();
    let ext = Path::new(&p)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    p.contains("firmware")
        && (["mbn", "bin", "fw", "mdt", "ucode", "dtb"].contains(&ext)
            || (ext.len() == 3
                && ext.starts_with('b')
                && ext[1..].chars().all(|c| c.is_ascii_hexdigit())))
}
pub fn analyze_elf(path: &str, data: &[u8]) -> Result<Blob, String> {
    let e = goblin::elf::Elf::parse(data).map_err(|e| e.to_string())?;
    let needed: Vec<String> = e.libraries.iter().map(|s| s.to_string()).collect();
    Ok(Blob {
        path: path.into(),
        arch: goblin::elf::header::machine_to_str(e.header.e_machine).into(),
        machine: e.header.e_machine,
        elf_class: e.header.e_ident[goblin::elf::header::EI_CLASS],
        soname: e.soname.map(str::to_string),
        rpath: e
            .rpaths
            .iter()
            .chain(e.runpaths.iter())
            .map(|s| s.to_string())
            .collect(),
        undefined: e
            .dynsyms
            .iter()
            .filter(|s| s.st_shndx == 0 && s.st_name != 0)
            .count(),
        bionic: needed.iter().any(|s| {
            [
                "libc.so",
                "liblog.so",
                "libcutils.so",
                "libbinder.so",
                "libutils.so",
                "libdl.so",
                "libm.so",
            ]
            .contains(&s.as_str())
        }),
        category: category(path),
        missing: vec![],
        needed,
    })
}
fn provided_libraries(blobs: &[Blob]) -> BTreeSet<(u16, u8, String)> {
    blobs.iter().filter(|b| b.elf_class != 0).flat_map(|b| {
        [b.soname.clone(), Path::new(&b.path).file_name().map(|s| s.to_string_lossy().into_owned())]
            .into_iter().flatten().map(|name| (b.machine, b.elf_class, name))
    }).collect()
}
fn has_provider(provided: &BTreeSet<(u16, u8, String)>, blob: &Blob, name: &str) -> bool {
    provided.contains(&(blob.machine, blob.elf_class, name.to_owned()))
}
#[tauri::command]
pub async fn analyze_blobs(
    app: tauri::AppHandle,
    codename: String,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w=workspace(&app,&codename)?;let root=w.join("blobs");let mut blobs=vec![];let mut warnings=vec![];
        for entry in walkdir::WalkDir::new(&root) {
            let entry=entry.map_err(|e|e.to_string())?;if !entry.file_type().is_file(){continue;}
            let p=entry.path().strip_prefix(&root).map_err(|e|e.to_string())?.to_string_lossy().to_string();
            let data=fs::read(entry.path()).map_err(|e|e.to_string())?;
            if data.starts_with(b"\x7fELF") {match analyze_elf(&p,&data) {Ok(b)=>blobs.push(b),Err(e)=>warnings.push(format!("{p}: {e}"))}} else if firmware(&p) {blobs.push(Blob {path:p,arch:"firmware".into(),machine:0,elf_class:0,soname:None,needed:vec![],rpath:vec![],undefined:0,bionic:false,category:"Firmware".into(),missing:vec![]});}
        }
        let provided=provided_libraries(&blobs);
        let system=["libc.so","libm.so","libdl.so","liblog.so","libcutils.so","libutils.so","libbinder.so","libandroid.so","libz.so","libstdc++.so","libbase.so","libhardware.so","libsync.so","libnativewindow.so","libEGL.so","libGLESv2.so"];
        let mut counts=BTreeMap::<String,usize>::new();let mut edges=vec![];let mut missing=BTreeSet::new();
        for b in &mut blobs { *counts.entry(b.category.clone()).or_default()+=1;for n in &b.needed {let resolved=has_provider(&provided,b,n)||system.contains(&n.as_str());edges.push(serde_json::json!({"from":b.path,"to":n,"resolved":resolved}));if !resolved{b.missing.push(n.clone());missing.insert(n.clone());}} }
        let report=serde_json::json!({"counts":counts,"blobs":blobs,"edges":edges,"missing":missing,"warnings":warnings});
        fs::write(w.join("report.json"),serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;Ok(report)
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn patch_blob(
    app: tauri::AppHandle,
    codename: String,
    path: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &codename)?;
        let root = w.join("blobs").canonicalize().map_err(|e| e.to_string())?;
        let source = root.join(&path).canonicalize().map_err(|e| e.to_string())?;
        if !source.starts_with(&root) {
            return Err("Path is outside blobs".into());
        }
        let data = fs::read(&source).map_err(|e| e.to_string())?;
        let e = goblin::elf::Elf::parse(&data).map_err(|e| e.to_string())?;
        let triplet = match e.header.e_machine {
            183 => "aarch64-linux-gnu",
            40 => "arm-linux-gnueabihf",
            62 => "x86_64-linux-gnu",
            3 => "i386-linux-gnu",
            _ => return Err("Unsupported ELF architecture".into()),
        };
        let dest = w
            .join("patched")
            .join(source.strip_prefix(&root).map_err(|e| e.to_string())?);
        fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::copy(&source, &dest).map_err(|e| e.to_string())?;
        command(
            "patchelf",
            &[
                "--set-rpath",
                &format!("/usr/lib/{triplet}/android"),
                dest.to_str().ok_or("Invalid path")?,
            ],
        )?;
        Ok(dest.display().to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn carve_firmware(app: tauri::AppHandle, codename: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &codename)?;
        let root = w.join("blobs");
        let mut count = 0;
        for entry in walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() && firmware(&entry.path().to_string_lossy()) {
                let dest = w.join("lib/firmware").join(
                    entry
                        .path()
                        .strip_prefix(&root)
                        .map_err(|e| e.to_string())?,
                );
                fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
                fs::copy(entry.path(), dest).map_err(|e| e.to_string())?;
                count += 1;
            }
        }
        Ok(format!(
            "Copied {count} firmware files. {}",
            if command("binwalk", &["--version"]).is_ok() {
                "binwalk available; embedded carving is not enabled."
            } else {
                "binwalk not installed; standalone firmware copied only."
            }
        ))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn architecture_scoped_providers() {
        let mut blob = Blob { path:"vendor/lib/libexample.so".into(),arch:"ARM".into(),machine:40,elf_class:1,soname:Some("libalias.so".into()),needed:vec![],rpath:vec![],undefined:0,bionic:false,category:"Other".into(),missing:vec![] };
        let provided = provided_libraries(std::slice::from_ref(&blob));
        assert!(has_provider(&provided, &blob, "libexample.so"));
        assert!(has_provider(&provided, &blob, "libalias.so"));
        assert!(!has_provider(&provided, &blob, "absent.so"));
        assert!(!has_provider(&provided_libraries(&[]), &blob, "libexample.so"));
        blob.machine = 183;
        assert!(!has_provider(&provided, &blob, "libexample.so"));
        blob.machine = 40;
        blob.elf_class = 2;
        assert!(!has_provider(&provided, &blob, "libalias.so"));
    }
    #[test]
    fn categories() {
        assert_eq!(category("vendor/lib/libGLES_adreno.so"), "GPU");
        assert_eq!(category("camera.qcom.so"), "Camera");
        assert_eq!(category(""), "Other");
        assert!(firmware("vendor/firmware/modem.b01"));
    }
    #[test]
    fn elf() {
        if let Ok(bytes) = fs::read("/bin/ls") {
            let blob = analyze_elf("ls", &bytes).unwrap();
            assert!(!blob.needed.is_empty());
            assert!(!blob.arch.is_empty());
        }
        assert!(analyze_elf("bad", b"bad").is_err());
    }
}
