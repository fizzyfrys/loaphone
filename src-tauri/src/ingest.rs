use crate::common::{command, log, workspace};
use std::{fs, path::Path};

fn extract_image(app: &tauri::AppHandle, image: &Path, out: &Path) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let data = fs::read(image).map_err(|e| e.to_string())?;
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
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
                let safe = entry
                    .enclosed_name()
                    .ok_or("Unsafe archive path")?
                    .to_owned();
                let name = safe.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if entry.is_dir()
                    || !(name.ends_with(".img")
                        || name == "payload.bin"
                        || name == "proprietary-files.txt")
                {
                    continue;
                }
                let dest = images.join(&safe);
                fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
                std::io::copy(
                    &mut entry,
                    &mut fs::File::create(&dest).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                if name == "payload.bin" {
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
