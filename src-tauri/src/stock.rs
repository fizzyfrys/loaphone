use crate::common::{command, log, workspace};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
fn archive_key(path: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
#[derive(Serialize, Deserialize)]
pub struct StockPlan {
    pub vendor: String,
    pub codename: String,
    pub serial: String,
    pub commands: Vec<Vec<String>>,
    pub note: String,
}
pub fn parse_edl(text: &str) -> bool {
    text.lines().any(|l| l.to_lowercase().contains("05c6:9008"))
}
#[tauri::command]
pub async fn detect_edl() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        command("lsusb", &[]).map(|s| serde_json::json!({"detected":parse_edl(&s),"detail":s}))
    })
    .await
    .map_err(|e| e.to_string())?
}
fn unzip(source: &Path, dest: &Path) -> Result<(), String> {
    let mut z = zip::ZipArchive::new(fs::File::open(source).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| e.to_string())?;
        let safe = e.enclosed_name().ok_or("Unsafe archive path")?.to_owned();
        let p = dest.join(safe);
        if e.is_dir() {
            fs::create_dir_all(&p).map_err(|e| e.to_string())?;
        } else {
            fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            std::io::copy(&mut e, &mut fs::File::create(p).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
#[tauri::command]
pub async fn stock_plan(
    app: tauri::AppHandle,
    vendor: String,
    codename: String,
    serial: String,
    path: String,
) -> Result<StockPlan, String> {
    tauri::async_runtime::spawn_blocking(move||{
        let w=workspace(&app,&codename)?;if serial.is_empty()||serial.starts_with('-'){return Err("Enter a device serial".into());}
        let mut commands=vec![];
        if vendor=="Pixel" {
            let source=Path::new(&path).canonicalize().map_err(|e|e.to_string())?;
            let imports=w.join("stock");fs::create_dir_all(&imports).map_err(|e|e.to_string())?;
            let dir=imports.join(archive_key(&source));
            if dir.exists(){fs::remove_dir_all(&dir).map_err(|e|e.to_string())?;}
            fs::create_dir(&dir).map_err(|e|e.to_string())?;unzip(&source,&dir)?;
            let mut bootloader=None;let mut radio=None;let mut update=None;
            for e in walkdir::WalkDir::new(&dir).into_iter().filter_map(Result::ok){if !e.file_type().is_file(){continue;}let n=e.file_name().to_string_lossy();if n.starts_with("bootloader-")&&n.ends_with(".img"){bootloader=Some(e.path().to_string_lossy().to_string());}if n.starts_with("radio-")&&n.ends_with(".img"){radio=Some(e.path().to_string_lossy().to_string());}if n.starts_with("image-")&&n.ends_with(".zip"){if !n.starts_with(&format!("image-{codename}-")){return Err("Factory image codename does not match".into());}update=Some(e.path().to_string_lossy().to_string());}}
            let update=update.ok_or("No image-<codename>-*.zip found in factory archive")?;
            for (part,image) in [("bootloader",bootloader),("radio",radio)]{if let Some(image)=image{commands.push(vec!["fastboot".into(),"-s".into(),serial.clone(),"flash".into(),part.into(),image]);commands.push(vec!["fastboot".into(),"-s".into(),serial.clone(),"reboot-bootloader".into()]);}}
            commands.push(vec!["fastboot".into(),"-s".into(),serial.clone(),"-w".into(),"update".into(),update]);
        }else if vendor=="OnePlus" {
            let dir=Path::new(&path);if !dir.join("rawprogram0.xml").is_file()||!dir.join("patch0.xml").is_file(){return Err("Select an extracted, compatible EDL package directory containing rawprogram0.xml and patch0.xml. A device-specific signed programmer may also be required by edl.".into());}
            commands.push(vec!["edl".into(),"qfil".into(),dir.join("rawprogram0.xml").to_string_lossy().into(),dir.join("patch0.xml").to_string_lossy().into(),path]);
        }else if vendor=="Samsung" {
            if !Path::new(&path).is_file(){return Err("Select a compatible stock boot.img. Full stock restoration needs the device-specific partition set and is not automated.".into());}
            commands.push(vec!["heimdall".into(),"flash".into(),"--BOOT".into(),path]);
        }else{return Err("Unsupported vendor".into());}
        let plan=StockPlan{vendor,codename,serial,commands,note:"Preview only until confirmed. These operations can erase data or brick a mismatched device. Pixel uses fastboot factory update; OnePlus needs an unlocked compatible EDL package and programmer; Samsung currently restores BOOT only. Vendor proprietary tools are not supported.".into()};
        fs::write(w.join("stock-plan.json"),serde_json::to_vec(&plan).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;Ok(plan)
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn run_stock(
    app: tauri::AppHandle,
    codename: String,
    confirm_token: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if codename != confirm_token {
            return Err("Type the codename exactly".into());
        }
        let w = workspace(&app, &codename)?;
        let plan: StockPlan = serde_json::from_slice(
            &fs::read(w.join("stock-plan.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if plan.vendor == "Pixel" {
            let vars = crate::device::parse_getvar(&command(
                "fastboot",
                &["-s", &plan.serial, "getvar", "all"],
            )?);
            if vars.get("product") != Some(&codename)
                || !vars
                    .get("unlocked")
                    .map(|s| s == "yes" || s == "true")
                    .unwrap_or(false)
            {
                return Err("Fastboot product or unlocked status does not match".into());
            }
        }
        if plan.vendor == "OnePlus" && !parse_edl(&command("lsusb", &[])?) {
            return Err("No Qualcomm EDL 9008 device detected".into());
        }
        for c in plan.commands {
            if !["fastboot", "edl", "heimdall"].contains(&c[0].as_str()) {
                return Err("Invalid restoration tool".into());
            }
            log(&app, "stock", c.join(" "));
            let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
            crate::common::command_logged(&app, "stock", &c[0], &args)?;
        }
        Ok("Stock operation finished. Review output and follow device boot instructions.".into())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn long_archive_path_key() {
        let path = format!("/home/owner/{}/factory.zip", "long-directory/".repeat(40));
        let key = archive_key(Path::new(&path));
        assert_eq!(key.len(), 16);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(key, archive_key(Path::new(&path)));
        assert_ne!(key, archive_key(Path::new("/other/factory.zip")));
    }
    #[test]
    fn edl() {
        assert!(parse_edl("Bus 001 Device 002: ID 05c6:9008 Qualcomm"));
        assert!(!parse_edl("ID 05c6:900e"));
        assert!(!parse_edl(""));
    }
}
