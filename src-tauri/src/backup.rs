use crate::common::{command, log, workspace};
use std::{fs, path::Path};
fn save_command(
    app: &tauri::AppHandle,
    serial: &str,
    dir: &Path,
    name: &str,
    args: &[&str],
) -> serde_json::Value {
    let mut adb = vec!["-s", serial, "shell"];
    adb.extend(args);
    match command("adb", &adb) {
        Ok(s) => match fs::write(dir.join(name), s) {
            Ok(_) => {
                log(app, "dump", format!("Saved {name}"));
                serde_json::json!({"file":name,"status":"saved"})
            }
            Err(e) => serde_json::json!({"file":name,"status":e.to_string()}),
        },
        Err(e) => {
            log(app, "dump", format!("{name}: {e}"));
            serde_json::json!({"file":name,"status":e})
        }
    }
}
#[tauri::command]
pub async fn hardware_dump(app: tauri::AppHandle, serial: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let codename=command("adb", &["-s",&serial,"shell","getprop","ro.product.device"])?;
        let w=workspace(&app,codename.trim())?;let dir=w.join("dump");fs::create_dir_all(&dir).map_err(|e|e.to_string())?;let mut results=vec![];
        for (name,args) in [
            ("getprop.txt",vec!["getprop"]),("cpuinfo.txt",vec!["cat","/proc/cpuinfo"]),("meminfo.txt",vec!["cat","/proc/meminfo"]),("partitions.txt",vec!["cat","/proc/partitions"]),
            ("block-map.txt",vec!["ls -l /dev/block/by-name /dev/block/platform/*/by-name"]),("dmesg.txt",vec!["su","-c","dmesg"]),("modules.txt",vec!["cat","/proc/modules"]),
            ("init-root.txt",vec!["cat /init*.rc /ueventd*.rc"]),("vendor-build.prop",vec!["cat","/vendor/build.prop"]),("hardware-libs.txt",vec!["ls -l /vendor/lib/hw /vendor/lib64/hw"])
        ] {results.push(save_command(&app,&serial,&dir,name,&args));}
        for (source,name) in [("/proc/config.gz","config.gz"),("/sys/firmware/devicetree/base","devicetree"),("/vendor/etc/vintf","vintf"),("/vendor/etc/init","init"),("/vendor/ueventd.rc","ueventd.rc")] {
            log(&app,"dump",format!("Reading {source}"));let r=command("adb", &["-s",&serial,"pull",source,dir.join(name).to_str().ok_or("Invalid path")?]);results.push(serde_json::json!({"file":name,"status":r.map(|_|"saved".into()).unwrap_or_else(|e|format!("skipped: {e}"))}));
        }
        fs::write(dir.join("summary.json"),serde_json::to_vec_pretty(&serde_json::json!({"codename":codename.trim(),"serial":serial,"items":results})).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        Ok(dir.display().to_string())
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn export_dump(app: tauri::AppHandle, codename: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &codename)?;
        let dir = w.join("dump");
        if !dir.join("summary.json").is_file() {
            return Err("Collect a hardware dump first".into());
        }
        let dest = w.join(format!("{codename}-dump.zip"));
        let mut zip = zip::ZipWriter::new(fs::File::create(&dest).map_err(|e| e.to_string())?);
        for e in walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_map(Result::ok)
        {
            if e.file_type().is_file() {
                zip.start_file(
                    e.path()
                        .strip_prefix(&dir)
                        .map_err(|e| e.to_string())?
                        .to_string_lossy(),
                    zip::write::SimpleFileOptions::default(),
                )
                .map_err(|e| e.to_string())?;
                std::io::copy(
                    &mut fs::File::open(e.path()).map_err(|e| e.to_string())?,
                    &mut zip,
                )
                .map_err(|e| e.to_string())?;
            }
        }
        zip.finish().map_err(|e| e.to_string())?;
        Ok(dest.display().to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
pub fn parse_content_rows(s: &str) -> Vec<serde_json::Value> {
    let mut rows: Vec<String> = Vec::new();
    for line in s.lines() {
        if line.starts_with("Row: ") {
            rows.push(line.to_owned());
        } else if let Some(row) = rows.last_mut() {
            row.push('\n');
            row.push_str(line);
        }
    }
    rows.into_iter().map(|row| serde_json::json!({"raw":row})).collect()
}
#[tauri::command]
pub async fn backup_data(
    app: tauri::AppHandle,
    serial: String,
    codename: String,
    folders: Vec<String>,
    include_apks: bool,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w=workspace(&app,&codename)?;let dir=crate::common::backup_dir(&w,&serial)?.join("user-data");fs::create_dir_all(&dir).map_err(|e|e.to_string())?;let mut results=vec![];let mut saved=0;
        for name in folders {if !["DCIM","Pictures","Movies","Music","Documents","Download"].contains(&name.as_str()){return Err("Invalid backup folder".into());}log(&app,"backup",format!("Copying {name}"));let r=command("adb", &["-s",&serial,"pull",&format!("/sdcard/{name}"),dir.join(&name).to_str().ok_or("Invalid path")?]);if r.is_ok(){saved+=1;}results.push(serde_json::json!({"source":name,"status":r.map(|_|"saved".into()).unwrap_or_else(|e|e)}));}
        for (name,uri) in [("contacts","content://com.android.contacts/data"),("sms","content://sms"),("calls","content://call_log/calls")] {
            log(&app,"backup",format!("Exporting {name}; Android may deny access"));
            match command("adb", &["-s",&serial,"shell","content","query","--uri",uri]) {Ok(s)=>{if s.contains("Exception")||s.contains("Permission Denial"){results.push(serde_json::json!({"source":name,"status":"permission denied"}));continue;}let rows=parse_content_rows(&s);fs::write(dir.join(format!("{name}.json")),serde_json::to_vec_pretty(&rows).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;saved+=1;results.push(serde_json::json!({"source":name,"status":"saved","rows":rows.len()}));},Err(e)=>results.push(serde_json::json!({"source":name,"status":e}))}
        }
        let packages=command("adb", &["-s",&serial,"shell","pm","list","packages","-3"])?;fs::write(dir.join("packages.txt"),&packages).map_err(|e|e.to_string())?;
        if include_apks {for package in packages.lines().filter_map(|l|l.strip_prefix("package:")) {if !package.chars().all(|c|c.is_ascii_alphanumeric()||c=='.'||c=='_'){continue;}log(&app,"backup",format!("Copying APKs: {package}"));if let Ok(paths)=command("adb", &["-s",&serial,"shell","pm","path",package]){for (i,path) in paths.lines().filter_map(|l|l.strip_prefix("package:")).enumerate(){let r=command("adb", &["-s",&serial,"pull",path,dir.join(format!("{package}-{i}.apk")).to_str().ok_or("Invalid path")?]);if let Err(e)=r{log(&app,"backup",e);}}}}}
        let summary=serde_json::json!({"serial":serial,"items":results,"saved_items":saved,"warning":"Not a full Android backup. Private app data, keys and DRM are excluded. Verify files independently."});fs::write(dir.join("summary.json"),serde_json::to_vec_pretty(&summary).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        if saved==0{return Err("No user content could be backed up. Review device permissions and the log.".into());}Ok(dir.display().to_string())
    }).await.map_err(|e|e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_rows() {
        assert_eq!(
            parse_content_rows("Row: 0 name=Alice\nRow: 1 name=Bob").len(),
            2
        );
        assert!(parse_content_rows("Permission Denial").is_empty());
        let rows = parse_content_rows("Header\nRow: 0 body=hello\nworld\n\nlast\nRow: 1 body=next\ncontinued");
        assert_eq!(rows[0]["raw"], "Row: 0 body=hello\nworld\n\nlast");
        assert_eq!(rows[1]["raw"], "Row: 1 body=next\ncontinued");
        assert!(parse_content_rows("").is_empty());
    }
}
