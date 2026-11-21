use serde::Serialize;
#[derive(Serialize)]
pub struct Tool {
    name: String,
    installed: bool,
    version: String,
}
#[tauri::command]
pub async fn check_tools() -> Result<Vec<Tool>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        [
            "adb",
            "fastboot",
            "payload-dumper-go",
            "debugfs",
            "e2fsck",
            "resize2fs",
            "img2simg",
            "xz",
            "fsck.erofs",
            "dump.erofs",
            "unpack_bootimg",
            "unpackbootimg",
            "dtc",
            "patchelf",
            "binwalk",
            "analyzeHeadless",
            "rizin",
            "r2",
            "edl",
            "heimdall",
            "lsusb",
        ]
        .iter()
        .map(|name| {
            let result = std::process::Command::new(name)
                .arg(if *name == "adb" {
                    "version"
                } else {
                    "--version"
                })
                .output();
            match result {
                Ok(o) => Tool {
                    name: name.to_string(),
                    installed: true,
                    version: format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    )
                    .lines()
                    .next()
                    .unwrap_or("Available")
                    .to_string(),
                },
                Err(_) => Tool {
                    name: name.to_string(),
                    installed: false,
                    version: "not installed".into(),
                },
            }
        })
        .collect()
    })
    .await
    .map_err(|e| e.to_string())
}
