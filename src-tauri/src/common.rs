use std::{path::PathBuf, process::Command};
use tauri::{Emitter, Manager};

pub fn workspace(app: &tauri::AppHandle, codename: &str) -> Result<PathBuf, String> {
    if codename.is_empty()
        || !codename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Use a codename containing letters, digits, hyphens or underscores".into());
    }
    let p = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("workspace"))
        .join(codename);
    std::fs::create_dir_all(p.join("blobs")).map_err(|e| e.to_string())?;
    Ok(p)
}
pub fn log(app: &tauri::AppHandle, stage: &str, line: impl AsRef<str>) {
    let _ = app.emit(
        "log",
        serde_json::json!({"stage":stage,"line":line.as_ref()}),
    );
}
pub fn command(tool: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(tool).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("{tool} is not installed")
        } else {
            e.to_string()
        }
    })?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("{tool}: {text}"))
    }
}
pub fn command_logged(
    app: &tauri::AppHandle,
    stage: &str,
    tool: &str,
    args: &[&str],
) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = Command::new(tool)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("{tool} is not installed")
            } else {
                e.to_string()
            }
        })?;
    let stdout = child.stdout.take().ok_or("No stdout")?;
    let stderr = child.stderr.take().ok_or("No stderr")?;
    std::thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                log(app, stage, line);
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                log(app, stage, line);
            }
        });
    });
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{tool} failed with {status}. Review activity log."))
    }
}
