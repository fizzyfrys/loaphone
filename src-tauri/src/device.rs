use crate::common::command;
use serde::Serialize;
use std::collections::BTreeMap;
#[derive(Serialize)]
pub struct Device {
    pub serial: String,
    pub mode: String,
    pub detail: String,
}
pub fn parse_devices(text: &str, mode: &str) -> Vec<Device> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let serial = parts.next()?;
            let state = parts.next()?;
            if serial == "List" || serial.starts_with('*') {
                return None;
            }
            Some(Device {
                serial: serial.into(),
                mode: if mode == "fastboot" {
                    mode.into()
                } else {
                    state.into()
                },
                detail: parts.collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}
pub fn parse_getprop(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once("]: [")?;
            Some((
                k.trim_start_matches('[').into(),
                v.trim_end_matches(']').into(),
            ))
        })
        .collect()
}
pub fn parse_getvar(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l
                .trim()
                .trim_start_matches("(bootloader)")
                .trim()
                .split_once(':')?;
            Some((k.trim().into(), v.trim().into()))
        })
        .collect()
}
#[tauri::command]
pub async fn list_devices() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut devices = vec![];
        let mut warnings = vec![];
        for (tool, args) in [
            ("adb", vec!["devices", "-l"]),
            ("fastboot", vec!["devices"]),
        ] {
            match command(tool, &args) {
                Ok(s) => devices.extend(parse_devices(&s, tool)),
                Err(e) => warnings.push(e),
            }
        }
        serde_json::json!({"devices":devices,"warnings":warnings})
    })
    .await
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn profile_device(serial: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if let Ok(props) = command("adb", &["-s",&serial,"shell","getprop"]) {
            let p = parse_getprop(&props);
            let get = |k:&str| p.get(k).cloned().unwrap_or_default();
            let battery = command("adb", &["-s",&serial,"shell","dumpsys","battery"]).unwrap_or_default();
            let level = battery.lines().find_map(|l|l.trim().strip_prefix("level:").map(str::trim)).unwrap_or("unknown");
            let root = command("adb", &["-s",&serial,"shell","su","-c","id"]).map(|s|s.contains("uid=0")).unwrap_or(false);
            Ok(serde_json::json!({"serial":serial,"codename":get("ro.product.device"),"model":get("ro.product.model"),"manufacturer":get("ro.product.manufacturer"),"soc":p.get("ro.board.platform").or(p.get("ro.hardware")),"android":get("ro.build.version.release"),"sdk":get("ro.build.version.sdk"),"slot":get("ro.boot.slot_suffix"),"layout":if get("ro.build.ab_update")=="true" {"A/B"}else{"A-only"},"locked":get("ro.boot.flash.locked"),"verified_boot":get("ro.boot.verifiedbootstate"),"battery":level,"root":root}))
        } else {
            let p=parse_getvar(&command("fastboot", &["-s",&serial,"getvar","all"])?);
            Ok(serde_json::json!({"serial":serial,"codename":p.get("product"),"unlocked":p.get("unlocked"),"slot":p.get("current-slot"),"slot_count":p.get("slot-count"),"battery_voltage":p.get("battery-voltage"),"mode":"fastboot"}))
        }
    }).await.map_err(|e|e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devices() {
        assert_eq!(
            parse_devices("List of devices attached\nabc device product:x\n", "adb")[0].serial,
            "abc"
        );
        assert!(parse_devices("", "adb").is_empty());
    }
    #[test]
    fn getprop() {
        assert_eq!(
            parse_getprop("[ro.product.device]: [beryllium]")["ro.product.device"],
            "beryllium"
        );
        assert!(parse_getprop("bad").is_empty());
    }
    #[test]
    fn getvar() {
        assert_eq!(
            parse_getvar("(bootloader) current-slot: a")["current-slot"],
            "a"
        );
        assert!(parse_getvar("").is_empty());
    }
}
