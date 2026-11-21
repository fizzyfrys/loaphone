use crate::common::{command, log, workspace};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub struct FlashParams {
    pub serial: String,
    pub codename: String,
    pub distro: String,
    pub slot: String,
    pub boot: String,
    pub dtbo: Option<String>,
    pub vendor_boot: Option<String>,
    pub rootfs: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub params: FlashParams,
    pub commands: Vec<Vec<String>>,
    pub warning: String,
}
fn validate(p: &FlashParams) -> Result<(), String> {
    if p.serial.is_empty() || p.serial.starts_with('-') || p.serial.chars().any(char::is_whitespace)
    {
        return Err("Select a valid device serial".into());
    }
    if p.codename.is_empty()
        || !p
            .codename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Enter the device codename".into());
    }
    if !["a", "b", "A-only"].contains(&p.slot.as_str()) {
        return Err("Select a valid slot layout".into());
    }
    if ![
        "postmarketOS",
        "postmarketOS (server, headless)",
        "Droidian",
        "Ubuntu Touch",
    ]
    .contains(&p.distro.as_str())
    {
        return Err("Unknown distro".into());
    }
    if p.boot.is_empty() || p.rootfs.is_empty() {
        return Err("Boot and rootfs images are required".into());
    }
    Ok(())
}
pub fn build_plan(p: FlashParams) -> Result<Plan, String> {
    validate(&p)?;
    let mut commands = vec![];
    for (part, image) in [
        ("boot", Some(p.boot.clone())),
        ("dtbo", p.dtbo.clone()),
        ("vendor_boot", p.vendor_boot.clone()),
        ("userdata", Some(p.rootfs.clone())),
    ] {
        if let Some(image) = image.filter(|s| !s.is_empty()) {
            let partition = if part != "userdata" && p.slot != "A-only" {
                format!("{part}_{}", p.slot)
            } else {
                part.into()
            };
            commands.push(vec![
                "fastboot".into(),
                "-s".into(),
                p.serial.clone(),
                "flash".into(),
                partition,
                image,
            ]);
        }
    }
    Ok(Plan{params:p,commands,warning:"Device-specific images only. Writing userdata destroys existing data. This generic plan is not a device port or a compatibility guarantee. No automatic reboot.".into()})
}
#[tauri::command]
pub fn recommend_track(codename: String) -> serde_json::Value {
    let mainline = [
        "beryllium",
        "enchilada",
        "fajita",
        "pocophone-f1",
        "dragonboard410c",
        "msm8916",
        "sdm845",
        "sdm660",
        "lavender",
    ];
    let support = crate::support::lookup(&codename);
    let supported = support["mainline"].as_bool().unwrap_or(false)
        || mainline.contains(&codename.to_lowercase().as_str());
    serde_json::json!({"track":if supported{"Track 2: Mainline / postmarketOS"}else{"Track 1: Halium / libhybris"},"distro":if supported{"postmarketOS"}else{"Droidian"},"support":support,"note":"Heuristic only. Tier 1 means a research target, not guaranteed Linux support. Verify current device wiki and exact images before flashing."})
}
#[tauri::command]
pub fn flash_plan(params: FlashParams) -> Result<Plan, String> {
    build_plan(params)
}
#[tauri::command]
pub async fn preflight(
    app: tauri::AppHandle,
    serial: String,
    codename: String,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w=workspace(&app,&codename)?;let mut backups=vec![];
        let props=command("adb", &["-s",&serial,"shell","getprop"]);
        let (battery,unlocked)=if let Ok(props)=props {
            let p=crate::device::parse_getprop(&props);let b=command("adb", &["-s",&serial,"shell","dumpsys","battery"]).unwrap_or_default();
            let battery=b.lines().find_map(|l|l.trim().strip_prefix("level:").and_then(|s|s.trim().parse::<u32>().ok()));
            if command("adb", &["-s",&serial,"shell","su","-c","id"]).map(|s|s.contains("uid=0")).unwrap_or(false){
                let dest=w.join("backup");std::fs::create_dir_all(&dest).map_err(|e|e.to_string())?;
                for part in ["efs","persist","modemst1","modemst2"] {
                    let remote=format!("/data/local/tmp/loaphone-{part}.img");
                    let result=command("adb", &["-s",&serial,"shell",&format!("su -c 'dd if=/dev/block/by-name/{part} of={remote}'")]).and_then(|_|command("adb", &["-s",&serial,"pull",&remote,dest.join(format!("{part}.img")).to_str().ok_or("Invalid path")?]));
                    backups.push(format!("{part}: {}",match result{Ok(_)=>"backed up".into(),Err(e)=>format!("skipped: {e}")}));
                }
            }else{backups.push("Skipped backups: root unavailable".into());}
            (battery,p.get("ro.boot.flash.locked").map(|s|s=="0").unwrap_or(false))
        }else{
            let p=crate::device::parse_getvar(&command("fastboot", &["-s",&serial,"getvar","all"])?);
            backups.push("Skipped backups: device is in fastboot, adb root required".into());
            (p.get("battery-soc-ok").and_then(|_|None::<u32>),p.get("unlocked").map(|s|s=="yes"||s=="true").unwrap_or(false))
        };
        let user_backup=w.join("backup/user-data/summary.json").is_file();
        Ok(serde_json::json!({"battery":battery,"battery_ok":battery.map(|b|b>50).unwrap_or(false),"unlocked":unlocked,"backups":backups,"user_backup":user_backup,"backup_warning":if user_backup{"Verify your backup before continuing"}else{"No user data backup found. Use Backup my data before flashing."},"note":"Unknown battery level is not a pass. Fastboot voltage cannot reliably determine percentage."}))
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn run_flash(
    app: tauri::AppHandle,
    plan: Plan,
    confirm_token: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if confirm_token!=plan.params.codename{return Err("Confirmation must exactly match the codename".into());}
        let canonical=build_plan(plan.params.clone())?;
        if canonical.commands!=plan.commands{return Err("Plan was altered. Generate it again.".into());}
        let vars=crate::device::parse_getvar(&command("fastboot", &["-s",&plan.params.serial,"getvar","all"])?);
        if !vars.get("unlocked").map(|s|s=="yes"||s=="true").unwrap_or(false){return Err("Bootloader unlock not verified".into());}
        if vars.get("product")!=Some(&confirm_token){return Err("Connected fastboot product does not match codename".into());}
        let battery=vars.get("battery-level").and_then(|s|s.trim_end_matches('%').parse::<u32>().ok());
        if !battery.map(|n|n>50).unwrap_or(false){return Err("Fastboot battery percentage must be known and above 50%. This device may require manual flashing using port instructions.".into());}
        for c in &canonical.commands {if !std::path::Path::new(c.last().unwrap()).is_file(){return Err(format!("Image not found: {}",c.last().unwrap()));}}
        for c in canonical.commands {log(&app,"flash",c.join(" "));let args:Vec<&str>=c[1..].iter().map(String::as_str).collect();crate::common::command_logged(&app,"flash","fastboot",&args)?;}
        Ok("Flash complete. Review the log before manually rebooting.".into())
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn verify_boot() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(|| {
        std::net::TcpStream::connect_timeout(
            &"172.16.42.1:22".parse().unwrap(),
            std::time::Duration::from_secs(4),
        )
        .map(|_| "SSH port reachable at 172.16.42.1:22".into())
        .map_err(|e| format!("SSH not reachable: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    fn params() -> FlashParams {
        FlashParams {
            serial: "abc".into(),
            codename: "beryllium".into(),
            distro: "postmarketOS".into(),
            slot: "a".into(),
            boot: "boot.img".into(),
            dtbo: None,
            vendor_boot: None,
            rootfs: "rootfs.img".into(),
        }
    }
    #[test]
    fn plan() {
        let p = build_plan(params()).unwrap();
        assert_eq!(p.commands[0][4], "boot_a");
        assert_eq!(p.commands[1][4], "userdata");
        let mut p = params();
        p.slot = "A-only".into();
        p.dtbo = Some("dtbo.img".into());
        assert_eq!(build_plan(p).unwrap().commands[1][4], "dtbo");
    }
    #[test]
    fn invalid() {
        let mut p = params();
        p.boot.clear();
        assert!(build_plan(p).is_err());
        let mut p = params();
        p.slot = "all".into();
        assert!(build_plan(p).is_err());
    }
}
