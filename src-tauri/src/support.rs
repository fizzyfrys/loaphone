pub fn lookup(codename: &str) -> serde_json::Value {
    let devices: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../devices.json")).expect("Built-in device table");
    devices
        .into_iter()
        .find(|d| d["codename"].as_str() == Some(&codename.to_lowercase()))
        .unwrap_or_else(
            || serde_json::json!({"codename":codename,"tier":"experimental","mainline":false}),
        )
}
#[tauri::command]
pub fn device_support(codename: String) -> serde_json::Value {
    lookup(&codename)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tiers() {
        assert_eq!(lookup("enchilada")["tier"], 1);
        assert_eq!(lookup("fajita")["mainline"], true);
        assert_eq!(lookup("sunfish")["mainline"], false);
        assert_eq!(lookup("")["tier"], "experimental");
    }
}
