mod backup;
mod common;
mod device;
mod flash;
mod ingest;
mod overlay;
mod rea;
mod rootfs;
mod stock;
mod support;
mod tools;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            tools::check_tools,
            device::list_devices,
            device::profile_device,
            ingest::ingest_archive,
            ingest::pull_from_device,
            rea::analyze_blobs,
            rea::patch_blob,
            rea::carve_firmware,
            overlay::build_overlay,
            rootfs::build_rootfs,
            flash::recommend_track,
            flash::flash_plan,
            flash::preflight,
            flash::run_flash,
            flash::verify_boot,
            support::device_support,
            backup::hardware_dump,
            backup::export_dump,
            backup::backup_data,
            stock::detect_edl,
            stock::stock_plan,
            stock::run_stock
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
