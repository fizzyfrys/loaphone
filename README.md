# loaphone

Native Linux on your old Android phone. Loaphone is a local-first Tauri v2 desktop workbench for profiling phones, collecting hardware evidence, extracting proprietary blobs, inspecting dependencies, preserving user data and planning a Linux installation. Reuse a phone as a Linux handheld or a headless server.

**Early experimental software, not a universal phone installer.** No phone is needed to explore the app or inspect a ROM. The app does not supply firmware, rootfs images, exploits, unlock codes or proprietary restoration tools.

## Run

Install Node 20 LTS, stable Rust and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/). On Ubuntu:

```sh
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev patchelf build-essential pkg-config
npm install && npm run tauri dev
```

```sh
cd src-tauri && cargo test
cd .. && npm run build
npm run tauri build -- --bundles deb
```

CI builds Linux, macOS and Windows bundles on pushes and pull requests. Download the per-platform artifacts from GitHub Actions. Unsigned bundles may trigger OS warnings. macOS and Windows builds are not locally verified by the Linux development workflow.

## Architecture: four layers

1. **Device Profiler**: adb / fastboot discovery, model and SoC properties, slots, root, battery, bootloader state, host tool inventory and a built-in tier table. Hardware Dump captures readable kernel, device tree, init and VINTF evidence, with per-item failures in summary.json and ZIP export.
2. **Source Selector**: imports ROM ZIPs and partition images, including boot, vendor_boot, DTBO and Android sparse images, or copies readable proprietary directories from a live device. Sparse images expand to raw images before ext4 / erofs filesystem extraction. Every codename has its own local workspace.
3. **REA Inspector**: inventories unpacked image files and analyzes ELF libraries with Rust `goblin` for SONAME, DT_NEEDED, RPATH / RUNPATH, undefined dynamic symbols, Bionic indicators and category heuristics. Resolves dependencies against supplied blobs and a known Android platform library list. Exports report.json, copies firmware and creates non-destructive patchelf copies.
4. **Flasher**: recommends mainline / postmarketOS or Halium / Droidian, previews explicit partition commands, performs preflight checks and requires exact codename confirmation. Includes an optional postmarketOS server profile and SSH reachability check.

Two companion views provide **Backup my data** and **Restore to stock**. React / TypeScript / Vite renders the UI; Rust owns filesystem and process operations on blocking workers. Tauri `log` events feed the activity panel. Flash and restore subprocess output streams as it arrives; other operations emit per-file / operation progress.

Workspaces live under the OS app data directory for `com.fizzyfrys.loaphone`, with `./workspace` fallback:

```text
<app-data>/<codename>/
  blobs/                 extracted libraries and firmware
  images/                imported partition images
  unpacked/<image>.img/  boot components, kernel.config, DTB/DTS pairs or expanded image.raw
  dump/                  hardware evidence and summary.json
  backup/<hex-serial>/user-data/   media, content-provider rows, packages and optional APKs
  backup/<hex-serial>/            readable EFS / persist / modemst copies
  patched/               modified copies only
  lib/firmware/          exported standalone firmware
  report.json
  stock/                 unpacked Pixel factory images
```

## Host tools

All optional tools are detected and missing tools are reported without crashing:

| Task | Tools |
| --- | --- |
| Discovery, dumps, data copies | adb, fastboot |
| ROM extraction | payload-dumper-go, debugfs (ext4), fsck.erofs (erofs) |
| Patching and inspection | patchelf, binwalk, Ghidra analyzeHeadless, rizin / r2 |
| Open recovery | fastboot, [bkerler edl](https://github.com/bkerler/edl), [Heimdall](https://github.com/Benjamin-Dobell/Heimdall), lsusb on Linux |

Put tools on PATH. No tool other than patchelf is required for a plain ELF report. A library classified as Android-provided may still be absent or incompatible on your target rootfs. Tier 1 means a prioritized research target, not a guarantee of a working Linux port. Wiki links and mainline classifications should be checked against current upstream documentation.

## Safety and current limits

- Dry run is on by default. Planning never executes flashing commands. Confirmation must match the device codename. Linux flash execution also verifies fastboot product, unlock state and battery percentage above 50%. If a bootloader only exposes voltage, execution is refused rather than guessing battery health.
- Back up personal data and critical partitions first, and verify the copies. Root is optional for ordinary pulls but needed for boot / critical partitions and some hardware evidence. Backups are best effort and never complete Android backups. Content-provider exports preserve raw rows as JSON because Android output is not an unambiguous CSV format. Permission-denied items are reported. APKs do not include private app data or keys.
- Factory restoration and userdata flashing can erase everything. Do not relock a bootloader with custom images. This application never unlocks, exploits, relocks or automatically reboots after a Linux flash.
- Pixel recovery unpacks a user-supplied factory ZIP and plans bootloader / radio flashes followed by fastboot -w update. Check downloaded firmware authenticity and hashes yourself. OnePlus EDL requires compatible rawprogram0.xml / patch0.xml and potentially a device-specific signed programmer; vendor-authorized devices may be unsupported. Samsung currently supports a stock BOOT partition image through Heimdall only, not a complete firmware restoration. Vendor proprietary tools are not supported.
- Generic partition plans are not device-specific port recipes. Supply boot, rootfs, optional DTBO and vendor_boot images made for the exact device and selected slot. postmarketOS, Droidian and Ubuntu Touch are labels for these supplied images, not rootfs downloaders or builders.
- Server profile describes SSH enabled, no UI and USB networking; the rootfs must already implement those settings. Optional Wi-Fi credentials remain in frontend memory and are not written into images. SSH verification only tests TCP 172.16.42.1:22, not authentication or OS identity.
- Boot v0–v4, vendor_boot v3–v4 and Android DTBO v0–v1 unpack without external tools. Ramdisk payloads are saved as-is. Kernel config recovery needs an embedded IKCONFIG and supports raw, gzip and LZ4 kernels. DTBs are decompiled without recovering original source labels or includes.
- Embedded binwalk carving, live device reboot sequencing and cancellation / process timeouts are not implemented. Use trusted ROM archives with sufficient free disk space. Do not import untrusted files as an elevated user.
- Hardware dump supplies research context, not automatic driver reverse engineering. REA analyzes the imported blobs directory, not kernel text logs or DTS semantics. Review exports for personal identifiers before sharing. Firmware may have redistribution restrictions.
- Real-device flashing, root backups and recovery operations have not been hardware-validated in this first version. Read the port's upstream installation and recovery instructions before proceeding.

## Roadmap

- Ghidra / rizin headless HAL analysis and reproducible REA jobs
- DTS to mainline conversion and device-tree comparison
- udev rule generation from ueventd.rc
- Rootfs building, server / Wi-Fi provisioning and device-specific installation recipes
- Archive quotas, process cancellation / timeouts
- Complete Samsung firmware mapping and stronger recovery image validation
- Hardware-backed integration tests for each supported device and OS
