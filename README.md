# loaphone

Native Linux on your old Android phone. Loaphone is a local-first Tauri v2 desktop workbench for profiling phones, collecting hardware evidence, extracting proprietary blobs, inspecting dependencies, preserving user data and planning a Linux installation. Reuse a phone as a Linux handheld or a headless server.

**Early experimental software, not a universal phone installer.** No phone is needed to explore the app or inspect a ROM. Rootfs builder can fetch public upstream images; the app does not supply firmware, exploits, unlock codes or proprietary restoration tools.

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
  overlay/               exported udev rules and firmware
  rootfs/cache/          downloaded upstream archives
  rootfs/rootfs.img      prepared raw ext4 filesystem
  rootfs/rootfs.sparse.img  optional img2simg output
  rootfs/report.json     source/output hashes, sizes and actions
```

## Host tools

All optional tools are detected and missing tools are reported without crashing:

| Task | Tools |
| --- | --- |
| Discovery, dumps, data copies | adb, fastboot |
| ROM extraction | payload-dumper-go, debugfs (ext4), fsck.erofs (erofs) |
| Patching and inspection | patchelf, binwalk, Ghidra analyzeHeadless, rizin / r2 |
| Open recovery | fastboot, [bkerler edl](https://github.com/bkerler/edl), [Heimdall](https://github.com/Benjamin-Dobell/Heimdall), lsusb on Linux |
| Rootfs builder | e2fsck, resize2fs, debugfs (e2fsprogs), xz; optional img2simg (android-sdk-libsparse-utils) |

Put tools on PATH. No tool other than patchelf is required for a plain ELF report. A library classified as Android-provided may still be absent or incompatible on your target rootfs. Tier 1 means a prioritized research target, not a guarantee of a working Linux port. Wiki links and mainline classifications should be checked against current upstream documentation.

## Safety and current limits

- Dry run is on by default. Planning never executes flashing commands. Confirmation must match the device codename. Linux flash execution also verifies fastboot product, unlock state and battery percentage above 50%. If a bootloader only exposes voltage, execution is refused rather than guessing battery health.
- Back up personal data and critical partitions first, and verify the copies. Root is optional for ordinary pulls but needed for boot / critical partitions and some hardware evidence. Backups are best effort and never complete Android backups. Content-provider exports preserve raw rows as JSON because Android output is not an unambiguous CSV format. Permission-denied items are reported. APKs do not include private app data or keys.
- Factory restoration and userdata flashing can erase everything. Do not relock a bootloader with custom images. This application never unlocks, exploits, relocks or automatically reboots after a Linux flash.
- Pixel recovery unpacks a user-supplied factory ZIP and plans bootloader / radio flashes followed by fastboot -w update. Check downloaded firmware authenticity and hashes yourself. OnePlus EDL requires compatible rawprogram0.xml / patch0.xml and potentially a device-specific signed programmer; vendor-authorized devices may be unsupported. Samsung currently supports a stock BOOT partition image through Heimdall only, not a complete firmware restoration. Vendor proprietary tools are not supported.
- Generic partition plans are not device-specific port recipes. Supply boot, rootfs, optional DTBO and vendor_boot images made for the exact device and selected slot. Flasher writes its rootfs input directly to userdata. In particular, upstream Droidian installs `data/rootfs.img` **inside** `/data`; the builder's extracted inner ext4 is not a ready-to-flash Droidian userdata container. Use the port's installation instructions, not a blind userdata flash.
- Rootfs builder's headless profile enables existing SSH services; it does not install packages. Systemd selects multi-user target and adds a configfs NCM/RNDIS service at 172.16.42.1/24; configure the host statically as 172.16.42.2/24. Existing gadget managers can conflict and may need disabling on target. OpenRC preserves and verifies pmOS USB configuration. Graphical packages are not removed. Optional Wi-Fi credentials remain in frontend memory and are not written into images. SSH verification only tests TCP 172.16.42.1:22, not authentication or OS identity.
- Boot v0–v4, vendor_boot v3–v4 and Android DTBO v0–v1 unpack without external tools. Ramdisk payloads are saved as-is. Kernel config recovery needs an embedded IKCONFIG and supports raw, gzip and LZ4 kernels. DTBs are decompiled without recovering original source labels or includes.
- Embedded binwalk carving, live device reboot sequencing and cancellation / process timeouts are not implemented. Use trusted ROM archives with sufficient free disk space. Do not import untrusted files as an elevated user.
- Hardware dump supplies research context, not automatic driver reverse engineering. REA analyzes the imported blobs directory, not kernel text logs or DTS semantics. Review exports for personal identifiers before sharing. Firmware may have redistribution restrictions.
- Real-device flashing, root backups and recovery operations have not been hardware-validated in this first version. Read the port's upstream installation and recovery instructions before proceeding.

## Roadmap

- Ghidra / rizin headless HAL analysis and reproducible REA jobs
- DTS to mainline conversion and device-tree comparison
- udev rule generation from ueventd.rc
- Wi-Fi provisioning and device-specific installation recipes
- Archive quotas, process cancellation / timeouts
- Complete Samsung firmware mapping and stronger recovery image validation
- Hardware-backed integration tests for each supported device and OS

## Rootfs builder

Use the **Rootfs builder** screen after exporting an overlay in REA Inspector.
On Ubuntu install `e2fsprogs xz-utils android-sdk-libsparse-utils`. No root,
mounts, chroot or qemu are used. The builder streams downloads into the device
workspace cache, checks published SHA-256 when available, extracts raw ext4
(or the root ext4 partition of a 512-byte-sector MBR/GPT disk), runs e2fsck and
resize2fs, then uses debugfs to apply overlay files and profile settings to a
copy. Default added capacity is 512 MiB. Added files are explicitly root-owned;
existing files not replaced by the overlay/profile keep their ownership.
Outputs from failed builds do not replace the previous successful raw image.
Allow several times the compressed size in free disk space; there is no quota
or build cancellation. LUKS, LVM, extended MBR and ambiguous multi-root images
require manual extraction. Android sparse *output* is optional; input is raw.
Current pmOS images can require e2fsprogs 1.47 or newer (Ubuntu 22.04's 1.46.5
rejects the orphan-file feature). Put a recent e2fsprogs installation on PATH;
the builder fails with the tool's diagnostic rather than stripping filesystem features.

The pmOS resolver follows `https://images.postmarketos.org/` to its current
directory and reads `index.json` (currently `https://images.nura.eco/bpo/index.json`).
Only published device mappings are included: google-sargo, oneplus-enchilada,
oneplus-fajita. Console/headless is preferred, otherwise the UI fallback is
reported. The latest image within that preference is selected across releases.
The index hash and published `.sha256` sidecar are checked for agreement.
Newer pmOS images may use systemd rather than OpenRC; init is detected from
the image, not inferred from its distro name. When pmOS's existing initramfs
USB address is verified in `/etc/unudhcpd.conf`, it is preserved on either init
system, including its upstream DHCP server, rather than adding a competing gadget.
Droidian resolves the latest GitHub release's generic `phone-rootfs-apiXX-arm64`
ZIP, extracts `data/rootfs.img`, and checks `SHA256SUMS` when published.
Choose the API level matching your Halium boot image. GitHub API rate limits
are reported; downloading the ZIP manually and choosing Local file works offline.
The current Droidian generic image may not include openssh-server; the headless
profile refuses images without an installed SSH service rather than pretending
SSH was enabled. Use a suitably provisioned source or build without that profile.

An optional OpenSSH public key is appended to `/root/.ssh/authorized_keys`
(0700 directory, 0600 file); the builder explicitly enables **key-only root
login**, leaving normal distro accounts unchanged. This intentionally uses root
instead of guessing image-specific default usernames. Omit the key to preserve
distro authentication policy. Review this security choice and generated files
before deployment. No keys or Wi-Fi credentials are sent to upstream servers.

Offline tests include a tiny `mkfs.ext4 -d` image, both init profiles and debugfs
verification. To reproduce a public-image smoke build through the same pipeline:

```sh
cd src-tauri
LOAPHONE_ROOTFS_SOURCE=/path/to/public.img.xz \
LOAPHONE_ROOTFS_WORKSPACE=/path/to/workspace \
cargo test public_image_build -- --ignored --nocapture
```
