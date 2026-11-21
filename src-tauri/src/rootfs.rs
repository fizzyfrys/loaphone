use crate::common::{log, workspace};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};

const PMOS_IMAGES: &str = "https://images.postmarketos.org/";
const DROIDIAN_RELEASE: &str =
    "https://api.github.com/repos/droidian-images/droidian/releases/latest";
static BUILD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Deserialize)]
pub struct BuildParams {
    pub codename: String,
    pub source: String,
    pub local_path: Option<String>,
    pub android_api: Option<u32>,
    pub headless: bool,
    pub ssh_key: Option<String>,
    pub headroom_mib: u64,
    pub sparse: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildReport {
    pub source: String,
    pub source_sha256: String,
    pub checksum_verified: bool,
    pub sha256: String,
    pub original_bytes: u64,
    pub output_bytes: u64,
    pub overlay_files_added: usize,
    pub profile_actions: Vec<String>,
    pub warnings: Vec<String>,
    pub output_path: String,
    pub sparse_path: Option<String>,
}

#[derive(Debug)]
struct Source {
    url: String,
    sha256: Option<String>,
    note: String,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn client() -> Result<Client, String> {
    Client::builder()
        .user_agent("loaphone/0.1 rootfs-builder")
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(7200))
        .build()
        .map_err(err)
}

fn resolve_pmos(index: &Value, device: &str) -> Result<Source, String> {
    let mut images = Vec::new();
    for release in index["releases"]
        .as_array()
        .ok_or("Invalid pmOS release index")?
    {
        for d in release["devices"].as_array().into_iter().flatten() {
            if d["name"].as_str() != Some(device) {
                continue;
            }
            for ui in d["interfaces"].as_array().into_iter().flatten() {
                let name = ui["name"].as_str().unwrap_or("");
                let rank = match name {
                    "console" | "headless" => 0,
                    "sxmo-de-sway" => 1,
                    _ => 2,
                };
                for image in ui["images"].as_array().into_iter().flatten() {
                    let file = image["name"].as_str().unwrap_or("");
                    if !file.ends_with(".img.xz") || file.ends_with("-boot.img.xz") {
                        continue;
                    }
                    if let Some(url) = image["url"].as_str() {
                        images.push((
                            rank,
                            image["timestamp"].as_str().unwrap_or(""),
                            url,
                            image["sha256"].as_str(),
                            name,
                        ));
                    }
                }
            }
        }
    }
    images.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(a.1)).then(a.2.cmp(b.2)));
    let (_, _, url, sha256, ui) = images
        .first()
        .ok_or("No published pmOS disk image for this device")?;
    if !url.starts_with("https://") {
        return Err("Non-HTTPS image URL refused".into());
    }
    Ok(Source {
        url: (*url).into(),
        sha256: sha256.map(str::to_owned),
        note: format!(
            "pmOS device {device}, UI {ui}. {}",
            if ["console", "headless"].contains(ui) {
                "Console image."
            } else {
                "No console image published; graphical packages remain installed."
            }
        ),
    })
}

fn resolve_droidian(release: &Value, api: u32) -> Result<Source, String> {
    let needle = format!("-phone-rootfs-api{api}-arm64-");
    let asset = release["assets"]
        .as_array()
        .ok_or("GitHub release has no assets (check API rate limit)")?
        .iter()
        .find(|a| {
            a["name"]
                .as_str()
                .is_some_and(|n| n.contains(&needle) && n.ends_with(".zip"))
        })
        .ok_or("No generic arm64 rootfs ZIP for selected Android API in latest Droidian release")?;
    Ok(Source {
        url: asset["browser_download_url"]
            .as_str()
            .ok_or("Missing asset URL")?
            .into(),
        sha256: None,
        note: format!(
            "Droidian generic arm64 API {api}. WARNING: upstream installs data/rootfs.img INSIDE /data, not directly onto userdata. This raw rootfs requires a compatible device-specific installation layout and Halium boot image; do not blindly flash it to userdata."
        ),
    })
}

fn sha256(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(err)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn download(
    client: &Client,
    url: &str,
    dest: &Path,
    progress: &dyn Fn(String),
) -> Result<(), String> {
    progress(format!("Downloading {url}"));
    let mut response = client
        .get(url)
        .send()
        .map_err(err)?
        .error_for_status()
        .map_err(err)?;
    let total = response.content_length();
    let partial = dest.with_extension("part");
    let mut file = File::create(&partial).map_err(err)?;
    let mut buf = vec![0; 1024 * 1024];
    let mut bytes = 0;
    let mut last = 0;
    loop {
        let n = response.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(err)?;
        bytes += n as u64;
        if bytes - last >= 16 * 1024 * 1024 {
            progress(format!(
                "Downloaded {} MiB{}",
                bytes / 1048576,
                total
                    .map(|t| format!(" / {} MiB", t / 1048576))
                    .unwrap_or_default()
            ));
            last = bytes;
        }
    }
    if total.is_some_and(|t| t != bytes) {
        return Err("Incomplete download".into());
    }
    file.sync_all().map_err(err)?;
    fs::rename(partial, dest).map_err(err)
}

fn le32(b: &[u8]) -> u64 {
    u32::from_le_bytes(b.try_into().unwrap()) as u64
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

fn read_at(f: &mut File, offset: u64, size: usize) -> Result<Vec<u8>, String> {
    let mut data = vec![0; size];
    f.seek(SeekFrom::Start(offset)).map_err(err)?;
    f.read_exact(&mut data).map_err(err)?;
    Ok(data)
}

fn ext4_at(f: &mut File, start: u64, length: u64) -> bool {
    length >= 2048
        && read_at(f, start.saturating_add(1024), 1024)
            .is_ok_and(|v| v[56..58] == [0x53, 0xef] && le32(&v[96..100]) & 0x40 != 0)
}

fn region(start_lba: u64, sectors: u64, disk_len: u64) -> Result<(u64, u64), String> {
    let start = start_lba
        .checked_mul(512)
        .ok_or("Partition offset overflow")?;
    let length = sectors.checked_mul(512).ok_or("Partition size overflow")?;
    if start == 0 || length == 0 || start.checked_add(length).is_none_or(|end| end > disk_len) {
        return Err("Partition outside image bounds".into());
    }
    Ok((start, length))
}

fn partitions(f: &mut File) -> Result<Vec<(u64, u64)>, String> {
    let size = f.metadata().map_err(err)?.len();
    let mbr = read_at(f, 0, 512)?;
    if mbr[510..512] != [0x55, 0xaa] {
        return Err("Not raw ext4 or an MBR/GPT disk image".into());
    }
    if (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xee) {
        let header = read_at(f, 512, 512)?;
        if &header[..8] != b"EFI PART" {
            return Err("Invalid GPT header".into());
        }
        let table = le64(&header[72..80])
            .checked_mul(512)
            .ok_or("GPT offset overflow")?;
        let count = le32(&header[80..84]);
        let entry_size = le32(&header[84..88]);
        if count > 4096
            || !(128..=4096).contains(&entry_size)
            || table
                .checked_add(count * entry_size)
                .is_none_or(|end| end > size)
        {
            return Err("Invalid GPT table bounds".into());
        }
        let mut result = Vec::new();
        for i in 0..count {
            let entry = read_at(f, table + i * entry_size, entry_size as usize)?;
            if entry[..16].iter().all(|b| *b == 0) {
                continue;
            }
            let start = le64(&entry[32..40]);
            let end = le64(&entry[40..48]);
            let sectors = end
                .checked_sub(start)
                .and_then(|n| n.checked_add(1))
                .ok_or("Invalid GPT partition range")?;
            result.push(region(start, sectors, size)?);
        }
        Ok(result)
    } else {
        let mut result = Vec::new();
        for i in 0..4 {
            let entry = &mbr[446 + i * 16..462 + i * 16];
            if entry[4] == 0 {
                continue;
            }
            if [0x05, 0x0f, 0x85].contains(&entry[4]) {
                return Err("Extended MBR partitions are not supported".into());
            }
            result.push(region(le32(&entry[8..12]), le32(&entry[12..16]), size)?);
        }
        Ok(result)
    }
}

fn extract_ext4(source: &Path, output: &Path) -> Result<(), String> {
    let mut input = File::open(source).map_err(err)?;
    let len = input.metadata().map_err(err)?.len();
    let (start, length) = if ext4_at(&mut input, 0, len) {
        (0, len)
    } else {
        let mut candidates: Vec<_> = partitions(&mut input)?
            .into_iter()
            .filter(|(s, l)| ext4_at(&mut input, *s, *l))
            .collect();
        let labeled: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|(s, _)| {
                read_at(&mut input, *s + 1144, 16).is_ok_and(|v| {
                    let label = String::from_utf8_lossy(&v).to_lowercase();
                    label.contains("root")
                })
            })
            .collect();
        if labeled.len() == 1 {
            candidates = labeled;
        }
        if candidates.len() != 1 {
            return Err(format!(
                "Expected exactly one ext4 root partition, found {} (encrypted or multi-root images require manual extraction)",
                candidates.len()
            ));
        }
        candidates[0]
    };
    input.seek(SeekFrom::Start(start)).map_err(err)?;
    let mut dest = File::create(output).map_err(err)?;
    let copied = std::io::copy(&mut input.take(length), &mut dest).map_err(err)?;
    if copied != length {
        return Err("Truncated root partition".into());
    }
    Ok(())
}

fn unpack(
    source: &Path,
    work: &Path,
    output: &Path,
    progress: &dyn Fn(String),
) -> Result<(), String> {
    let name = source.to_string_lossy().to_lowercase();
    let expanded = work.join("expanded.img");
    if name.ends_with(".xz") {
        progress("Decompressing XZ image".into());
        let status = Command::new("xz")
            .args(["-dc", "--"])
            .arg(source)
            .stdout(Stdio::from(File::create(&expanded).map_err(err)?))
            .status()
            .map_err(err)?;
        if !status.success() {
            return Err(format!("xz failed: {status}"));
        }
        extract_ext4(&expanded, output)?;
        fs::remove_file(expanded).map_err(err)?;
    } else if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(File::open(source).map_err(err)?).map_err(err)?;
        let mut candidates = Vec::new();
        let mut all_images = Vec::new();
        for i in 0..zip.len() {
            let entry = zip.by_index(i).map_err(err)?;
            let n = entry.name().to_lowercase();
            if n.ends_with(".img") {
                all_images.push(i);
            }
            if n.ends_with(".img") && (n.contains("rootfs") || n.ends_with("system.img")) {
                candidates.push(i);
            }
        }
        if candidates.is_empty() && all_images.len() == 1 {
            candidates = all_images;
        }
        if candidates.len() != 1 {
            return Err(format!(
                "Expected one rootfs/system .img in ZIP, found {}",
                candidates.len()
            ));
        }
        let mut entry = zip.by_index(candidates[0]).map_err(err)?;
        progress(format!("Extracting ZIP entry {}", entry.name()));
        std::io::copy(&mut entry, &mut File::create(&expanded).map_err(err)?).map_err(err)?;
        extract_ext4(&expanded, output)?;
        fs::remove_file(expanded).map_err(err)?;
    } else if name.ends_with(".img") {
        extract_ext4(source, output)?;
    } else {
        return Err("Choose .img, .img.xz or .zip".into());
    }
    Ok(())
}

fn host(
    tool: &str,
    args: &[&std::ffi::OsStr],
    fsck: bool,
    progress: &dyn Fn(String),
) -> Result<(), String> {
    progress(format!("Running {tool}"));
    let out = Command::new(tool).args(args).output().map_err(|e| {
        format!(
            "{tool}: {e}. Install e2fsprogs, xz-utils and optionally android-sdk-libsparse-utils."
        )
    })?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    progress(text.clone());
    if out.status.success() || (fsck && out.status.code() == Some(1)) {
        Ok(())
    } else {
        Err(format!("{tool} failed: {text}"))
    }
}

fn quote(s: &str) -> Result<String, String> {
    if s.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
        return Err("Unsupported character in image path".into());
    }
    Ok(format!("\"{s}\""))
}

struct Image<'a> {
    path: &'a Path,
}
impl Image<'_> {
    fn read(&self, command: &str) -> Result<String, String> {
        let out = Command::new("debugfs")
            .args(["-R", command])
            .arg(self.path)
            .output()
            .map_err(err)?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into())
    }
    fn stat(&self, path: &str) -> Result<Option<String>, String> {
        let out = self.read(&format!("stat {}", quote(path)?))?;
        Ok(out.contains("Inode:").then_some(out))
    }
    fn write(&self, command: &str) -> Result<(), String> {
        let out = Command::new("debugfs")
            .args(["-w", "-R", command])
            .arg(self.path)
            .output()
            .map_err(err)?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        let errors: Vec<_> = stderr
            .lines()
            .filter(|line| !line.starts_with("debugfs ") && !line.trim().is_empty())
            .collect();
        if !out.status.success() || !errors.is_empty() {
            return Err(format!("debugfs {command}: {stderr}"));
        }
        Ok(())
    }
    fn metadata(&self, path: &str, mode: u32) -> Result<(), String> {
        for (field, value) in [
            ("mode", format!("0{mode:o}")),
            ("uid", "0".into()),
            ("gid", "0".into()),
        ] {
            self.write(&format!("set_inode_field {} {field} {value}", quote(path)?))?;
        }
        Ok(())
    }
    fn dirs(&self, path: &str) -> Result<(), String> {
        let mut current = String::new();
        for component in path.split('/').filter(|s| !s.is_empty()) {
            if component == "." || component == ".." {
                return Err("Unsafe overlay path".into());
            }
            current.push('/');
            current.push_str(component);
            if self.stat(&current)?.is_none() {
                self.write(&format!("mkdir {}", quote(&current)?))?;
                self.metadata(&current, 0o40755)?;
            }
        }
        Ok(())
    }
    fn remove(&self, path: &str) -> Result<(), String> {
        if let Some(stat) = self.stat(path)? {
            if stat.contains("Type: directory") {
                return Err(format!("Refusing to replace image directory {path}"));
            }
            self.write(&format!("rm {}", quote(path)?))?;
        }
        Ok(())
    }
    fn parent(&self, path: &str) -> Result<(), String> {
        self.dirs(path.rsplit_once('/').ok_or("Expected absolute path")?.0)
    }
    fn file(&self, source: &Path, path: &str, mode: u32) -> Result<(), String> {
        self.parent(path)?;
        self.remove(path)?;
        self.write(&format!(
            "write {} {}",
            quote(source.to_str().ok_or("Non-UTF8 source")?)?,
            quote(path)?
        ))?;
        self.metadata(path, 0o100000 | mode)
    }
    fn symlink(&self, path: &str, target: &str) -> Result<(), String> {
        self.parent(path)?;
        self.remove(path)?;
        self.write(&format!("symlink {} {}", quote(path)?, quote(target)?))?;
        self.metadata(path, 0o120777)
    }
    fn text(&self, work: &Path, path: &str, text: &str, mode: u32) -> Result<(), String> {
        let staging = work.join("profile-file");
        fs::write(&staging, text).map_err(err)?;
        self.file(&staging, path, mode)
    }
}

const USB_SCRIPT: &str = r##"#!/bin/sh
set -eu
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
G=/sys/kernel/config/usb_gadget/loaphone
mkdir -p "$G"
cd "$G"
if [ ! -s UDC ] || [ -z "$(cat UDC)" ]; then
    echo 0x1d6b > idVendor
    echo 0x0104 > idProduct
    mkdir -p strings/0x409 configs/c.1/strings/0x409
    echo loaphone > strings/0x409/serialnumber
    echo Loaphone > strings/0x409/manufacturer
    echo 'USB networking' > strings/0x409/product
    echo 'NCM and RNDIS' > configs/c.1/strings/0x409/configuration
    mkdir -p functions/ncm.usb0 functions/rndis.usb1
    echo 02:00:00:42:01:01 > functions/ncm.usb0/dev_addr
    echo 02:00:00:42:01:02 > functions/ncm.usb0/host_addr
    echo 02:00:00:42:02:01 > functions/rndis.usb1/dev_addr
    echo 02:00:00:42:02:02 > functions/rndis.usb1/host_addr
    [ -L configs/c.1/ncm.usb0 ] || ln -s "$G/functions/ncm.usb0" configs/c.1/ncm.usb0
    [ -L configs/c.1/rndis.usb1 ] || ln -s "$G/functions/rndis.usb1" configs/c.1/rndis.usb1
    UDC=$(ls /sys/class/udc | head -n 1)
    [ -n "$UDC" ] || { echo 'No USB device controller' >&2; exit 1; }
    echo "$UDC" > UDC
fi
ip link add br-loaphone type bridge 2>/dev/null || true
for function in ncm.usb0 rndis.usb1; do
    interface=$(cat "$G/functions/$function/ifname")
    ip link set "$interface" master br-loaphone
    ip link set "$interface" up
done
ip address replace 172.16.42.1/24 dev br-loaphone
ip link set br-loaphone up
"##;

const USB_SERVICE: &str = "[Unit]\nDescription=Loaphone static USB networking (host: 172.16.42.2/24)\nAfter=systemd-modules-load.service\nConditionPathExists=/sys/class/udc\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/loaphone-usbnet\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n";

fn validate_key(key: &str) -> Result<(), String> {
    let parts: Vec<_> = key.split_whitespace().collect();
    if key.lines().count() != 1
        || parts.len() < 2
        || ![
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]
        .contains(&parts[0])
        || parts[1].len() < 32
        || !parts[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
    {
        return Err(
            "Enter one OpenSSH public key (not a private key or authorized_keys options)".into(),
        );
    }
    Ok(())
}

fn profile(image: &Image<'_>, work: &Path, key: Option<&str>) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    let pmos_usb = image
        .read("cat /etc/unudhcpd.conf")
        .unwrap_or_default()
        .contains("unudhcpd_host_ip=172.16.42.1");
    if image.stat("/usr/lib/systemd/systemd")?.is_some()
        || image.stat("/lib/systemd/systemd")?.is_some()
    {
        let ssh = [
            "/usr/lib/systemd/system/ssh.service",
            "/lib/systemd/system/ssh.service",
            "/usr/lib/systemd/system/sshd.service",
            "/lib/systemd/system/sshd.service",
        ]
        .into_iter()
        .find(|p| image.stat(p).ok().flatten().is_some())
        .ok_or("No installed SSH systemd service; install openssh-server in the source image")?;
        let service = ssh.rsplit('/').next().unwrap();
        image.symlink(
            &format!("/etc/systemd/system/multi-user.target.wants/{service}"),
            ssh,
        )?;
        let target = if image
            .stat("/usr/lib/systemd/system/multi-user.target")?
            .is_some()
        {
            "/usr/lib/systemd/system/multi-user.target"
        } else {
            "/lib/systemd/system/multi-user.target"
        };
        image.symlink("/etc/systemd/system/default.target", target)?;
        if pmos_usb {
            actions.push(format!("Enabled {service} and multi-user target; verified pmOS initramfs USB configuration at 172.16.42.1. Preserved existing gadget/network setup (including upstream DHCP service)."));
        } else {
            image.text(work, "/usr/local/sbin/loaphone-usbnet", USB_SCRIPT, 0o755)?;
            image.text(
                work,
                "/etc/systemd/system/loaphone-usbnet.service",
                USB_SERVICE,
                0o644,
            )?;
            image.symlink(
                "/etc/systemd/system/multi-user.target.wants/loaphone-usbnet.service",
                "/etc/systemd/system/loaphone-usbnet.service",
            )?;
            actions.push(format!("Enabled {service}, multi-user target and loaphone-usbnet (172.16.42.1/24, NCM/RNDIS). Set host to 172.16.42.2/24; no DHCP. Existing USB gadget services may need disabling on target."));
        }
    } else if image.stat("/sbin/openrc")?.is_some() || image.stat("/etc/init.d/sshd")?.is_some() {
        if image.stat("/etc/init.d/sshd")?.is_none() {
            return Err("OpenRC image has no sshd service".into());
        }
        image.symlink("/etc/runlevels/default/sshd", "/etc/init.d/sshd")?;
        let usb = image.read("cat /etc/conf.d/usb-moded").unwrap_or_default();
        let networking = image
            .read("cat /etc/network/interfaces")
            .unwrap_or_default();
        if !pmos_usb && !usb.contains("172.16.42.1") && !networking.contains("172.16.42.1") {
            return Err("Cannot verify pmOS static USB networking at 172.16.42.1; use an image with its USB networking configured".into());
        }
        actions.push("Enabled OpenRC sshd; verified existing pmOS USB static address 172.16.42.1 (no gadget replacement). Graphical packages/services are otherwise unchanged.".into());
    } else {
        return Err("Unsupported init: neither systemd nor OpenRC detected".into());
    }
    if let Some(key) = key.filter(|k| !k.trim().is_empty()) {
        validate_key(key)?;
        image.dirs("/root/.ssh")?;
        image.metadata("/root/.ssh", 0o40700)?;
        let old = image
            .read("cat /root/.ssh/authorized_keys")
            .unwrap_or_default();
        image.text(
            work,
            "/root/.ssh/authorized_keys",
            &format!(
                "{}{}\n",
                if old.is_empty() {
                    old
                } else {
                    format!("{}\n", old.trim_end())
                },
                key.trim()
            ),
            0o600,
        )?;
        image.text(
            work,
            "/etc/ssh/sshd_config.d/00-loaphone-key.conf",
            "PermitRootLogin prohibit-password\nPubkeyAuthentication yes\n",
            0o600,
        )?;
        let config = image.read("cat /etc/ssh/sshd_config")?;
        if !config.contains("Include /etc/ssh/sshd_config.d/") {
            image.text(
                work,
                "/etc/ssh/sshd_config",
                &format!("Include /etc/ssh/sshd_config.d/*.conf\n{config}"),
                0o600,
            )?;
        }
        actions.push("Appended public key for root (root-owned 0700 .ssh / 0600 authorized_keys); enabled key-only root SSH. Existing distro user accounts unchanged.".into());
    }
    Ok(actions)
}

fn overlay(image: &Image<'_>, source: &Path) -> Result<usize, String> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(source)
        .min_depth(1)
        .sort_by_file_name()
    {
        let entry = entry.map_err(err)?;
        let relative = entry.path().strip_prefix(source).map_err(err)?;
        let path = format!(
            "/{}",
            relative
                .to_str()
                .ok_or("Non-UTF8 overlay path")?
                .replace('\\', "/")
        );
        if entry.file_type().is_dir() {
            image.dirs(&path)?;
        } else if entry.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).map_err(err)?;
            image.symlink(&path, target.to_str().ok_or("Non-UTF8 symlink")?)?;
            count += 1;
        } else if entry.file_type().is_file() {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                entry.metadata().map_err(err)?.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            image.file(entry.path(), &path, mode)?;
            count += 1;
        } else {
            return Err(format!(
                "Unsupported overlay entry: {}",
                entry.path().display()
            ));
        }
    }
    Ok(count)
}

fn build_at(w: &Path, p: &BuildParams, progress: &dyn Fn(String)) -> Result<BuildReport, String> {
    let _guard = BUILD_LOCK
        .try_lock()
        .map_err(|_| "Another rootfs build is already running")?;
    if p.headroom_mib > 32768 {
        return Err("Headroom must be between 0 and 32768 MiB".into());
    }
    if let Some(key) = p.ssh_key.as_deref().filter(|k| !k.trim().is_empty()) {
        validate_key(key)?;
        if !p.headless {
            return Err("SSH key requires the headless profile".into());
        }
    }
    let root = w.join("rootfs");
    let cache = root.join("cache");
    fs::create_dir_all(&cache).map_err(err)?;
    let work = root.join("building");
    if work.exists() {
        fs::remove_dir_all(&work).map_err(err)?;
    }
    fs::create_dir(&work).map_err(err)?;
    let mut warnings = Vec::new();
    let (source, description, expected) = if p.source == "local" {
        let path = fs::canonicalize(p.local_path.as_deref().ok_or("Select a local image")?)
            .map_err(err)?;
        (path.clone(), path.display().to_string(), None)
    } else {
        let c = client()?;
        let resolved = match p.source.as_str() {
            "pmos" => {
                let support = crate::support::lookup(&p.codename);
                let device = support["pmos"].as_str().ok_or(
                    "No published pmOS device mapping for this codename; use a local image",
                )?;
                progress("Resolving pmOS index".into());
                let landing = c
                    .get(PMOS_IMAGES)
                    .send()
                    .map_err(err)?
                    .error_for_status()
                    .map_err(err)?;
                let index_url = landing.url().join("index.json").map_err(err)?;
                let index = c
                    .get(index_url)
                    .send()
                    .map_err(err)?
                    .error_for_status()
                    .map_err(err)?
                    .json::<Value>()
                    .map_err(err)?;
                let mut source = resolve_pmos(&index, device)?;
                let response = c
                    .get(format!("{}.sha256", source.url))
                    .send()
                    .map_err(err)?;
                if response.status() != reqwest::StatusCode::NOT_FOUND {
                    let text = response
                        .error_for_status()
                        .map_err(err)?
                        .text()
                        .map_err(err)?;
                    let sidecar = text
                        .split_whitespace()
                        .next()
                        .ok_or("Empty pmOS checksum file")?;
                    if sidecar.len() != 64 || !sidecar.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err("Invalid pmOS SHA-256 file".into());
                    }
                    if source
                        .sha256
                        .as_ref()
                        .is_some_and(|hash| !hash.eq_ignore_ascii_case(sidecar))
                    {
                        return Err("pmOS index and sidecar checksum disagree".into());
                    }
                    source.sha256 = Some(sidecar.into());
                }
                source
            }
            "droidian" => {
                progress("Resolving latest Droidian release via GitHub API".into());
                let release=c.get(DROIDIAN_RELEASE).send().map_err(err)?.error_for_status().map_err(|e| format!("GitHub API: {e}. If rate limited, download a release ZIP and use Local file."))?.json::<Value>().map_err(err)?;
                let mut source = resolve_droidian(&release, p.android_api.unwrap_or(28))?;
                if let Some(asset) = release["assets"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["name"] == "SHA256SUMS")
                {
                    let url = asset["browser_download_url"]
                        .as_str()
                        .ok_or("Missing checksum URL")?;
                    let sums = c
                        .get(url)
                        .send()
                        .map_err(err)?
                        .error_for_status()
                        .map_err(err)?
                        .text()
                        .map_err(err)?;
                    let name = source.url.rsplit('/').next().unwrap();
                    source.sha256 = sums.lines().find_map(|l| {
                        let mut s = l.split_whitespace();
                        let hash = s.next()?;
                        let file = s.next()?.trim_start_matches('*');
                        (file == name).then(|| hash.to_owned())
                    });
                    if source.sha256.is_none() {
                        return Err("Release checksum file does not list the selected asset".into());
                    }
                }
                source
            }
            _ => return Err("Unknown rootfs source".into()),
        };
        warnings.push(resolved.note);
        let filename = resolved
            .url
            .rsplit('/')
            .next()
            .ok_or("Invalid download URL")?;
        if filename.contains(['?', '\\']) || filename.is_empty() {
            return Err("Invalid image filename".into());
        }
        let path = cache.join(filename);
        if !path.is_file() {
            download(&c, &resolved.url, &path, progress)?;
        } else {
            progress(format!("Using cached {}", path.display()));
        }
        (path, resolved.url, resolved.sha256)
    };
    progress("Hashing source".into());
    let source_sha256 = sha256(&source)?;
    if let Some(expected) = &expected {
        if !expected.eq_ignore_ascii_case(&source_sha256) {
            return Err("Source SHA-256 mismatch; remove the cached download and retry".into());
        }
    } else {
        warnings
            .push("No published checksum verified for this source; review its provenance.".into());
    }
    let image_path = work.join("rootfs.img");
    progress("Extracting raw ext4 root filesystem (no boot image unpacking)".into());
    unpack(&source, &work, &image_path, progress)?;
    let original_bytes = fs::metadata(&image_path).map_err(err)?.len();
    host(
        "e2fsck",
        &["-fy".as_ref(), image_path.as_os_str()],
        true,
        progress,
    )?;
    File::options()
        .write(true)
        .open(&image_path)
        .map_err(err)?
        .set_len(
            original_bytes
                .checked_add(p.headroom_mib * 1048576)
                .ok_or("Image size overflow")?,
        )
        .map_err(err)?;
    host("resize2fs", &[image_path.as_os_str()], false, progress)?;
    let image = Image { path: &image_path };
    let overlay_path = w.join("overlay");
    let overlay_files_added = if overlay_path.is_dir() {
        progress("Applying device overlay".into());
        overlay(&image, &overlay_path)?
    } else {
        warnings.push("Device overlay missing: build one in REA Inspector first.".into());
        0
    };
    let profile_actions = if p.headless {
        progress("Applying headless profile".into());
        profile(&image, &work, p.ssh_key.as_deref())?
    } else {
        vec![]
    };
    host(
        "e2fsck",
        &["-fy".as_ref(), image_path.as_os_str()],
        true,
        progress,
    )?;
    let digest = sha256(&image_path)?;
    let sparse_temp = work.join("rootfs.sparse.img");
    let sparse_path = if p.sparse {
        if Command::new("img2simg").arg("--help").output().is_ok() {
            host(
                "img2simg",
                &[image_path.as_os_str(), sparse_temp.as_os_str()],
                false,
                progress,
            )?;
            Some(root.join("rootfs.sparse.img").display().to_string())
        } else {
            warnings.push("img2simg not installed; raw output only.".into());
            None
        }
    } else {
        None
    };
    let output = root.join("rootfs.img");
    let report = BuildReport {
        source: description,
        source_sha256,
        checksum_verified: expected.is_some(),
        sha256: digest,
        original_bytes,
        output_bytes: fs::metadata(&image_path).map_err(err)?.len(),
        overlay_files_added,
        profile_actions,
        warnings,
        output_path: output.display().to_string(),
        sparse_path,
    };
    // Only publish successful builds; failed builds leave the previous output intact.
    if output.exists() {
        fs::remove_file(&output).map_err(err)?;
    }
    fs::rename(&image_path, &output).map_err(err)?;
    let sparse_output = root.join("rootfs.sparse.img");
    if sparse_output.exists() {
        fs::remove_file(&sparse_output).map_err(err)?;
    }
    if report.sparse_path.is_some() {
        fs::rename(&sparse_temp, sparse_output).map_err(err)?;
    }
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(err)?,
    )
    .map_err(err)?;
    fs::remove_dir_all(work).map_err(err)?;
    progress(format!("Rootfs ready: {}", output.display()));
    Ok(report)
}

#[tauri::command]
pub async fn build_rootfs(
    app: tauri::AppHandle,
    params: BuildParams,
) -> Result<BuildReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &params.codename)?;
        build_at(&w, &params, &|line| log(&app, "rootfs", line))
    })
    .await
    .map_err(err)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "loaphone-rootfs-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn source_resolution() {
        let index: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rootfs-pmos.json")).unwrap();
        let source = resolve_pmos(&index, "arrow-db410c").unwrap();
        assert!(source.url.ends_with("-arrow-db410c.img.xz"));
        assert!(!source.url.ends_with("-boot.img.xz"));
        assert!(source.note.contains("Console image"));
        assert_eq!(
            source.sha256.unwrap(),
            "d13052e37318a1b4f250c41d502934294466001a8779a2ff508d9d21e6c91dae"
        );
        assert!(resolve_pmos(&index, "unknown").is_err());
        assert!(resolve_pmos(&serde_json::json!({}), "arrow-db410c").is_err());
        let mut multiple = index.clone();
        let mut ui = multiple["releases"][0]["devices"][1]["interfaces"][0].clone();
        ui["name"] = "phosh".into();
        ui["images"][1]["timestamp"] = "2099-01-01".into();
        multiple["releases"][0]["devices"][1]["interfaces"]
            .as_array_mut()
            .unwrap()
            .push(ui);
        assert!(
            resolve_pmos(&multiple, "arrow-db410c")
                .unwrap()
                .note
                .contains("Console image")
        );
        let release: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rootfs-droidian.json")).unwrap();
        assert!(
            resolve_droidian(&release, 28)
                .unwrap()
                .url
                .contains("phone-rootfs-api28-arm64")
        );
        assert!(resolve_droidian(&release, 33).is_err());
        assert!(resolve_droidian(&serde_json::json!({"assets":[]}), 28).is_err());
    }

    fn disk(gpt: bool) -> Vec<u8> {
        let mut d = vec![0; 512 * 64];
        d[510..512].copy_from_slice(&[0x55, 0xaa]);
        d[450] = if gpt { 0xee } else { 0x83 };
        d[454..458].copy_from_slice(&8u32.to_le_bytes());
        d[458..462].copy_from_slice(&32u32.to_le_bytes());
        if gpt {
            d[512..520].copy_from_slice(b"EFI PART");
            d[584..592].copy_from_slice(&2u64.to_le_bytes());
            d[592..596].copy_from_slice(&1u32.to_le_bytes());
            d[596..600].copy_from_slice(&128u32.to_le_bytes());
            d[1024] = 1;
            d[1056..1064].copy_from_slice(&8u64.to_le_bytes());
            d[1064..1072].copy_from_slice(&39u64.to_le_bytes());
        }
        d[4096 + 1080..4096 + 1082].copy_from_slice(&[0x53, 0xef]);
        d[4096 + 1120] = 0x40;
        d
    }

    #[test]
    fn mbr_and_gpt_partitions() {
        let dir = TestDir::new();
        for gpt in [false, true] {
            let path = dir.0.join("disk.img");
            fs::write(&path, disk(gpt)).unwrap();
            let mut f = File::open(&path).unwrap();
            assert_eq!(partitions(&mut f).unwrap(), vec![(4096, 16384)]);
            let out = dir.0.join("root.img");
            extract_ext4(&path, &out).unwrap();
            assert_eq!(fs::metadata(out).unwrap().len(), 16384);
            let mut invalid = disk(gpt);
            if gpt {
                invalid[1064..1072].copy_from_slice(&u64::MAX.to_le_bytes());
            } else {
                invalid[458..462].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            fs::write(&path, invalid).unwrap();
            assert!(partitions(&mut File::open(&path).unwrap()).is_err());
        }
        let path = dir.0.join("empty.img");
        fs::write(&path, []).unwrap();
        assert!(extract_ext4(&path, &dir.0.join("out.img")).is_err());
    }

    #[test]
    fn profile_generation_and_input_safety() {
        assert!(USB_SCRIPT.contains("172.16.42.1/24"));
        assert!(USB_SCRIPT.contains("functions/ncm.usb0 functions/rndis.usb1"));
        assert!(USB_SERVICE.contains("WantedBy=multi-user.target"));
        assert!(
            validate_key("ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= test").is_ok()
        );
        for key in [
            "",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "ssh-ed25519 short",
            "ssh-rsa AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ncommand=bad",
        ] {
            assert!(validate_key(key).is_err());
        }
        assert!(quote("/a\nwrite bad").is_err());
        assert!(quote("/a\"b").is_err());
        assert_eq!(quote("/path with spaces").unwrap(), "\"/path with spaces\"");
    }

    fn tools_available() -> bool {
        ["mkfs.ext4", "e2fsck", "resize2fs", "debugfs"]
            .iter()
            .all(|t| Command::new(t).arg("-V").output().is_ok())
    }

    fn tiny_image(dir: &Path, openrc: bool) -> PathBuf {
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("etc/ssh")).unwrap();
        fs::write(tree.join("etc/ssh/sshd_config"), "# test config\n").unwrap();
        if openrc {
            fs::create_dir_all(tree.join("etc/init.d")).unwrap();
            fs::create_dir_all(tree.join("etc/network")).unwrap();
            fs::write(tree.join("etc/init.d/sshd"), "#!/sbin/openrc-run\n").unwrap();
            fs::write(
                tree.join("etc/network/interfaces"),
                "iface usb0 inet static\n address 172.16.42.1\n",
            )
            .unwrap();
        } else {
            fs::create_dir_all(tree.join("usr/lib/systemd/system")).unwrap();
            fs::create_dir_all(tree.join("lib/systemd/system")).unwrap();
            fs::write(tree.join("usr/lib/systemd/systemd"), "systemd fixture").unwrap();
            fs::write(
                tree.join("usr/lib/systemd/system/ssh.service"),
                "[Service]\nExecStart=/usr/sbin/sshd -D\n",
            )
            .unwrap();
            fs::write(
                tree.join("lib/systemd/system/multi-user.target"),
                "[Unit]\n",
            )
            .unwrap();
        }
        let image = dir.join("source.img");
        File::create(&image).unwrap().set_len(32 * 1048576).unwrap();
        assert!(
            Command::new("mkfs.ext4")
                .args(["-q", "-F", "-d"])
                .arg(&tree)
                .arg(&image)
                .status()
                .unwrap()
                .success()
        );
        image
    }

    fn params(source: &Path) -> BuildParams {
        BuildParams {
            codename: "test".into(),
            source: "local".into(),
            local_path: Some(source.display().to_string()),
            android_api: None,
            headless: true,
            ssh_key: Some(
                "ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= fixture".into(),
            ),
            headroom_mib: 16,
            sparse: false,
        }
    }

    #[test]
    fn local_pipeline_ext4_overlay_and_profiles() {
        if !tools_available() {
            eprintln!("SKIP rootfs integration: install e2fsprogs");
            return;
        }
        for openrc in [false, true] {
            let dir = TestDir::new();
            let source = tiny_image(&dir.0, openrc);
            let source_digest = sha256(&source).unwrap();
            let w = dir.0.join("workspace");
            fs::create_dir_all(w.join("overlay/etc/udev/rules.d")).unwrap();
            fs::write(
                w.join("overlay/etc/udev/rules.d/99-test.rules"),
                "# loaphone overlay test\n",
            )
            .unwrap();
            let report = build_at(&w, &params(&source), &|_| {}).unwrap();
            assert_eq!(report.overlay_files_added, 1);
            assert_eq!(report.output_bytes, 48 * 1048576);
            assert_eq!(sha256(&source).unwrap(), source_digest);
            let image = Image {
                path: Path::new(&report.output_path),
            };
            assert!(
                image
                    .read("cat /etc/udev/rules.d/99-test.rules")
                    .unwrap()
                    .contains("overlay test")
            );
            assert!(
                image
                    .stat("/root/.ssh/authorized_keys")
                    .unwrap()
                    .unwrap()
                    .contains("0600")
            );
            assert!(
                image
                    .read("cat /root/.ssh/authorized_keys")
                    .unwrap()
                    .contains("ssh-ed25519")
            );
            if openrc {
                assert!(
                    image
                        .stat("/etc/runlevels/default/sshd")
                        .unwrap()
                        .unwrap()
                        .contains("/etc/init.d/sshd")
                );
            } else {
                assert!(
                    image
                        .stat("/etc/systemd/system/multi-user.target.wants/ssh.service")
                        .unwrap()
                        .unwrap()
                        .contains("ssh.service")
                );
                assert!(
                    image
                        .read("cat /usr/local/sbin/loaphone-usbnet")
                        .unwrap()
                        .contains("172.16.42.1/24")
                );
                assert!(
                    image
                        .stat("/usr/local/sbin/loaphone-usbnet")
                        .unwrap()
                        .unwrap()
                        .contains("0755")
                );
            }
            let mut no_profile = params(&source);
            no_profile.headless = false;
            no_profile.ssh_key = None;
            fs::remove_dir_all(w.join("overlay")).unwrap();
            let empty = build_at(&w, &no_profile, &|_| {}).unwrap();
            assert_eq!(empty.overlay_files_added, 0);
            assert!(empty.warnings.iter().any(|s| s.contains("overlay missing")));
            let previous = sha256(Path::new(&empty.output_path)).unwrap();
            fs::write(&source, "not ext4").unwrap();
            assert!(build_at(&w, &params(&source), &|_| {}).is_err());
            assert_eq!(sha256(Path::new(&empty.output_path)).unwrap(), previous);
        }
    }

    #[test]
    #[ignore = "Explicit public-image smoke test: LOAPHONE_ROOTFS_SOURCE and LOAPHONE_ROOTFS_WORKSPACE required"]
    fn public_image_build() {
        let source = std::env::var("LOAPHONE_ROOTFS_SOURCE").expect("source path");
        let w = std::env::var("LOAPHONE_ROOTFS_WORKSPACE").expect("workspace path");
        let mut p = params(Path::new(&source));
        p.headroom_mib = 512;
        p.ssh_key = None;
        p.sparse = true;
        let report = build_at(Path::new(&w), &p, &|s| println!("{s}")).unwrap();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        let image = Image {
            path: Path::new(&report.output_path),
        };
        println!(
            "{}",
            image
                .read("stat /etc/systemd/system/multi-user.target.wants/ssh.service")
                .unwrap()
        );
        println!(
            "{}",
            image
                .read("stat /etc/systemd/system/multi-user.target.wants/sshd.service")
                .unwrap()
        );
        println!(
            "{}",
            image.read("stat /etc/runlevels/default/sshd").unwrap()
        );
        println!(
            "{}",
            image
                .read("cat /etc/udev/rules.d/99-loaphone-android.rules")
                .unwrap()
        );
    }
}
