//! Optional headless reverse-engineering pass over HAL ELF blobs.
//!
//! Loaphone never ships a disassembler. When Rizin or Ghidra's `analyzeHeadless`
//! is installed on the host it is used to collect raw facts (ioctl call sites,
//! strings, constants), which are classified here into per-blob findings.

use crate::common::workspace;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_FINDINGS: usize = 200;
const RIZIN_TIMEOUT: Duration = Duration::from_secs(180);
const GHIDRA_TIMEOUT: Duration = Duration::from_secs(900);
const GHIDRA_SCRIPT: &str = include_str!("../ghidra/LoaphoneScan.java");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Rizin,
    Ghidra,
}

#[derive(Clone, Debug, Serialize)]
pub struct Backend {
    kind: Kind,
    program: PathBuf,
    version: String,
}

#[derive(Serialize)]
pub struct Status {
    available: bool,
    backend: Option<Backend>,
    message: String,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct RawIoctl {
    pub address: u64,
    pub function: String,
    pub request: Option<u64>,
}
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct RawString {
    pub address: u64,
    pub value: String,
}
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct RawConstant {
    pub address: u64,
    pub function: String,
    pub value: u64,
}
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct Section {
    pub start: u64,
    pub end: u64,
}

/// Backend-neutral facts gathered from one binary.
#[derive(Debug, Default, Deserialize)]
pub struct RawScan {
    pub ioctls: Vec<RawIoctl>,
    pub strings: Vec<RawString>,
    pub constants: Vec<RawConstant>,
    pub sections: Vec<Section>,
    /// The backend skipped functions (limit hit or decompilation failed).
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct IoctlFinding {
    address: String,
    function: String,
    request: Option<String>,
    decoded: Option<String>,
    subsystem: Option<String>,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct PathFinding {
    address: String,
    value: String,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct RegisterFinding {
    value: String,
    address: String,
    function: String,
    sites: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Findings {
    path: String,
    ioctls: Vec<IoctlFinding>,
    firmware: Vec<PathFinding>,
    nodes: Vec<PathFinding>,
    registers: Vec<RegisterFinding>,
    truncated: bool,
    error: Option<String>,
    seconds: f64,
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".bat", ".cmd", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        exts.iter()
            .map(|e| dir.join(format!("{name}{e}")))
            .find(|p| p.is_file())
    })
}

fn rizin() -> Option<Backend> {
    let program = find_on_path("rizin")?;
    let out = Command::new(&program).arg("-v").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("rizin")
        .trim()
        .to_string();
    Some(Backend {
        kind: Kind::Rizin,
        program,
        version,
    })
}

fn ghidra() -> Option<Backend> {
    let script = if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };
    let program = std::env::var_os("GHIDRA_INSTALL_DIR")
        .map(|d| PathBuf::from(d).join("support").join(script))
        .filter(|p| p.is_file())
        .or_else(|| find_on_path("analyzeHeadless"))?;
    let props = fs::canonicalize(&program)
        .ok()
        .and_then(|p| {
            p.parent()?
                .parent()
                .map(|d| d.join("Ghidra/application.properties"))
        })
        .and_then(|p| fs::read_to_string(p).ok());
    let version = props
        .as_deref()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("application.version="))
        })
        .map(|v| format!("Ghidra {}", v.trim()))
        .unwrap_or_else(|| "Ghidra".into());
    Some(Backend {
        kind: Kind::Ghidra,
        program,
        version,
    })
}

/// Rizin is preferred because it is fast; `LOAPHONE_DECOMPILER` can force
/// `rizin`, `ghidra` or `none`.
pub fn detect() -> Option<Backend> {
    match std::env::var("LOAPHONE_DECOMPILER").ok().as_deref() {
        Some("none") => None,
        Some("rizin") => rizin(),
        Some("ghidra") => ghidra(),
        _ => rizin().or_else(ghidra),
    }
}

pub fn status_of(backend: Option<Backend>) -> Status {
    match backend {
        Some(b) => Status {
            available: true,
            message: format!("Headless analysis uses {}", b.version),
            backend: Some(b),
        },
        None => Status {
            available: false,
            backend: None,
            message:
                "Neither Rizin nor Ghidra headless (analyzeHeadless) is installed. Install Rizin \
                      or set GHIDRA_INSTALL_DIR to scan HAL blobs for ioctls, firmware paths and \
                      hardware registers. The ELF inventory still works without them."
                    .into(),
        },
    }
}

fn kill_tree(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .status();
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<String, String> {
    // Own process group so a timeout also kills children (Ghidra's JVM is
    // started by a launcher script).
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let stdout = drain(Box::new(child.stdout.take().ok_or("no stdout")?));
    let stderr = drain(Box::new(child.stderr.take().ok_or("no stderr")?));
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            let out = stdout.join().unwrap_or_default();
            if status.success() {
                return Ok(out);
            }
            let err = stderr.join().unwrap_or_default();
            let detail = out
                .lines()
                .chain(err.lines())
                .rfind(|l| l.contains("ERROR") || l.contains("Error"))
                .or_else(|| err.lines().rfind(|l| !l.trim().is_empty()))
                .unwrap_or("")
                .trim()
                .to_string();
            return Err(format!("exited with {status}: {detail}"));
        }
        if start.elapsed() > timeout {
            kill_tree(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------- Rizin ----

const MARK: &str = "LOAPHONE:";

fn rizin_sections(out: &str) -> BTreeMap<String, Vec<serde_json::Value>> {
    let mut map = BTreeMap::<String, Vec<serde_json::Value>>::new();
    let mut current = String::new();
    for line in out.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix(MARK) {
            current = name.trim().to_string();
        } else if (line.starts_with('[') || line.starts_with('{'))
            && let Ok(v) = serde_json::from_str(line)
        {
            map.entry(current.clone()).or_default().push(v);
        }
    }
    map
}

fn reg_index(op: &str) -> Option<u8> {
    let op = op.trim();
    let n = match op {
        "ip" => return Some(12),
        "lr" => return Some(14),
        _ => op
            .strip_prefix('x')
            .or_else(|| op.strip_prefix('w'))
            .or_else(|| op.strip_prefix('r'))?,
    };
    n.parse().ok().filter(|n: &u8| *n < 31)
}

fn imm(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches('#');
    if let Some(h) = s.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn shift(s: Option<&&str>) -> u32 {
    s.and_then(|s| s.trim().strip_prefix("lsl"))
        .and_then(imm)
        .unwrap_or(0) as u32
}

/// Tracks immediate values through one function's disassembly. Returns ioctl
/// call sites with the request register value (if constant) and every
/// immediate materialised into a register.
pub fn track_function(
    function: &str,
    ops: &[serde_json::Value],
    ioctl_targets: &[(u64, u64)],
    arm32: bool,
    read32: &dyn Fn(u64) -> Option<u64>,
) -> (Vec<RawIoctl>, Vec<RawConstant>) {
    let mut regs: BTreeMap<u8, u64> = BTreeMap::new();
    let (mut ioctls, mut constants) = (vec![], vec![]);
    let mask = if arm32 { 0xffff_ffff } else { u64::MAX };
    // Without a CFG, values are only trusted along straight-line code: state
    // is dropped at every branch target and after unconditional jumps.
    let join_points: BTreeSet<u64> = ops
        .iter()
        .filter(|op| ["jmp", "cjmp"].contains(&op["type"].as_str().unwrap_or("")))
        .filter_map(|op| op["jump"].as_u64())
        .collect();
    let mut after_jump = false;
    for op in ops {
        let addr = op["offset"].as_u64().unwrap_or(0);
        let kind = op["type"].as_str().unwrap_or("");
        let text = op["opcode"].as_str().unwrap_or("").to_lowercase();
        if after_jump || join_points.contains(&addr) {
            regs.clear();
        }
        after_jump = ["jmp", "ujmp", "ret"].contains(&kind);
        if let Some(target) = op["jump"].as_u64()
            && ["call", "ucall", "jmp", "ucjmp"].contains(&kind)
            && ioctl_targets
                .iter()
                .any(|(lo, hi)| (*lo..*hi).contains(&target))
        {
            ioctls.push(RawIoctl {
                address: addr,
                function: function.into(),
                request: regs.get(&1).map(|v| v & 0xffff_ffff),
            });
        }
        if kind == "call" || kind == "ucall" {
            regs.retain(|r, _| if arm32 { *r > 3 && *r != 12 } else { *r > 18 });
            continue;
        }
        let (mnem, rest) = text.split_once(' ').unwrap_or((text.as_str(), ""));
        let base = mnem.trim_end_matches(".w");
        let reads_only = ["cmp", "cmn", "tst", "teq", "cbz", "cbnz", "tbz", "tbnz", "push"]
            .contains(&base)
            || (base.starts_with("st")
                && !["stx", "stlx", "strex", "stlex"].iter().any(|p| base.starts_with(p)));
        if reads_only {
            continue;
        }
        let args: Vec<&str> = rest.split(", ").collect();
        let Some(rd) = args.first().and_then(|a| reg_index(a)) else {
            continue;
        };
        let wide = !arm32 && args[0].trim().starts_with('x');
        let m = if wide || arm32 { mask } else { 0xffff_ffff };
        let src = args.get(1).copied().unwrap_or("");
        let value = match base {
            "mov" | "movs" | "movz" | "movw" | "mvn" if imm(src).is_some() => {
                let v = imm(src).unwrap() << shift(args.get(2));
                Some(if base == "mvn" { !v & m } else { v & m })
            }
            "mov" | "movs" if reg_index(src).is_some() => {
                regs.get(&reg_index(src).unwrap()).copied()
            }
            "orr" if src.ends_with("zr") => args.get(2).and_then(|s| imm(s)),
            "movk" => match (regs.get(&rd), imm(src)) {
                (Some(old), Some(v)) => {
                    let sh = shift(args.get(2));
                    Some((old & !(0xffff << sh) | v << sh) & m)
                }
                _ => None,
            },
            "movt" => match (regs.get(&rd), imm(src)) {
                (Some(old), Some(v)) => Some(old & 0xffff | (v & 0xffff) << 16),
                _ => None,
            },
            "ldr" if src.contains("pc") || imm(src).is_some() => {
                op["ptr"].as_u64().and_then(read32)
            }
            _ => None,
        };
        match value {
            Some(v) => {
                regs.insert(rd, v);
                constants.push(RawConstant {
                    address: addr,
                    function: function.into(),
                    value: v,
                });
            }
            None => {
                regs.remove(&rd);
            }
        }
    }
    (ioctls, constants)
}

fn read32_at(data: &[u8]) -> impl Fn(u64) -> Option<u64> + '_ {
    let elf = goblin::elf::Elf::parse(data).ok();
    let segs: Vec<(u64, u64, u64)> = elf
        .map(|e| {
            e.program_headers
                .iter()
                .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
                .map(|p| (p.p_vaddr, p.p_filesz, p.p_offset))
                .collect()
        })
        .unwrap_or_default();
    move |va| {
        let (v, _, off) = segs.iter().find(|(v, sz, _)| (*v..v + sz).contains(&va))?;
        let o = (off + va - v) as usize;
        data.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
    }
}

pub fn rizin_scan(program: &Path, file: &Path) -> Result<RawScan, String> {
    let mut cmd = Command::new(program);
    cmd.args([
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "scr.interactive=false",
        "-e",
        "bin.relocs.apply=true",
    ]);
    for c in [
        "aa",
        "echo LOAPHONE:imports",
        "iij",
        "echo LOAPHONE:strings",
        "izj",
        "echo LOAPHONE:sections",
        "iSj",
        "echo LOAPHONE:info",
        "ij",
        "echo LOAPHONE:functions",
        "pdfj @@F",
    ] {
        cmd.args(["-c", c]);
    }
    cmd.arg(file);
    let out = run_with_timeout(cmd, RIZIN_TIMEOUT)?;
    let data = fs::read(file).map_err(|e| e.to_string())?;
    parse_rizin(&out, &data)
}

pub fn parse_rizin(out: &str, data: &[u8]) -> Result<RawScan, String> {
    let s = rizin_sections(out);
    let first = |k: &str| {
        s.get(k)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    };
    let info = first("info");
    if info.is_null() {
        return Err("rizin produced no output for this file".into());
    }
    let arm32 = info["bin"]["arch"] == "arm" && info["bin"]["bits"].as_u64() != Some(64);
    let imports = first("imports");
    let ioctl_targets: Vec<(u64, u64)> = imports
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["name"] == "ioctl")
        .filter_map(|i| i["plt"].as_u64().filter(|p| *p != 0))
        .map(|p| (p, p + if arm32 { 8 } else { 4 }))
        .collect();
    let strings = first("strings")
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            Some(RawString {
                address: v["vaddr"].as_u64()?,
                value: v["string"].as_str()?.into(),
            })
        })
        .collect();
    let sections = first("sections")
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["vaddr"].as_u64().is_some_and(|a| a != u64::MAX))
        .map(|v| {
            let start = v["vaddr"].as_u64().unwrap_or(0);
            Section {
                start,
                end: start + v["vsize"].as_u64().unwrap_or(0),
            }
        })
        .collect();
    let read32 = read32_at(data);
    let mut scan = RawScan {
        strings,
        sections,
        ..Default::default()
    };
    for f in s.get("functions").into_iter().flatten() {
        let name = f["name"].as_str().unwrap_or("?");
        let ops = f["ops"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        let (i, c) = track_function(name, ops, &ioctl_targets, arm32, &read32);
        scan.ioctls.extend(i);
        scan.constants.extend(c);
    }
    Ok(scan)
}

// --------------------------------------------------------------- Ghidra ----

/// Creates a fresh directory only this user can access. `create_dir` fails on
/// an existing path, so a pre-created (possibly hostile) directory is never reused.
fn private_temp_dir() -> Result<PathBuf, String> {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    for _ in 0..16 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "loaphone-ghidra-{}-{}-{nanos:08x}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("could not create a private temporary directory".into())
}

pub fn ghidra_scan(program: &Path, file: &Path) -> Result<RawScan, String> {
    let dir = private_temp_dir()?;
    let result = (|| {
        fs::write(dir.join("LoaphoneScan.java"), GHIDRA_SCRIPT).map_err(|e| e.to_string())?;
        let out = dir.join("scan.json");
        let mut cmd = Command::new(program);
        cmd.arg(&dir)
            .arg("loaphone")
            .arg("-import")
            .arg(file)
            .arg("-scriptPath")
            .arg(&dir)
            .arg("-postScript")
            .arg("LoaphoneScan.java")
            .arg(&out)
            .args(["-deleteProject", "-analysisTimeoutPerFile", "600"]);
        run_with_timeout(cmd, GHIDRA_TIMEOUT)?;
        let text =
            fs::read_to_string(&out).map_err(|_| "Ghidra did not produce results".to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

// --------------------------------------------------------- Classification --

const SUBSYSTEMS: &[(u8, &str)] = &[
    (b'I', "ION allocator"),
    (b'F', "fbdev"),
    (b'd', "DRM/KMS"),
    (b'V', "V4L2"),
    (b'A', "ALSA PCM"),
    (b'U', "ALSA control"),
    (b'H', "ALSA hwdep"),
    (b'b', "binder"),
    (b'>', "sync_file"),
    (0x09, "KGSL (Adreno)"),
    (0x97, "QSEECom"),
    (b'a', "MSM audio"),
    (b'm', "MSM display"),
    (b'T', "TTY"),
    (b'u', "uinput"),
    (0xe9, "NXP NFC (pn5xx)"),
];

pub fn decode_ioctl(req: u64) -> (String, Option<&'static str>) {
    let dir = (req >> 30) & 3;
    let size = (req >> 16) & 0x3fff;
    let ty = ((req >> 8) & 0xff) as u8;
    let nr = req & 0xff;
    let ty_s = if ty.is_ascii_graphic() {
        format!("'{}'", ty as char)
    } else {
        format!("0x{ty:02x}")
    };
    let text = match dir {
        0 => format!("_IO({ty_s}, 0x{nr:02x})"),
        1 => format!("_IOW({ty_s}, 0x{nr:02x}, {size})"),
        2 => format!("_IOR({ty_s}, 0x{nr:02x}, {size})"),
        _ => format!("_IOWR({ty_s}, 0x{nr:02x}, {size})"),
    };
    (
        text,
        SUBSYSTEMS.iter().find(|(t, _)| *t == ty).map(|(_, n)| *n),
    )
}

pub fn is_firmware_ref(s: &str) -> bool {
    let l = s.to_lowercase();
    if l.len() < 5 || l.len() > 256 || l.contains(' ') && !l.contains('/') {
        return false;
    }
    let name = l.rsplit('/').next().unwrap_or("");
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    let fw_ext = ["mdt", "mbn", "tlv", "fw", "ucode", "hcd", "nvm"].contains(&ext)
        || (ext.len() == 3
            && ext.starts_with('b')
            && ext[1..].chars().all(|c| c.is_ascii_hexdigit()));
    fw_ext
        || (ext == "bin" && (name.contains("fw") || name.contains("nv") || l.contains("firmware")))
        || (l.starts_with('/') && l.contains("/firmware"))
}

pub fn is_device_node(s: &str) -> bool {
    ["/dev/", "/sys/", "/proc/device-tree"]
        .iter()
        .any(|p| s.starts_with(p))
        && !s.contains(' ')
}

/// Physical MMIO on Android SoCs sits between 16 MiB and 1 GiB. Constants in
/// that window that are word aligned, not a bare power-of-two style flag and
/// not an address inside the binary itself (nor a common f32 such as 1.0f)
/// are reported as candidates.
pub fn is_register_candidate(v: u64, sections: &[Section]) -> bool {
    (0x0100_0000..0x4000_0000).contains(&v)
        && v & 3 == 0
        && v & 0x00ff_ffff != 0
        && v & 0x0fff == 0
        && !(v & 0xffff == 0 && (0x3c..=0x3f).contains(&(v >> 24)))
        && !sections.iter().any(|s| (s.start..s.end).contains(&v))
}

fn cap<T>(v: &mut Vec<T>, truncated: &mut bool) {
    if v.len() > MAX_FINDINGS {
        v.truncate(MAX_FINDINGS);
        *truncated = true;
    }
}

pub fn classify(path: &str, raw: RawScan) -> Findings {
    let raw_truncated = raw.truncated;
    let mut f = Findings {
        path: path.into(),
        ..Default::default()
    };
    for i in raw.ioctls {
        let (decoded, subsystem) = match i.request {
            Some(r) => {
                let (d, s) = decode_ioctl(r);
                (Some(d), s.map(str::to_string))
            }
            None => (None, None),
        };
        f.ioctls.push(IoctlFinding {
            address: format!("0x{:x}", i.address),
            function: i.function,
            request: i.request.map(|r| format!("0x{r:08x}")),
            decoded,
            subsystem,
        });
    }
    let mut seen = BTreeSet::new();
    for s in raw.strings {
        if !seen.insert(s.value.clone()) {
            continue;
        }
        let item = PathFinding {
            address: format!("0x{:x}", s.address),
            value: s.value,
        };
        if is_firmware_ref(&item.value) {
            f.firmware.push(item);
        } else if is_device_node(&item.value) {
            f.nodes.push(item);
        }
    }
    let mut regs = BTreeMap::<u64, RegisterFinding>::new();
    for c in raw.constants {
        if !is_register_candidate(c.value, &raw.sections) {
            continue;
        }
        regs.entry(c.value)
            .and_modify(|r| r.sites += 1)
            .or_insert(RegisterFinding {
                value: format!("0x{:08x}", c.value),
                address: format!("0x{:x}", c.address),
                function: c.function,
                sites: 1,
            });
    }
    f.registers = regs.into_values().collect();
    let mut t = false;
    cap(&mut f.ioctls, &mut t);
    cap(&mut f.firmware, &mut t);
    cap(&mut f.nodes, &mut t);
    cap(&mut f.registers, &mut t);
    f.truncated = t || raw_truncated;
    f
}

pub fn scan_file(backend: &Backend, file: &Path, path: &str) -> Findings {
    let start = Instant::now();
    let raw = match backend.kind {
        Kind::Rizin => rizin_scan(&backend.program, file),
        Kind::Ghidra => ghidra_scan(&backend.program, file),
    };
    let mut f = match raw {
        Ok(raw) => classify(path, raw),
        Err(e) => Findings {
            path: path.into(),
            error: Some(e),
            ..Default::default()
        },
    };
    f.seconds = (start.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    f
}

/// HAL-ish ELF blobs worth a headless pass: shared objects and executables
/// under vendor/odm partitions, skipping firmware images.
pub fn hal_targets(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = vec![];
    for e in walkdir::WalkDir::new(root).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let mut head = [0u8; 4];
        let is_elf = fs::File::open(e.path())
            .and_then(|mut f| f.read_exact(&mut head))
            .is_ok()
            && head == *b"\x7fELF";
        if !is_elf {
            continue;
        }
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap_or(e.path())
            .to_string_lossy()
            .replace('\\', "/");
        out.push((e.path().to_path_buf(), rel));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

pub fn scan_all(
    backend: &Backend,
    targets: Vec<(PathBuf, String)>,
    progress: impl Fn(&Findings) + Sync,
) -> Vec<Findings> {
    let workers = match backend.kind {
        Kind::Rizin => std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2),
        Kind::Ghidra => 1,
    };
    let queue = Arc::new(Mutex::new(
        targets.into_iter().enumerate().collect::<Vec<_>>(),
    ));
    let results = Mutex::new(vec![]);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let Some((i, (file, rel))) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let f = scan_file(backend, &file, &rel);
                    progress(&f);
                    results.lock().unwrap().push((i, f));
                }
            });
        }
    });
    let mut r = results.into_inner().unwrap();
    r.sort_by_key(|(i, _)| *i);
    r.into_iter().map(|(_, f)| f).collect()
}

#[tauri::command]
pub async fn decompiler_status() -> Status {
    tauri::async_runtime::spawn_blocking(|| status_of(detect()))
        .await
        .unwrap_or_else(|_| status_of(None))
}

#[tauri::command]
pub async fn headless_analyze(
    app: tauri::AppHandle,
    codename: String,
    paths: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let w = workspace(&app, &codename)?;
        let status = status_of(detect());
        let Some(backend) = status.backend.clone() else {
            return Ok(serde_json::json!({"status": status, "findings": []}));
        };
        let mut targets = hal_targets(&w.join("blobs"));
        if let Some(p) = paths {
            targets.retain(|(_, rel)| p.contains(rel));
        }
        crate::common::log(
            &app,
            "rea",
            format!("{}: scanning {} ELF blobs", backend.version, targets.len()),
        );
        let findings = scan_all(&backend, targets, |f| {
            let line = match &f.error {
                Some(e) => format!("{}: {e}", f.path),
                None => format!(
                    "{}: {} ioctl, {} firmware, {} register candidates ({}s)",
                    f.path,
                    f.ioctls.len(),
                    f.firmware.len(),
                    f.registers.len(),
                    f.seconds
                ),
            };
            crate::common::log(&app, "rea", line);
        });
        let report = serde_json::json!({"status": status, "findings": findings});
        fs::write(
            w.join("headless.json"),
            serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        Ok(report)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(p: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(p)
    }

    fn rizin_backend() -> Option<Backend> {
        let b = rizin();
        if b.is_none() && std::env::var_os("LOAPHONE_REQUIRE_RIZIN").is_some() {
            panic!("LOAPHONE_REQUIRE_RIZIN is set but rizin is not on PATH");
        }
        b
    }

    #[test]
    fn private_temp_dir_is_fresh_and_owner_only() {
        let a = private_temp_dir().unwrap();
        let b = private_temp_dir().unwrap();
        assert_ne!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
        }
        fs::remove_dir(a).unwrap();
        fs::remove_dir(b).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_kills_the_whole_process_group() {
        let pidfile = private_temp_dir().unwrap().join("pid");
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("sleep 30 & echo $! > {}; wait", pidfile.display()));
        let err = run_with_timeout(cmd, Duration::from_millis(300)).unwrap_err();
        assert!(err.starts_with("timed out"), "{err}");
        let pid = fs::read_to_string(&pidfile).unwrap();
        // Gone, or a zombie waiting for a reaper, both count as terminated.
        let alive = || {
            fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
                .ok()
                .and_then(|st| st.rsplit(')').next().map(|r| r.trim_start().to_string()))
                .is_some_and(|r| !r.starts_with('Z'))
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let alive = alive();
        fs::remove_dir_all(pidfile.parent().unwrap()).unwrap();
        assert!(!alive, "background sleep {pid} survived the timeout");
    }

    #[test]
    fn tracker_keeps_values_across_reads_and_drops_them_at_joins() {
        let ops: Vec<serde_json::Value> = serde_json::from_str(r#"[
            {"offset":0,"type":"mov","opcode":"mov w1, 0x4901"},
            {"offset":4,"type":"cmp","opcode":"cmp w1, 3"},
            {"offset":8,"type":"store","opcode":"str w1, [sp, 8]"},
            {"offset":12,"type":"call","opcode":"bl 0x630","jump":1584},
            {"offset":16,"type":"cjmp","opcode":"b.ne 0x24","jump":36},
            {"offset":20,"type":"mov","opcode":"mov w1, 0x4902"},
            {"offset":24,"type":"jmp","opcode":"b 0x28","jump":40},
            {"offset":36,"type":"mov","opcode":"mov w1, 0x4903"},
            {"offset":40,"type":"call","opcode":"bl 0x630","jump":1584}
        ]"#).unwrap();
        let (i, _) = track_function("f", &ops, &[(0x630, 0x634)], false, &|_| None);
        assert_eq!(i[0].request, Some(0x4901), "cmp/str must not clobber w1");
        assert_eq!(i[1].request, None, "two paths reach the second call");
    }

    #[test]
    fn backend_truncation_marks_findings_incomplete() {
        let raw: RawScan = serde_json::from_str(
            r#"{"ioctls":[],"strings":[],"constants":[],"sections":[],"truncated":true}"#,
        )
        .unwrap();
        assert!(classify("a.so", raw).truncated);
        assert!(!classify("b.so", RawScan::default()).truncated);
    }

    #[test]
    fn exclusive_store_status_register_is_not_a_constant() {
        let ops: Vec<serde_json::Value> = serde_json::from_str(r#"[
            {"offset":0,"type":"mov","opcode":"movw r1, 0x5003"},
            {"offset":4,"type":"store","opcode":"strex r1, r2, [r3]"},
            {"offset":8,"type":"call","opcode":"blx 0x3b8","jump":952}
        ]"#).unwrap();
        let (i, _) = track_function("f", &ops, &[(0x3b4, 0x3bc)], true, &|_| None);
        assert_eq!(i[0].request, None);
    }

    #[test]
    fn missing_backend_reports_message_instead_of_failing() {
        let s = status_of(None);
        assert!(!s.available);
        assert!(s.message.contains("Neither Rizin nor Ghidra"));
    }

    #[test]
    fn decodes_ioctl_requests() {
        assert_eq!(
            decode_ioctl(0xc0144900),
            ("_IOWR('I', 0x00, 20)".into(), Some("ION allocator"))
        );
        assert_eq!(decode_ioctl(0x40085003).0, "_IOW('P', 0x03, 8)");
        assert_eq!(decode_ioctl(0x5009).0, "_IO('P', 0x09)");
    }

    #[test]
    fn classifies_strings_and_constants() {
        for s in [
            "%s/%s.mdt",
            "btfw30.tlv",
            "crnv32u.bin",
            "/vendor/firmware/image/gptauuid.xml",
            "a630_zap.b02",
        ] {
            assert!(is_firmware_ref(s), "{s}");
        }
        for s in [
            "libc.so",
            "output.bin",
            "Error reading from %s file",
            "/data/vendor/misc",
        ] {
            assert!(!is_firmware_ref(s), "{s}");
        }
        assert!(is_device_node("/sys/class/leds/blue/brightness"));
        assert!(!is_device_node("/vendor/lib64"));
        let image = [Section {
            start: 0x0100_0000,
            end: 0x0110_0000,
        }];
        assert!(is_register_candidate(0x0ae0_0000, &image));
        assert!(
            !is_register_candidate(0x0100_8000, &image),
            "inside the binary"
        );
        assert!(
            !is_register_candidate(0x4008_5003, &image),
            "ioctl request range"
        );
        assert!(!is_register_candidate(0x0200_0000, &image), "bare flag");
        assert!(
            !is_register_candidate(0x0ae0_0004, &image),
            "not page aligned"
        );
        assert!(!is_register_candidate(0x3f80_0000, &image), "1.0f");
    }

    #[test]
    fn tracks_arm64_movz_movk_and_arm32_movw_movt() {
        let ops: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
            {"offset":16,"type":"mov","opcode":"mov w1, 0x5003"},
            {"offset":20,"type":"mov","opcode":"movk w1, 0x4008, lsl 16"},
            {"offset":24,"type":"call","opcode":"bl 0x630","jump":1584},
            {"offset":28,"type":"mov","opcode":"mov x5, 0x7000"},
            {"offset":32,"type":"mov","opcode":"movk x5, 0x1d8, lsl 16"}
        ]"#,
        )
        .unwrap();
        let (i, c) = track_function("f", &ops, &[(0x630, 0x634)], false, &|_| None);
        assert_eq!(
            i,
            vec![RawIoctl {
                address: 24,
                function: "f".into(),
                request: Some(0x4008_5003)
            }]
        );
        assert!(c.iter().any(|c| c.value == 0x01d8_7000));
        let ops: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
            {"offset":1,"type":"mov","opcode":"movw r1, 0x5003"},
            {"offset":2,"type":"mov","opcode":"movt r1, 0x4008"},
            {"offset":3,"type":"load","opcode":"ldr r2, [pc, 0x3c]","ptr":64},
            {"offset":4,"type":"jmp","opcode":"b.w 0x3b8","jump":952}
        ]"#,
        )
        .unwrap();
        let (i, c) = track_function("g", &ops, &[(0x3b4, 0x3bc)], true, &|p| {
            (p == 64).then_some(0x0ae0_0000)
        });
        assert_eq!(i[0].request, Some(0x4008_5003));
        assert!(c.iter().any(|c| c.value == 0x0ae0_0000));
    }

    fn assert_synthetic(f: &Findings) {
        assert_eq!(f.error, None);
        let reqs: Vec<_> = f
            .ioctls
            .iter()
            .filter_map(|i| i.decoded.as_deref())
            .collect();
        assert!(reqs.contains(&"_IOW('P', 0x03, 8)"), "{reqs:?}");
        assert!(reqs.contains(&"_IO('P', 0x09)"), "{reqs:?}");
        assert!(
            f.firmware
                .iter()
                .any(|p| p.value == "/vendor/firmware/probe/probe_fw.mdt")
        );
        assert!(f.nodes.iter().any(|p| p.value == "/dev/probe0"));
        let regs: Vec<_> = f.registers.iter().map(|r| r.value.as_str()).collect();
        assert!(
            regs.contains(&"0x0ae00000") && regs.contains(&"0x01d87000"),
            "{regs:?}"
        );
    }

    #[test]
    fn rizin_finds_synthetic_hal_evidence() {
        let Some(b) = rizin_backend() else { return };
        for arch in ["arm64", "arm"] {
            let p = format!("libhalprobe.{arch}.so");
            assert_synthetic(&scan_file(&b, &fixture(&format!("synthetic/{p}")), &p));
        }
    }

    #[test]
    fn rizin_scans_lineage_vendor_blobs() {
        let Some(b) = rizin_backend() else { return };
        let root = fixture("lineage-sargo");
        let targets = hal_targets(&root);
        assert_eq!(targets.len(), 4);
        let all = scan_all(&b, targets, |_| {});
        let get = |p: &str| all.iter().find(|f| f.path == p).unwrap();
        let g = get("vendor/lib64/libgralloccore.so");
        assert!(
            g.ioctls
                .iter()
                .any(|i| i.subsystem.as_deref() == Some("ION allocator")),
            "{:?}",
            g.ioctls
        );
        assert!(!get("vendor/lib/libgralloccore.so").ioctls.is_empty());
        let lights = get("vendor/lib64/hw/lights.qcom.so");
        assert!(
            lights
                .nodes
                .iter()
                .any(|n| n.value.starts_with("/sys/class/leds/"))
        );
        let nfc = get("vendor/lib64/nfc_nci_nxp.so");
        assert!(!nfc.firmware.is_empty() || !nfc.nodes.is_empty(), "{nfc:?}");
        println!("{}", serde_json::to_string_pretty(&all).unwrap());
    }

    #[test]
    fn ghidra_finds_synthetic_hal_evidence() {
        if std::env::var_os("LOAPHONE_TEST_GHIDRA").is_none() {
            return;
        }
        let b = ghidra().expect("LOAPHONE_TEST_GHIDRA is set but analyzeHeadless was not found");
        assert_synthetic(&scan_file(
            &b,
            &fixture("synthetic/libhalprobe.arm64.so"),
            "libhalprobe.arm64.so",
        ));
    }
}
