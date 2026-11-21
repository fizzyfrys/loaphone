import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

type BuildReport = {
  source: string; source_sha256: string; checksum_verified: boolean; sha256: string;
  original_bytes: number; output_bytes: number; overlay_files_added: number;
  profile_actions: string[]; warnings: string[]; output_path: string; sparse_path: string | null;
};
type Props = {
  codename: string; setCodename: (name: string) => void; busy: boolean;
  run: <T>(action: () => Promise<T>, success?: (result: T) => void) => Promise<void>;
  useImage: (path: string, source: string) => void;
  onBuilt: () => void;
};

export default function RootfsBuilder({ codename, setCodename, busy, run, useImage, onBuilt }: Props) {
  const [source, setSource] = useState("pmos"), [local, setLocal] = useState("");
  const [headless, setHeadless] = useState(true), [key, setKey] = useState("");
  const [headroom, setHeadroom] = useState(512), [sparse, setSparse] = useState(false), [api, setApi] = useState(28);
  const [report, setReport] = useState<BuildReport | null>(null);
  useEffect(() => { setReport(null); }, [codename, source, local, headless, key, headroom, sparse, api]);
  const mib = (n: number) => `${(n / 1048576).toFixed(1)} MiB`;
  return <>
    <section className="callout"><h3>A prepared filesystem, not a device port</h3><p>Build an unmounted ext4 copy with your device overlay and optional SSH / USB-network profile. Original files are untouched. You still need a compatible boot image and installation layout.</p></section>
    <section className="panel">
      <div className="fields"><label>Device codename<input disabled={busy} value={codename} onChange={e => setCodename(e.target.value)} placeholder="e.g. enchilada" /></label>
        <label>Image source<select disabled={busy} value={source} onChange={e => setSource(e.target.value)}><option value="pmos">postmarketOS for this device</option><option value="droidian">Droidian generic arm64</option><option value="local">Local file (img / img.xz / zip)</option></select></label></div>
      {source === "pmos" && <p className="muted">Resolves the latest published device image and verifies its indexed SHA-256. Console is preferred; if unavailable, graphical packages remain. Published mappings: sargo, enchilada, fajita.</p>}
      {source === "droidian" && <><label>Android / Halium API<select disabled={busy} value={api} onChange={e => setApi(Number(e.target.value))}>{[28, 29, 30, 32, 33].map(n => <option key={n} value={n}>API {n}</option>)}</select></label><div className="notice">Upstream Droidian installs data/rootfs.img inside /data. This builder exports that inner image, NOT a ready-to-flash userdata container. Follow your device port’s installation instructions. API level must match your Halium boot image.</div></>}
      {source === "local" && <label className="file">Local source<div><input disabled={busy} value={local} onChange={e => setLocal(e.target.value)} placeholder="/path/to/rootfs.img" /><button disabled={busy} onClick={async () => { const p = await open({ multiple: false, filters: [{ name: "Root filesystem", extensions: ["img", "xz", "zip"] }] }); if (typeof p === "string") setLocal(p); }}>Browse</button></div></label>}
      <div className="fields"><label>Additional headroom (MiB)<input disabled={busy} type="number" min="0" max="32768" step="64" value={headroom} onChange={e => setHeadroom(Number(e.target.value))} /></label></div>
      <label className="check"><input disabled={busy} type="checkbox" checked={headless} onChange={e => setHeadless(e.target.checked)} /> Apply headless server profile</label>
      {headless && <><p className="muted">Enables installed SSH services. Systemd selects multi-user target and adds static NCM/RNDIS networking at 172.16.42.1/24 (host: 172.16.42.2/24, no DHCP), unless existing pmOS USB configuration is verified and preserved. OpenRC enables sshd and verifies pmOS USB configuration. No packages are installed or removed.</p><label>Optional SSH public key<input disabled={busy} value={key} onChange={e => setKey(e.target.value)} placeholder="ssh-ed25519 AAAA…" /></label><p className="muted">Adds the key for root, explicitly allowing key-only root SSH; existing distro users stay unchanged. Without a key, distro authentication defaults remain. Existing USB gadget services may conflict; review on target.</p></>}
      <label className="check"><input disabled={busy} type="checkbox" checked={sparse} onChange={e => setSparse(e.target.checked)} /> Also create Android sparse output (if img2simg is installed)</label>
      <p className="muted">Needs e2fsprogs (1.47+ for current pmOS images) and xz-utils on the host; no sudo, mounts or emulation. Build a device overlay in REA Inspector first. Downloads are cached in this device’s rootfs/cache directory.</p>
      <button className="primary" disabled={busy || !codename || (source === "local" && !local) || !Number.isInteger(headroom) || headroom < 0 || headroom > 32768} onClick={() => { setReport(null); run(() => invoke<BuildReport>("build_rootfs", { params: { codename, source, local_path: local || null, android_api: api, headless, ssh_key: key || null, headroom_mib: headroom, sparse } }), result => { setReport(result); onBuilt(); }); }}>{busy ? "Building… see activity log" : "Build rootfs"}</button>
    </section>
    {report && <section className="panel"><div className="section-head"><h3>Rootfs ready</h3><span className="pill">ext4 / raw</span></div><p className="path">{report.output_path}</p><dl><div><dt>Source</dt><dd className="path">{report.source}</dd></div><div><dt>Size</dt><dd>{mib(report.original_bytes)} → {mib(report.output_bytes)}</dd></div><div><dt>Overlay</dt><dd>{report.overlay_files_added} files added</dd></div><div><dt>Source checksum</dt><dd>{report.checksum_verified ? "Published SHA-256 verified" : "Computed only (not independently verified)"}</dd></div></dl><details><summary>SHA-256 hashes</summary><p className="path">Source: {report.source_sha256}</p><p className="path">Output: {report.sha256}</p></details>{report.profile_actions.map(a => <p key={a}>{a}</p>)}{report.warnings.map(w => <div className="notice" key={w}>{w}</div>)}{report.sparse_path && <p className="path">Sparse: {report.sparse_path}</p>}<button className="primary" onClick={() => useImage(report.output_path, source)}>Use in Flasher</button><p className="muted">Fills the raw-image path only. Does not flash, choose boot images or establish device compatibility.</p></section>}
  </>;
}
