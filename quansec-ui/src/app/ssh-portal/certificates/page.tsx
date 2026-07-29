"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { ShieldCheck, Copy, Check, Download, KeyRound, AlertTriangle, Fingerprint } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";
function authHeaders(json = false): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("quansec_token") : null;
  const h: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  if (json) h["Content-Type"] = "application/json";
  return h;
}

interface IssuedCert {
  serial: number; identity: string; principals: string; valid_hours: number;
  issued_at: string; expires_at: string; revoked: boolean; expired: boolean;
}

export default function CertificatesPage() {
  const [caInfo, setCaInfo] = useState<{ ca_public_key: string; fingerprint: string } | null>(null);
  const [issued, setIssued] = useState<IssuedCert[]>([]);
  const [publicKey, setPublicKey] = useState("");
  const [identity, setIdentity] = useState("");
  const [principals, setPrincipals] = useState("hd6441");
  const [hours, setHours] = useState(8);
  const [result, setResult] = useState<{ certificate: string; filename: string; serial: number } | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const load = async () => {
    try {
      const [ca, list] = await Promise.all([
        fetch(`${API_BASE}/api/ssh/ca/info`, { headers: authHeaders() }).then((r) => r.json()),
        fetch(`${API_BASE}/api/ssh/ca/issued`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setCaInfo(ca);
      setIssued(Array.isArray(list) ? list : []);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const issue = async () => {
    setError(""); setResult(null); setIssuing(true);
    try {
      const res = await fetch(`${API_BASE}/api/ssh/ca/issue`, {
        method: "POST", headers: authHeaders(true),
        body: JSON.stringify({ public_key: publicKey.trim(), identity: identity.trim(), principals: principals.trim(), valid_hours: hours }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "issue failed");
      setResult(data);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "error");
    } finally { setIssuing(false); }
  };

  const download = () => {
    if (!result) return;
    const blob = new Blob([result.certificate + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = result.filename; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--lattice-violet-dim)" }}>
          Certificate Authority
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>Issue Certificate</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-primary)" }}>
          Onboard a user: sign their public key into a short-lived Zero Trust certificate
        </p>
      </div>

      {/* CA info */}
      {caInfo && (
        <Panel className="mb-6 px-5 py-4">
          <div className="flex items-center gap-2 mb-2">
            <Fingerprint size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>QUANSEC CA Fingerprint</span>
          </div>
          <div className="text-xs font-mono-display" style={{ color: "var(--text-primary)" }}>{caInfo.fingerprint}</div>
        </Panel>
      )}

      {/* Issue form */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Onboarding" title="Sign a User Public Key" />
        <div className="px-5 py-5 space-y-4">
          <div className="flex items-start gap-2 px-3.5 py-2.5 rounded-lg" style={{ background: "var(--threat-amber-glow)", border: "1px solid var(--threat-amber-dim)" }}>
            <AlertTriangle size={14} style={{ color: "var(--threat-amber)" }} className="shrink-0 mt-0.5" />
            <span className="text-xs" style={{ color: "var(--text-primary)" }}>
              The user submits only their <b>public</b> key. Their private key never leaves their device.
            </span>
          </div>

          <div>
            <label className="block text-xs font-mono-display font-bold uppercase tracking-wide mb-2" style={{ color: "var(--text-primary)" }}>User Public Key</label>
            <textarea value={publicKey} onChange={(e) => setPublicKey(e.target.value)} rows={3}
              placeholder="ssh-ed25519 AAAAC3Nza... user@device"
              className="w-full px-3.5 py-2.5 rounded-lg text-xs font-mono-display outline-none focus-ring resize-none"
              style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-mono-display font-bold uppercase tracking-wide mb-2" style={{ color: "var(--text-primary)" }}>Identity</label>
              <input value={identity} onChange={(e) => setIdentity(e.target.value)} placeholder="alice@bank.com"
                className="w-full px-3.5 py-2.5 rounded-lg text-sm outline-none focus-ring"
                style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }} />
            </div>
            <div>
              <label className="block text-xs font-mono-display font-bold uppercase tracking-wide mb-2" style={{ color: "var(--text-primary)" }}>Principals</label>
              <input value={principals} onChange={(e) => setPrincipals(e.target.value)} placeholder="hd6441"
                className="w-full px-3.5 py-2.5 rounded-lg text-sm outline-none focus-ring"
                style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }} />
            </div>
            <div>
              <label className="block text-xs font-mono-display font-bold uppercase tracking-wide mb-2" style={{ color: "var(--text-primary)" }}>Valid (hours)</label>
              <input type="number" value={hours} min={1} max={168} onChange={(e) => setHours(parseInt(e.target.value) || 8)}
                className="w-full px-3.5 py-2.5 rounded-lg text-sm outline-none focus-ring"
                style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }} />
            </div>
          </div>

          {error && (
            <div className="px-3.5 py-2.5 rounded-lg text-xs font-mono-display" style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>{error}</div>
          )}

          <button onClick={issue} disabled={issuing || !publicKey.trim() || !identity.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-bold disabled:opacity-50 focus-ring"
            style={{ background: "var(--lattice-violet)", color: "#1a0f3d" }}>
            <ShieldCheck size={15} /> {issuing ? "Signing…" : "Issue Certificate"}
          </button>
        </div>
      </Panel>

      {/* Result */}
      {result && (
        <Panel className="mb-6 overflow-hidden">
          <div className="px-5 py-4" style={{ background: "var(--pqc-cyan-glow)", borderBottom: "1px solid var(--pqc-cyan-dim)" }}>
            <div className="flex items-center gap-2">
              <ShieldCheck size={16} style={{ color: "var(--pqc-cyan)" }} />
              <span className="text-sm font-bold" style={{ color: "var(--pqc-cyan)" }}>Certificate issued — serial #{result.serial}</span>
            </div>
          </div>
          <div className="px-5 py-4">
            <div className="text-xs font-mono-display mb-3 break-all px-3.5 py-3 rounded-lg" style={{ background: "var(--bg-panel-raised)", color: "var(--text-primary)", maxHeight: 120, overflow: "auto" }}>
              {result.certificate}
            </div>
            <div className="flex gap-3">
              <button onClick={download} className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold focus-ring" style={{ background: "var(--pqc-cyan)", color: "#04201c" }}>
                <Download size={13} /> Download {result.filename}
              </button>
              <button onClick={() => { navigator.clipboard.writeText(result.certificate); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono-display focus-ring" style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}>
                {copied ? <Check size={13} style={{ color: "var(--pqc-cyan)" }} /> : <Copy size={13} />} {copied ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        </Panel>
      )}

      {/* Issued certificates */}
      <Panel>
        <PanelHeader eyebrow={`${issued.length} issued`} title="Issued Certificates" />
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left border-b" style={{ borderColor: "var(--border-hairline)" }}>
                {["Serial", "Identity", "Principals", "Issued", "Status"].map((h) => (
                  <th key={h} className="px-4 py-2.5 font-mono-display text-[10px] uppercase tracking-wider font-bold" style={{ color: "var(--text-primary)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {issued.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-10 text-center text-sm" style={{ color: "var(--text-primary)" }}>No certificates issued yet</td></tr>
              )}
              {issued.map((c) => (
                <tr key={c.serial} className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>#{c.serial}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--lattice-violet)" }}>{c.identity}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>{c.principals}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>{new Date(c.issued_at).toLocaleString()}</td>
                  <td className="px-4 py-3">
                    {c.revoked ? <span className="font-mono-display font-bold" style={{ color: "var(--danger-red)" }}>REVOKED</span>
                      : c.expired ? <span className="font-mono-display font-bold" style={{ color: "var(--threat-amber)" }}>EXPIRED</span>
                      : <span className="font-mono-display font-bold" style={{ color: "var(--pqc-cyan)" }}>VALID</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
