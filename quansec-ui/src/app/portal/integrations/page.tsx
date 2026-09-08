"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { ShieldCheck, ShieldAlert, Download, Copy, Check, Radio } from "lucide-react";
import { authHeaders as bearerHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";
import { SHOWCASE_MODE } from "@/lib/mock/mode";

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";
function authHeaders(json = false): HeadersInit {
  // Authorization comes from the in-memory access token; see
  // src/lib/auth-fetch.ts. Nothing is read from localStorage.
  const h: Record<string, string> = { ...bearerHeaders() };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

// Set per copy: "ipsec" or "ssh"
const PROTOCOL: string = "ipsec";

interface FailModeInfo {
  mode: string;
  kex?: string;
  proposal?: string;
  desc: string;
}

export default function IntegrationsPage() {
  const [failmode, setFailmode] = useState<FailModeInfo | null>(null);
  const [applying, setApplying] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const load = async () => {
    try {
      const d = await mockFetch(`/api/failmode`, { headers: authHeaders() }).then((r) => r.json());
      setFailmode(d[PROTOCOL]);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const toggle = async (mode: string) => {
    setApplying(true);
    try {
      await mockFetch(`/api/failmode/set`, {
        method: "POST", headers: authHeaders(true),
        body: JSON.stringify({ protocol: PROTOCOL, mode }),
      });
      await load();
    } finally { setApplying(false); }
  };

  const copyEndpoint = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopied(url); setTimeout(() => setCopied(null), 2000);
  };

  const fetchEndpoint = (fmt: string, url: string) => {
    if (!SHOWCASE_MODE) {
      window.open(url, "_blank", "noreferrer");
      return;
    }
    const sample: Record<string, string> = {
      CEF: `CEF:0|QUANSEC|IPsec|1.0|policy.apply|Policy applied: pqc-level5|3|src=10.20.0.1 dst=10.20.0.2 cs1Label=kem cs1=ML-KEM-1024`,
      JSON: JSON.stringify({ event: "policy.apply", protocol: "ipsec", policy: "pqc-level5", occurred_at: new Date().toISOString() }, null, 2),
      Syslog: `<134>1 ${new Date().toISOString()} quansec ipsec - - - policy.apply policy="pqc-level5" pqc_enabled=true`,
    };
    const blob = new Blob([sample[fmt] ?? ""], { type: "text/plain" });
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl; a.download = `quansec-siem-events.${fmt.toLowerCase()}`; a.click();
    URL.revokeObjectURL(blobUrl);
  };

  const isClosed = failmode?.mode === "fail-closed";

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--lattice-violet-dim)" }}>
          Crypto-Agility
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>Failure Mode & Export</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-primary)" }}>
          Configure failure behavior and export events to your SIEM
        </p>
      </div>

      {/* Fail mode toggle */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Safety Control" title="Failure Mode" />
        <div className="px-5 py-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button onClick={() => toggle("fail-closed")} disabled={applying}
              className="text-left rounded-xl border p-5 transition-all focus-ring disabled:opacity-50"
              style={{ background: isClosed ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)", borderColor: isClosed ? "var(--pqc-cyan-dim)" : "var(--border-hairline)" }}>
              <div className="flex items-center gap-2 mb-2">
                <ShieldCheck size={18} style={{ color: "var(--pqc-cyan)" }} />
                <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Fail-Closed</span>
                {isClosed && <span className="ml-auto text-[10px] font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--pqc-cyan)", color: "#04201c" }}>ACTIVE</span>}
              </div>
              <p className="text-xs leading-relaxed" style={{ color: "var(--text-primary)" }}>
                If PQC can&apos;t be negotiated, refuse the connection. No classical downgrade. Maximum security.
              </p>
            </button>

            <button onClick={() => toggle("fail-open")} disabled={applying}
              className="text-left rounded-xl border p-5 transition-all focus-ring disabled:opacity-50"
              style={{ background: !isClosed ? "var(--threat-amber-glow)" : "var(--bg-panel-raised)", borderColor: !isClosed ? "var(--threat-amber-dim)" : "var(--border-hairline)" }}>
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert size={18} style={{ color: "var(--threat-amber)" }} />
                <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Fail-Open</span>
                {!isClosed && <span className="ml-auto text-[10px] font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--threat-amber)", color: "#2a1a04" }}>ACTIVE</span>}
              </div>
              <p className="text-xs leading-relaxed" style={{ color: "var(--text-primary)" }}>
                If PQC can&apos;t be negotiated, allow classical fallback. Preserves uptime. Lower security.
              </p>
            </button>
          </div>
          {failmode && (
            <div className="mt-4 px-4 py-3 rounded-lg font-mono-display text-xs" style={{ background: "var(--bg-panel-raised)", color: "var(--text-primary)" }}>
              Current config: {failmode.kex || failmode.proposal}
            </div>
          )}
        </div>
      </Panel>

      {/* SIEM export card */}
      <Panel>
        <PanelHeader eyebrow="Integration" title="SIEM Export" />
        <div className="px-5 py-5">
          <p className="text-sm mb-4" style={{ color: "var(--text-primary)" }}>
            Stream security events to Splunk, QRadar, ArcSight, or Elastic. Supports CEF, JSON, and syslog.
          </p>
          <div className="space-y-2.5">
            {[
              { fmt: "CEF", url: `${API_BASE}/api/siem/events?format=cef`, desc: "ArcSight / Splunk / QRadar" },
              { fmt: "JSON", url: `${API_BASE}/api/siem/events?format=json`, desc: "Elastic / generic" },
              { fmt: "Syslog", url: `${API_BASE}/api/siem/events?format=syslog`, desc: "RFC 5424" },
            ].map((row) => (
              <div key={row.fmt} className="flex items-center justify-between gap-3 px-4 py-3 rounded-lg" style={{ background: "var(--bg-panel-raised)" }}>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--lattice-violet-glow)", color: "var(--lattice-violet)" }}>{row.fmt}</span>
                    <span className="text-xs" style={{ color: "var(--text-primary)" }}>{row.desc}</span>
                  </div>
                  <div className="text-[11px] font-mono-display mt-1 truncate" style={{ color: "var(--text-tertiary)" }}>{row.url}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button onClick={() => copyEndpoint(row.url)} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-mono-display focus-ring" style={{ background: "var(--bg-panel)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}>
                    {copied === row.url ? <Check size={11} style={{ color: "var(--pqc-cyan)" }} /> : <Copy size={11} />}
                    {copied === row.url ? "Copied" : "Copy"}
                  </button>
                  <button onClick={() => fetchEndpoint(row.fmt, row.url)} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-mono-display focus-ring" style={{ background: "var(--bg-panel)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}>
                    <Download size={11} /> Fetch
                  </button>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-2 text-[11px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>
            <Radio size={11} /> Prometheus metrics also exposed at {API_BASE}/metrics
          </div>
        </div>
      </Panel>
    </div>
  );
}
