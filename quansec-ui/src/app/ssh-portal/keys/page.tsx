"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { Copy, Check, Plus, Trash2, X, KeyRound, AlertTriangle } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";
function authHeaders(json = false): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("quansec_token") : null;
  const h: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  if (json) h["Content-Type"] = "application/json";
  return h;
}

interface ApiKey { id: number; name: string; key_prefix: string; last_used: string | null; revoked: boolean; }

export default function SshKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showForm, setShowForm] = useState(false);

  const load = async () => {
    try {
      const r = await fetch(`${API_BASE}/api/keys`, { headers: authHeaders() });
      const data = await r.json();
      setKeys(Array.isArray(data) ? data : []);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!name.trim()) return;
    setCreating(true);
    try {
      const r = await fetch(`${API_BASE}/api/keys`, { method: "POST", headers: authHeaders(true), body: JSON.stringify({ name: name.trim() }) });
      const data = await r.json();
      setRevealed(data.api_key);
      setName(""); setShowForm(false);
      await load();
    } finally { setCreating(false); }
  };

  const revoke = async (id: number) => {
    await fetch(`${API_BASE}/api/keys/${id}`, { method: "DELETE", headers: authHeaders() });
    await load();
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8 flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--lattice-violet-dim)" }}>Integration</div>
          <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>API Keys</h1>
          <p className="text-sm mt-1.5 max-w-lg" style={{ color: "var(--text-secondary)" }}>
            Use an API key to query your SSH sessions&apos; quantum-safe status from your own systems.
          </p>
        </div>
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold focus-ring shrink-0"
          style={{ background: "var(--lattice-violet)", color: "#1a0f3d" }}>
          <Plus size={15} /> Generate new key
        </button>
      </div>

      {revealed && (
        <Panel className="mb-6 overflow-hidden">
          <div className="px-5 py-4" style={{ background: "var(--lattice-violet-glow)", borderBottom: "1px solid var(--lattice-violet-dim)" }}>
            <div className="flex items-start gap-3">
              <AlertTriangle size={16} style={{ color: "var(--lattice-violet)" }} className="shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-bold mb-1" style={{ color: "var(--lattice-violet)" }}>Save this key now — it won&apos;t be shown again</div>
                <div className="text-xs" style={{ color: "var(--text-secondary)" }}>Store it in your environment variables.</div>
              </div>
              <button onClick={() => setRevealed(null)} className="focus-ring"><X size={16} style={{ color: "var(--text-tertiary)" }} /></button>
            </div>
          </div>
          <div className="px-5 py-4 flex items-center gap-3">
            <code className="flex-1 px-3.5 py-2.5 rounded-lg text-xs font-mono-display overflow-x-auto whitespace-nowrap"
              style={{ background: "var(--bg-panel-raised)", color: "var(--lattice-violet)" }}>{revealed}</code>
            <button onClick={() => { navigator.clipboard.writeText(revealed); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              className="flex items-center gap-1.5 px-3 py-2.5 rounded-lg text-xs font-mono-display shrink-0 focus-ring"
              style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}>
              {copied ? <Check size={13} style={{ color: "var(--lattice-violet)" }} /> : <Copy size={13} />}{copied ? "Copied" : "Copy"}
            </button>
          </div>
        </Panel>
      )}

      {showForm && (
        <Panel className="mb-6 px-5 py-5">
          <div className="text-sm font-semibold mb-3" style={{ color: "var(--text-primary)" }}>Name this key</div>
          <div className="flex gap-3">
            <input autoFocus value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && create()}
              placeholder="e.g. Monitoring server" className="flex-1 px-3.5 py-2.5 rounded-lg text-sm outline-none focus-ring"
              style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }} />
            <button onClick={create} disabled={creating || !name.trim()} className="px-4 py-2.5 rounded-lg text-sm font-bold disabled:opacity-50 focus-ring"
              style={{ background: "var(--lattice-violet)", color: "#1a0f3d" }}>{creating ? "Creating…" : "Create"}</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-2.5 rounded-lg text-sm focus-ring"
              style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)", border: "1px solid var(--border-hairline-bright)" }}>Cancel</button>
          </div>
        </Panel>
      )}

      <Panel>
        <PanelHeader eyebrow={`${keys.filter((k) => !k.revoked).length} active`} title="Your keys" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {keys.length === 0 && (
            <div className="px-5 py-12 text-center">
              <KeyRound size={28} className="mx-auto mb-3" style={{ color: "var(--text-tertiary)" }} />
              <div className="text-sm" style={{ color: "var(--text-secondary)" }}>No API keys yet</div>
            </div>
          )}
          {keys.map((k) => (
            <div key={k.id} className="px-5 py-4 flex items-center justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{k.name}</span>
                  {k.revoked && <span className="text-[10px] font-mono-display px-1.5 py-0.5 rounded" style={{ background: "var(--danger-glow)", color: "var(--danger-red)" }}>REVOKED</span>}
                </div>
                <div className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>{k.key_prefix}</div>
              </div>
              {!k.revoked && (
                <button onClick={() => revoke(k.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display shrink-0 focus-ring" style={{ color: "var(--text-tertiary)" }}>
                  <Trash2 size={13} /> Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
