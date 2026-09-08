"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader, PageHeader, EmptyState, ConfirmDialog, DismissButton } from "@/components/ui-primitives";
import { Copy, Check, Plus, Trash2, KeyRound, AlertTriangle } from "lucide-react";
import { authHeaders as bearerHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

function authHeaders(json = false): HeadersInit {
  // Authorization comes from the in-memory access token; see
  // src/lib/auth-fetch.ts. Nothing is read from localStorage.
  const h: Record<string, string> = { ...bearerHeaders() };
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
  const [confirmRevoke, setConfirmRevoke] = useState<ApiKey | null>(null);

  const load = async () => {
    try {
      const r = await mockFetch(`/api/keys`, { headers: authHeaders() });
      const data = await r.json();
      setKeys(Array.isArray(data) ? data : []);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!name.trim()) return;
    setCreating(true);
    try {
      const r = await mockFetch(`/api/keys`, { method: "POST", headers: authHeaders(true), body: JSON.stringify({ name: name.trim() }) });
      const data = await r.json();
      setRevealed(data.api_key);
      setName(""); setShowForm(false);
      await load();
    } finally { setCreating(false); }
  };

  const revoke = async (key: ApiKey) => {
    await mockFetch(`/api/keys/${key.id}`, { method: "DELETE", headers: authHeaders() });
    setConfirmRevoke(null);
    await load();
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <PageHeader
        eyebrow="Integration"
        title="API keys"
        description="Use an API key to query your SSH sessions' quantum-safe status from your own systems."
        accent="var(--lattice-violet)"
        actions={
          <button onClick={() => setShowForm(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold focus-ring shrink-0"
            style={{ background: "var(--lattice-violet)", color: "#1a0f3d" }}>
            <Plus size={15} /> Generate new key
          </button>
        }
      />

      {revealed && (
        <Panel className="mb-6 overflow-hidden">
          <div className="px-5 py-4" style={{ background: "var(--lattice-violet-glow)", borderBottom: "1px solid var(--lattice-violet-dim)" }}>
            <div className="flex items-start gap-3">
              <AlertTriangle size={16} style={{ color: "var(--lattice-violet)" }} className="shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-bold mb-1" style={{ color: "var(--lattice-violet)" }}>Save this key now — it won&apos;t be shown again</div>
                <div className="text-xs" style={{ color: "var(--text-secondary)" }}>Store it in your environment variables.</div>
              </div>
              <DismissButton onClick={() => setRevealed(null)} />
            </div>
          </div>
          <div className="px-5 py-4 flex items-center gap-3">
            <code className="flex-1 px-3.5 py-2.5 rounded-lg text-xs font-mono-display overflow-x-auto whitespace-nowrap break-all"
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
            <EmptyState icon={<KeyRound size={28} />} title="No API keys yet" />
          )}
          {keys.map((k) => (
            <div key={k.id} className="px-5 py-4 flex items-center justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>{k.name}</span>
                  {k.revoked && <span className="text-[10px] font-mono-display px-1.5 py-0.5 rounded" style={{ background: "var(--danger-glow)", color: "var(--danger-red)" }}>REVOKED</span>}
                </div>
                <div className="text-xs font-mono-display break-all" style={{ color: "var(--text-tertiary)" }}>{k.key_prefix}</div>
              </div>
              {!k.revoked && (
                <button onClick={() => setConfirmRevoke(k)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display shrink-0 focus-ring" style={{ color: "var(--text-tertiary)" }}>
                  <Trash2 size={13} /> Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <ConfirmDialog
        open={confirmRevoke !== null}
        title={`Revoke ${confirmRevoke?.name}?`}
        description="Any application using this key stops working immediately. This cannot be undone."
        confirmLabel="Revoke permanently"
        onConfirm={() => confirmRevoke && revoke(confirmRevoke)}
        onCancel={() => setConfirmRevoke(null)}
      />
    </div>
  );
}
