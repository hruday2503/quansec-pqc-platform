"use client";

import { useEffect, useState } from "react";
import { quanseq, ApiKey, ApiKeyCreated } from "@/lib/api";
import { Panel, PanelHeader, PageHeader, EmptyState, ConfirmDialog, DismissButton } from "@/components/ui-primitives";
import { Copy, Check, Plus, Trash2, KeyRound, AlertTriangle } from "lucide-react";

function timeAgo(iso: string | null) {
  if (!iso) return "Never used";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function KeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [revealedKey, setRevealedKey] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<ApiKey | null>(null);

  const load = async () => {
    try {
      const data = await quanseq.listApiKeys();
      setKeys(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleCreate = async () => {
    if (!newKeyName.trim()) return;
    setCreating(true);
    try {
      const created = await quanseq.createApiKey(newKeyName.trim());
      setRevealedKey(created);
      setNewKeyName("");
      setShowCreateForm(false);
      await load();
    } catch {
      // backend may not have the endpoint yet — show inline error via revealedKey null
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (key: ApiKey) => {
    await quanseq.revokeApiKey(key.id);
    setConfirmRevoke(null);
    await load();
  };

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <PageHeader
        eyebrow="Integration"
        title="API keys"
        description="Use an API key to connect your application to a quantum-safe IPsec tunnel. Keys never expire until you revoke them."
        actions={
          <button
            onClick={() => setShowCreateForm(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold transition-opacity focus-ring shrink-0"
            style={{ background: "var(--pqc-cyan)", color: "#04201c" }}
          >
            <Plus size={15} />
            Generate new key
          </button>
        }
      />

      {/* Revealed key — shown once */}
      {revealedKey && (
        <Panel className="mb-6 overflow-hidden" >
          <div className="px-5 py-4" style={{ background: "var(--pqc-cyan-glow)", borderBottom: "1px solid var(--pqc-cyan-dim)" }}>
            <div className="flex items-start gap-3">
              <AlertTriangle size={16} style={{ color: "var(--pqc-cyan)" }} className="shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold mb-1" style={{ color: "var(--pqc-cyan)" }}>
                  Save this key now — it won&apos;t be shown again
                </div>
                <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  Store it in your environment variables or secrets manager.
                </div>
              </div>
              <DismissButton onClick={() => setRevealedKey(null)} />
            </div>
          </div>
          <div className="px-5 py-4 flex items-center gap-3">
            <code
              className="flex-1 px-3.5 py-2.5 rounded-lg text-xs font-mono-display overflow-x-auto whitespace-nowrap break-all"
              style={{ background: "var(--bg-panel-raised)", color: "var(--pqc-cyan)" }}
            >
              {revealedKey.api_key}
            </code>
            <button
              onClick={() => copyKey(revealedKey.api_key)}
              className="flex items-center gap-1.5 px-3 py-2.5 rounded-lg text-xs font-mono-display shrink-0 focus-ring"
              style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)" }}
            >
              {copied ? <Check size={13} style={{ color: "var(--pqc-cyan)" }} /> : <Copy size={13} />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </Panel>
      )}

      {/* Create form */}
      {showCreateForm && (
        <Panel className="mb-6 px-5 py-5">
          <div className="text-sm font-semibold mb-3">Name this key</div>
          <div className="flex gap-3">
            <input
              autoFocus
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              placeholder="e.g. Production server, CI pipeline"
              className="flex-1 px-3.5 py-2.5 rounded-lg text-sm outline-none focus-ring"
              style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline)", color: "var(--text-primary)" }}
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newKeyName.trim()}
              className="px-4 py-2.5 rounded-lg text-sm font-semibold disabled:opacity-50 focus-ring"
              style={{ background: "var(--pqc-cyan)", color: "#04201c" }}
            >
              {creating ? "Creating…" : "Create"}
            </button>
            <button
              onClick={() => setShowCreateForm(false)}
              className="px-4 py-2.5 rounded-lg text-sm focus-ring"
              style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)", border: "1px solid var(--border-hairline)" }}
            >
              Cancel
            </button>
          </div>
        </Panel>
      )}

      {/* Keys list */}
      <Panel>
        <PanelHeader eyebrow={`${keys.filter((k) => !k.revoked).length} active`} title="Your keys" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {loading && (
            <div className="px-5 py-10 text-center text-sm" style={{ color: "var(--text-tertiary)" }}>Loading…</div>
          )}
          {!loading && keys.length === 0 && (
            <EmptyState
              icon={<KeyRound size={28} />}
              title="No API keys yet"
              hint="Generate a key to start integrating your quantum-safe tunnel."
            />
          )}
          {keys.map((k) => (
            <div key={k.id} className="px-5 py-4 flex items-center justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-sm font-medium">{k.name}</span>
                  {k.revoked && (
                    <span className="text-[10px] font-mono-display px-1.5 py-0.5 rounded" style={{ background: "var(--danger-glow)", color: "var(--danger-red)" }}>
                      REVOKED
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>
                  <span className="break-all">{k.key_prefix}</span>
                  <span>{timeAgo(k.last_used)}</span>
                </div>
              </div>
              {!k.revoked && (
                <button
                  onClick={() => setConfirmRevoke(k)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display shrink-0 focus-ring transition-colors"
                  style={{ color: "var(--text-tertiary)" }}
                >
                  <Trash2 size={13} />
                  Revoke
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
        onConfirm={() => confirmRevoke && handleRevoke(confirmRevoke)}
        onCancel={() => setConfirmRevoke(null)}
      />
    </div>
  );
}
