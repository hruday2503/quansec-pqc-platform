"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader, PageHeader } from "@/components/ui-primitives";
import { Check, X, Calendar, Loader2 } from "lucide-react";
import { authHeaders as bearerHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

function authHeaders(json = false): HeadersInit {
  // Authorization comes from the in-memory access token; see
  // src/lib/auth-fetch.ts. Nothing is read from localStorage.
  const h: Record<string, string> = { ...bearerHeaders() };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

interface Policy {
  name: string; label: string; description: string; kex: string; pqc: boolean;
}
interface CompareRow {
  field: string; classical: string | boolean; pqc: string | boolean; why_changed: string; standard: string;
}

export default function SshPolicyPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [rows, setRows] = useState<CompareRow[]>([]);
  const [days, setDays] = useState<number | null>(null);
  const [applying, setApplying] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = async () => {
    const [p, cmp] = await Promise.all([
      mockFetch(`/api/ssh/policies`, { headers: authHeaders() }).then((r) => r.json()),
      mockFetch(`/api/ssh/policies/compare`, { headers: authHeaders() }).then((r) => r.json()),
    ]);
    setPolicies(Array.isArray(p) ? p : []);
    setRows(cmp.comparison || []);
    setDays(cmp.days_remaining ?? null);
  };

  useEffect(() => { load(); }, []);

  const apply = async (name: string) => {
    setApplying(name); setToast(null);
    try {
      const res = await mockFetch(`/api/ssh/policies/apply`, {
        method: "POST", headers: authHeaders(true), body: JSON.stringify({ policy_name: name }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "failed");
      setToast(`Policy "${data.policy}" applied — sshd restarted with KEX ${data.kex}. Reconnect to apply.`);
      await load();
    } catch (e) {
      setToast(`Failed to apply: ${e instanceof Error ? e.message : "error"}`);
    } finally {
      setApplying(null);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <PageHeader
        eyebrow="Migration control"
        title="SSH policy engine"
        accent="var(--lattice-violet)"
        actions={days !== null && (
          <div className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono-display font-semibold"
            style={{ background: "var(--lattice-violet-glow)", color: "var(--lattice-violet)", border: "1px solid var(--lattice-violet-dim)" }}>
            <Calendar size={13} />
            {days.toLocaleString()} days to CNSA 2.0 SSH deadline
          </div>
        )}
      />

      {toast && (
        <div className="mb-6 px-4 py-3 rounded-lg text-sm font-mono-display"
          style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-secondary)" }}>
          {toast}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-8">
        {policies.map((p) => (
          <Panel key={p.name} className="px-6 py-5 flex flex-col">
            <span className="self-start text-[10px] font-mono-display font-bold uppercase tracking-wider px-2 py-0.5 rounded mb-3"
              style={{ background: p.pqc ? "var(--lattice-violet-glow)" : "var(--threat-amber-glow)", color: p.pqc ? "var(--lattice-violet)" : "var(--threat-amber)" }}>
              {p.pqc ? "POST-QUANTUM" : "CLASSICAL"}
            </span>
            <h3 className="text-base font-bold mb-1.5" style={{ color: "var(--text-primary)" }}>{p.label}</h3>
            <p className="text-xs leading-relaxed mb-4 flex-1" style={{ color: "var(--text-secondary)" }}>{p.description}</p>
            <div className="text-[11px] font-mono-display mb-4" style={{ color: "var(--text-secondary)" }}>{p.kex}</div>
            <button onClick={() => apply(p.name)} disabled={applying !== null}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-bold disabled:opacity-50 focus-ring"
              style={{ background: p.pqc ? "var(--lattice-violet)" : "var(--bg-panel-raised)", color: p.pqc ? "#1a0f3d" : "var(--text-primary)", border: p.pqc ? "none" : "1px solid var(--border-hairline-bright)" }}>
              {applying === p.name && <Loader2 size={14} className="animate-spin" />}
              {applying === p.name ? "Applying…" : "Apply Policy"}
            </button>
          </Panel>
        ))}
      </div>

      <Panel>
        <PanelHeader eyebrow="Compliance Report" title="What Changed and Why" />
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b" style={{ borderColor: "var(--border-hairline)" }}>
                {["Field", "Classical", "Post-Quantum", "Why It Changed"].map((h) => (
                  <th key={h} className="px-5 py-3 font-mono-display text-[10px] uppercase tracking-wider font-bold" style={{ color: "var(--text-secondary)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.field} className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-5 py-3.5 text-sm font-medium" style={{ color: "var(--text-primary)" }}>{row.field}</td>
                  <td className="px-5 py-3.5 text-xs font-mono-display" style={{ color: "var(--threat-amber)" }}>
                    {typeof row.classical === "boolean" ? (row.classical ? <Check size={14} /> : <X size={14} />) : row.classical}
                  </td>
                  <td className="px-5 py-3.5 text-xs font-mono-display" style={{ color: "var(--lattice-violet)" }}>
                    {typeof row.pqc === "boolean" ? (row.pqc ? <Check size={14} /> : <X size={14} />) : row.pqc}
                  </td>
                  <td className="px-5 py-3.5 text-xs" style={{ color: "var(--text-secondary)" }}>{row.why_changed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
