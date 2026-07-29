"use client";

import { useEffect, useState } from "react";
import { quansec, PolicyCompare, Policy } from "@/lib/api";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { Check, X, Calendar, Loader2 } from "lucide-react";

export default function PolicyPage() {
  const [compare, setCompare] = useState<PolicyCompare | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [applying, setApplying] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = async () => {
    const [c, p] = await Promise.all([quansec.getCompare(), quansec.getPolicies()]);
    setCompare(c);
    setPolicies(p);
  };

  useEffect(() => {
    load();
  }, []);

  const handleApply = async (name: string) => {
    setApplying(name);
    setToast(null);
    try {
      const res = await quansec.applyPolicy(name);
      setToast(`Policy "${res.policy}" applied. Re-initiate tunnel to take effect.`);
      await load();
    } catch {
      setToast("Failed to apply policy. Check API connectivity.");
    } finally {
      setApplying(null);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="mb-8 flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="text-[11px] font-mono-display tracking-[0.18em] uppercase mb-1" style={{ color: "var(--text-tertiary)" }}>
            Migration Control
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Policy Engine</h1>
        </div>
        {compare && (
          <div
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono-display"
            style={{ background: "var(--lattice-violet-glow)", color: "var(--lattice-violet)", border: "1px solid var(--lattice-violet-dim)" }}
          >
            <Calendar size={13} />
            {compare.days_remaining.toLocaleString()} days to {compare.cnsa_deadline}
          </div>
        )}
      </div>

      {toast && (
        <div
          className="mb-6 px-4 py-3 rounded-lg text-sm font-mono-display"
          style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-secondary)" }}
        >
          {toast}
        </div>
      )}

      {/* Policy cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
        {policies.map((p) => (
          <Panel key={p.name} className="px-6 py-5 flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <span
                className="text-[10px] font-mono-display uppercase tracking-wider px-2 py-0.5 rounded"
                style={{
                  background: p.pqc ? "var(--pqc-cyan-glow)" : "var(--threat-amber-glow)",
                  color: p.pqc ? "var(--pqc-cyan)" : "var(--threat-amber)",
                }}
              >
                {p.pqc ? "POST-QUANTUM" : "CLASSICAL"}
              </span>
            </div>
            <h3 className="text-base font-semibold mb-1.5">{p.label}</h3>
            <p className="text-xs leading-relaxed mb-5 flex-1" style={{ color: "var(--text-tertiary)" }}>
              {p.description}
            </p>
            <div className="text-[11px] font-mono-display mb-4" style={{ color: "var(--text-secondary)" }}>
              {p.ike_proposal}
            </div>
            <button
              onClick={() => handleApply(p.name)}
              disabled={applying !== null}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-opacity disabled:opacity-50 focus-ring"
              style={{
                background: p.pqc ? "var(--pqc-cyan)" : "var(--bg-panel-raised)",
                color: p.pqc ? "#04201c" : "var(--text-primary)",
                border: p.pqc ? "none" : "1px solid var(--border-hairline-bright)",
              }}
            >
              {applying === p.name ? <Loader2 size={14} className="animate-spin" /> : null}
              {applying === p.name ? "Applying…" : "Apply Policy"}
            </button>
          </Panel>
        ))}
      </div>

      {/* Comparison table */}
      <Panel>
        <PanelHeader eyebrow="Compliance Report" title="What Changed and Why" />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b" style={{ borderColor: "var(--border-hairline)" }}>
                <th className="px-5 py-3 font-mono-display text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--text-tertiary)" }}>Field</th>
                <th className="px-5 py-3 font-mono-display text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--text-tertiary)" }}>Classical</th>
                <th className="px-5 py-3 font-mono-display text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--text-tertiary)" }}>Post-Quantum</th>
                <th className="px-5 py-3 font-mono-display text-[10px] uppercase tracking-wider font-medium" style={{ color: "var(--text-tertiary)" }}>Why It Changed</th>
              </tr>
            </thead>
            <tbody>
              {compare?.comparison.map((row) => (
                <tr key={row.field} className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-5 py-3.5 text-sm font-medium">{row.field}</td>
                  <td className="px-5 py-3.5 text-xs font-mono-display" style={{ color: "var(--threat-amber)" }}>
                    {typeof row.classical === "boolean" ? (
                      row.classical ? <Check size={14} /> : <X size={14} />
                    ) : (
                      row.classical
                    )}
                  </td>
                  <td className="px-5 py-3.5 text-xs font-mono-display" style={{ color: "var(--pqc-cyan)" }}>
                    {typeof row.pqc === "boolean" ? (
                      row.pqc ? <Check size={14} /> : <X size={14} />
                    ) : (
                      row.pqc
                    )}
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
