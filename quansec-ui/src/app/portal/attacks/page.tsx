"use client";

import { useState } from "react";
import { quansec, AttackResult } from "@/lib/api";
import { Panel, PanelHeader, AttackResultBadge } from "@/components/ui-primitives";
import { Atom, Clock, Key, Radio, ShieldQuestion, Loader2 } from "lucide-react";

const ATTACKS = [
  { id: "downgrade", label: "IKE Downgrade", icon: Radio, desc: "MITM strips PQC proposal, forces classical fallback" },
  { id: "shors", label: "Shor's Algorithm", icon: Atom, desc: "Quantum factoring attack on the key exchange" },
  { id: "harvest", label: "Harvest Now, Decrypt Later", icon: Clock, desc: "Captured traffic decrypted retroactively by future quantum computers" },
  { id: "factoring", label: "Key Factoring", icon: Key, desc: "Real Pollard rho factoring of a classical key" },
  { id: "kyber-resist", label: "Kyber Brute Force", icon: ShieldQuestion, desc: "10,000 attempts against the ML-KEM-1024 lattice" },
];

function ResultRow({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined) return null;
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b last:border-0" style={{ borderColor: "var(--border-hairline)" }}>
      <span className="text-[11px] font-mono-display uppercase tracking-wide shrink-0" style={{ color: "var(--text-tertiary)" }}>
        {label.replace(/_/g, " ")}
      </span>
      <span className="text-xs font-mono-display text-right" style={{ color: "var(--text-secondary)" }}>
        {typeof value === "object" ? JSON.stringify(value) : String(value)}
      </span>
    </div>
  );
}

export default function AttacksPage() {
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AttackResult>>({});

  const run = async (id: string) => {
    setRunning(id);
    try {
      const res = await quansec.runAttack(id);
      setResults((prev) => ({ ...prev, [id]: res }));
    } catch {
      setResults((prev) => ({ ...prev, [id]: { attack: id, result: "ERROR" } }));
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display tracking-[0.18em] uppercase mb-1" style={{ color: "var(--text-tertiary)" }}>
          Cryptanalysis
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Attack Simulation Lab</h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          Real cryptographic attacks run against the current tunnel policy
        </p>
      </div>

      <div className="space-y-4">
        {ATTACKS.map((attack) => {
          const Icon = attack.icon;
          const result = results[attack.id];
          const isRunning = running === attack.id;

          return (
            <Panel key={attack.id} className="overflow-hidden">
              <div className="px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3.5 min-w-0">
                  <div
                    className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: "var(--lattice-violet-glow)", border: "1px solid var(--lattice-violet-dim)" }}
                  >
                    <Icon size={16} style={{ color: "var(--lattice-violet)" }} />
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-semibold">{attack.label}</div>
                    <div className="text-xs truncate" style={{ color: "var(--text-tertiary)" }}>{attack.desc}</div>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  {result && <AttackResultBadge result={result.result} />}
                  <button
                    onClick={() => run(attack.id)}
                    disabled={running !== null}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold font-mono-display transition-opacity disabled:opacity-50 focus-ring"
                    style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
                  >
                    {isRunning && <Loader2 size={13} className="animate-spin" />}
                    {isRunning ? "RUNNING" : "RUN ATTACK"}
                  </button>
                </div>
              </div>

              {result && (
                <div className="px-5 pb-4 pt-1">
                  <div
                    className="rounded-lg px-4 py-3"
                    style={{ background: "var(--bg-panel-raised)" }}
                  >
                    {Object.entries(result)
                      .filter(([k]) => !["attack", "result"].includes(k))
                      .slice(0, 6)
                      .map(([k, v]) => (
                        <ResultRow key={k} label={k} value={v} />
                      ))}
                  </div>
                </div>
              )}
            </Panel>
          );
        })}
      </div>
    </div>
  );
}
