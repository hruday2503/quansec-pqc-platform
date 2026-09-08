"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader, PqcBadge, StateBadge, AttackResultBadge } from "@/components/ui-primitives";
import { Terminal, Radio, Atom, Clock, Loader2 } from "lucide-react";
import { authHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

interface SshStats {
  total_connections: number;
  active: number;
  closed: number;
  pqc_enabled: number;
  pqc_coverage: number;
}

interface SshConn {
  id: number;
  session_key: string;
  local_host: string;
  remote_host: string;
  kex_algorithm: string;
  kem_label: string;
  pqc_enabled: boolean;
  state: string;
}

const ATTACKS = [
  { id: "downgrade", label: "KEX Downgrade", icon: Radio, desc: "MITM strips the hybrid KEX to force classical X25519" },
  { id: "shors", label: "Shor's Algorithm", icon: Atom, desc: "Quantum attack against the X25519 half of the exchange" },
  { id: "harvest", label: "Harvest Now, Decrypt Later", icon: Clock, desc: "Recorded SSH traffic decrypted retroactively" },
];

export default function SshPage() {
  const [stats, setStats] = useState<SshStats | null>(null);
  const [conns, setConns] = useState<SshConn[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { result: string; [k: string]: unknown }>>({});

  const load = async () => {
    try {
      const [s, c] = await Promise.all([
        mockFetch(`/api/ssh/stats`, { headers: authHeaders() }).then((r) => r.json()),
        mockFetch(`/api/ssh/connections`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setStats(s);
      setConns(Array.isArray(c) ? c : []);
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const runAttack = async (id: string) => {
    setRunning(id);
    try {
      const res = await mockFetch(`/api/ssh/attacks/${id}`, {
        method: "POST",
        headers: authHeaders(),
      }).then((r) => r.json());
      setResults((prev) => ({ ...prev, [id]: res }));
    } finally {
      setRunning(null);
    }
  };

  const coverage = stats?.pqc_coverage ?? 0;
  const isFullyPqc = coverage === 100;

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--pqc-cyan-dim)" }}>
          Protocol Module
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>SSH</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-primary)" }}>
          Hybrid X25519 + ML-KEM-768 key exchange monitoring
        </p>
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>Active Sessions</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>{stats?.active ?? 0}</div>
        </Panel>
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>PQC Sessions</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--pqc-cyan)" }}>{stats?.pqc_enabled ?? 0}</div>
        </Panel>
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: isFullyPqc ? "var(--pqc-cyan)" : "var(--threat-amber)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>PQC Coverage</span>
          </div>
          <div className={`text-4xl font-extrabold font-mono-display tabular-nums ${isFullyPqc ? "gradient-cyan-text" : ""}`} style={!isFullyPqc ? { color: "var(--threat-amber)" } : undefined}>
            {coverage.toFixed(0)}%
          </div>
        </Panel>
      </div>

      {/* Connections */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Live Feed" title="SSH Connections" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {conns.length === 0 && (
            <div className="px-5 py-10 text-center text-sm" style={{ color: "var(--pqc-cyan)" }}>
              No SSH sessions detected. Open an SSH connection to VM B to see it here.
            </div>
          )}
          {conns.map((c) => (
            <div key={c.id} className="px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-sm font-mono-display font-medium" style={{ color: "var(--text-primary)" }}>{c.remote_host}</span>
                  <StateBadge state={c.state} />
                </div>
                <div className="text-xs font-mono-display" style={{ color: "var(--text-primary)" }}>{c.kex_algorithm}</div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-xs font-mono-display" style={{ color: c.pqc_enabled ? "var(--pqc-cyan)" : "var(--text-secondary)" }}>{c.kem_label}</span>
                <PqcBadge pqc={c.pqc_enabled} size="sm" />
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* Attacks */}
      <Panel>
        <PanelHeader eyebrow="Cryptanalysis" title="SSH Attack Lab" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {ATTACKS.map((a) => {
            const Icon = a.icon;
            const res = results[a.id];
            return (
              <div key={a.id} className="px-5 py-4">
                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3.5 min-w-0">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: "var(--lattice-violet-glow)", border: "1px solid var(--lattice-violet-dim)" }}>
                      <Icon size={16} style={{ color: "var(--lattice-violet)" }} />
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{a.label}</div>
                      <div className="text-xs truncate" style={{ color: "var(--text-primary)" }}>{a.desc}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {res && <AttackResultBadge result={res.result} />}
                    <button
                      onClick={() => runAttack(a.id)}
                      disabled={running !== null}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold font-mono-display disabled:opacity-50 focus-ring"
                      style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
                    >
                      {running === a.id && <Loader2 size={13} className="animate-spin" />}
                      {running === a.id ? "RUNNING" : "RUN ATTACK"}
                    </button>
                  </div>
                </div>
                {res && (
                  <div className="mt-3 ml-12 rounded-lg px-4 py-3" style={{ background: "var(--bg-panel-raised)" }}>
                    {Object.entries(res).filter(([k]) => !["attack", "result", "explanation", "reason"].includes(k)).slice(0, 5).map(([k, v]) => (
                      <div key={k} className="flex items-start justify-between gap-4 py-1.5 border-b last:border-0" style={{ borderColor: "var(--border-hairline)" }}>
                        <span className="text-[11px] font-mono-display uppercase tracking-wide shrink-0" style={{ color: "var(--pqc-cyan)" }}>{k.replace(/_/g, " ")}</span>
                        <span className="text-xs font-mono-display text-right" style={{ color: "var(--text-primary)" }}>{String(v)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
