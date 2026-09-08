"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader, PageHeader, PqcBadge, StateBadge, MetricValue, EmptyState } from "@/components/ui-primitives";
import { AttackCard, AttackOutcome } from "@/components/attack-card";
import { Terminal, Radio, Atom, Clock } from "lucide-react";
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
  { id: "downgrade", label: "KEX Downgrade", icon: Radio, description: "MITM strips the hybrid KEX to force classical X25519" },
  { id: "shors", label: "Shor's Algorithm", icon: Atom, description: "Quantum attack against the X25519 half of the exchange" },
  { id: "harvest", label: "Harvest Now, Decrypt Later", icon: Clock, description: "Recorded SSH traffic decrypted retroactively" },
];

export default function SshSessionsPage() {
  const [stats, setStats] = useState<SshStats | null>(null);
  const [conns, setConns] = useState<SshConn[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AttackOutcome>>({});

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

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <PageHeader
        eyebrow="Protocol module"
        title="SSH sessions"
        description="Hybrid X25519 + ML-KEM-768 key exchange monitoring."
        accent="var(--lattice-violet)"
      />

      {/* Stat grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Active sessions</span>
          </div>
          <MetricValue value={stats?.active ?? 0} />
        </Panel>
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>PQC sessions</span>
          </div>
          <MetricValue value={stats?.pqc_enabled ?? 0} tone="cyan" />
        </Panel>
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: coverage === 100 ? "var(--pqc-cyan)" : "var(--threat-amber)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>PQC coverage</span>
          </div>
          <MetricValue value={`${coverage.toFixed(0)}%`} tone={coverage === 100 ? "cyan" : "amber"} />
        </Panel>
      </div>

      {/* Connections */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Live feed" title="SSH connections" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {conns.length === 0 && (
            <EmptyState
              icon={<Terminal size={28} />}
              title="No SSH sessions detected"
              hint="Open an SSH connection to a monitored host to see it here."
            />
          )}
          {conns.map((c) => (
            <div key={c.id} className="px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 mb-1">
                  <span className="text-sm font-mono-display font-medium" style={{ color: "var(--text-primary)" }}>{c.remote_host}</span>
                  <StateBadge state={c.state} />
                </div>
                <div className="text-xs font-mono-display" style={{ color: "var(--text-secondary)" }}>{c.kex_algorithm}</div>
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
      <div>
        <div className="mb-3 text-[11px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-tertiary)" }}>
          Cryptanalysis · SSH Attack Lab
        </div>
        <div className="space-y-4">
          {ATTACKS.map((attack) => (
            <AttackCard
              key={attack.id}
              attack={attack}
              outcome={results[attack.id]}
              running={running === attack.id}
              disabled={running !== null}
              onRun={() => runAttack(attack.id)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
