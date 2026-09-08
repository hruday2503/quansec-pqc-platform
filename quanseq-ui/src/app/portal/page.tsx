"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, KeyRound, Network, Wifi, WifiOff } from "lucide-react";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { useLiveStats } from "@/lib/use-live-stats";
import { quanseq, ApiKey } from "@/lib/api";

export default function PortalOverview() {
  const { stats, connected } = useLiveStats();
  const [keys, setKeys] = useState<ApiKey[]>([]);

  useEffect(() => {
    quanseq.listApiKeys().then(setKeys).catch(() => setKeys([]));
  }, []);

  const hasKey = keys.some((k) => !k.revoked);
  const coverage = stats?.pqc_coverage ?? 0;
  const isFullyPqc = coverage === 100;

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--pqc-cyan-dim)" }}>
            Welcome back
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>
            Your QUANSEQ Integration
          </h1>
        </div>
        <div
          className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono-display font-semibold"
          style={{
            background: connected ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
            color: connected ? "var(--pqc-cyan)" : "var(--text-secondary)",
            border: `1px solid ${connected ? "var(--pqc-cyan-dim)" : "var(--border-hairline-bright)"}`,
          }}
        >
          {connected ? <Wifi size={12} /> : <WifiOff size={12} />}
          {connected ? "LIVE" : "RECONNECTING"}
        </div>
      </div>

      {!hasKey && (
        <Panel className="mb-6 relative overflow-hidden">
          <div className="absolute inset-0 lattice-bg-active" />
          <div className="absolute -top-20 -left-20 w-80 h-80 rounded-full blur-3xl pointer-events-none" style={{ background: "var(--pqc-cyan-glow)", opacity: 0.6 }} />
          <div className="absolute inset-0" style={{ background: "linear-gradient(180deg, transparent 0%, var(--bg-panel) 88%)" }} />
          <div className="relative z-10 px-7 py-8">
            <div className="text-[11px] font-mono-display font-bold tracking-wider uppercase mb-2.5" style={{ color: "var(--pqc-cyan)" }}>Get started</div>
            <h2 className="text-xl font-bold mb-2.5" style={{ color: "var(--text-primary)" }}>Connect your first application</h2>
            <p className="text-sm mb-6 max-w-lg leading-relaxed" style={{ color: "var(--text-secondary)" }}>
              Generate an API key to start securing your traffic with ML-KEM-1024 post-quantum encryption. Takes about two minutes.
            </p>
            <Link href="/portal/keys" className="inline-flex items-center gap-2 px-5 py-3 rounded-lg text-sm font-bold focus-ring" style={{ background: "var(--pqc-cyan)", color: "#04201c" }}>
              Generate API key <ArrowRight size={16} strokeWidth={2.5} />
            </Link>
          </div>
        </Panel>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <KeyRound size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Active Keys</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>{keys.filter((k) => !k.revoked).length}</div>
        </Panel>
        <Panel className="px-6 py-5">
          <div className="flex items-center gap-2 mb-3.5">
            <Network size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Active Tunnels</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>{stats?.established ?? 0}</div>
        </Panel>
        <Panel className="px-6 py-5 relative overflow-hidden">
          {isFullyPqc && <div className="absolute -top-8 -right-8 w-32 h-32 rounded-full blur-2xl pointer-events-none" style={{ background: "var(--pqc-cyan-glow)" }} />}
          <div className="relative flex items-center gap-2 mb-3.5">
            <Network size={15} style={{ color: isFullyPqc ? "var(--pqc-cyan)" : "var(--threat-amber)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>PQC Coverage</span>
          </div>
          <div className={`relative text-4xl font-extrabold font-mono-display tabular-nums ${isFullyPqc ? "gradient-cyan-text" : ""}`} style={!isFullyPqc ? { color: "var(--threat-amber)" } : undefined}>
            {coverage.toFixed(0)}%
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHeader eyebrow="Quick Start" title="Connect in 3 lines" />
        <div className="px-5 py-5">
          <pre className="rounded-lg px-4 py-4 text-xs font-mono-display overflow-x-auto leading-relaxed" style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)", border: "1px solid var(--border-hairline)" }}>
{`curl https://api.quanseq.io/api/ipsec/stats \\
  -H "Authorization: Bearer qsk_live_••••••••••••••••"

# { "pqc_coverage": 100.0, "established": 1, ... }`}
          </pre>
          <div className="flex items-center justify-between mt-4">
            <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>Full setup guide with SDKs and framework examples</span>
            <Link href="/portal/docs" className="inline-flex items-center gap-1.5 text-xs font-mono-display font-bold focus-ring" style={{ color: "var(--pqc-cyan)" }}>
              View docs <ArrowRight size={12} strokeWidth={2.5} />
            </Link>
          </div>
        </div>
      </Panel>
    </div>
  );
}
