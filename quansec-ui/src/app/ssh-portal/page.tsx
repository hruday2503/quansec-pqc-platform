"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Terminal, ArrowRight, Wifi, WifiOff, ShieldCheck } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("quansec_token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export default function SshPortalOverview() {
  const [stats, setStats] = useState<{ active: number; pqc_enabled: number; pqc_coverage: number } | null>(null);
  const [days, setDays] = useState<number | null>(null);

  const load = async () => {
    try {
      const [s, cmp] = await Promise.all([
        fetch(`${API_BASE}/api/ssh/stats`, { headers: authHeaders() }).then((r) => r.json()),
        fetch(`${API_BASE}/api/ssh/policies/compare`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setStats(s);
      setDays(cmp.days_remaining);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const coverage = stats?.pqc_coverage ?? 0;
  const isFullyPqc = coverage === 100;

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--lattice-violet-dim)" }}>
          SSH Module
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>Overview</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Hybrid X25519 + ML-KEM-768 SSH monitoring
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
        <div className="rounded-xl border px-6 py-5" style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}>
          <div className="flex items-center gap-2 mb-3.5">
            <Terminal size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>Active Sessions</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>{stats?.active ?? 0}</div>
        </div>
        <div className="rounded-xl border px-6 py-5" style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}>
          <div className="flex items-center gap-2 mb-3.5">
            <ShieldCheck size={15} style={{ color: "var(--lattice-violet)" }} />
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>PQC Sessions</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: "var(--lattice-violet)" }}>{stats?.pqc_enabled ?? 0}</div>
        </div>
        <div className="rounded-xl border px-6 py-5 relative overflow-hidden" style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}>
          <div className="flex items-center gap-2 mb-3.5">
            {isFullyPqc ? <Wifi size={15} style={{ color: "var(--pqc-cyan)" }} /> : <WifiOff size={15} style={{ color: "var(--threat-amber)" }} />}
            <span className="text-xs font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-secondary)" }}>PQC Coverage</span>
          </div>
          <div className="text-4xl font-extrabold font-mono-display tabular-nums" style={{ color: isFullyPqc ? "var(--pqc-cyan)" : "var(--threat-amber)" }}>
            {coverage.toFixed(0)}%
          </div>
        </div>
      </div>

      <Link href="/ssh-portal/docs" className="block focus-ring rounded-xl">
        <div className="rounded-xl border p-6 transition-all hover:scale-[1.01] relative overflow-hidden" style={{ background: "var(--bg-panel)", borderColor: "var(--lattice-violet-dim)" }}>
          <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-2xl" style={{ background: "var(--lattice-violet-glow)" }} />
          <div className="relative flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold mb-1" style={{ color: "var(--text-primary)" }}>Integration Guide</h2>
              <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                Connect and monitor SSH sessions secured with hybrid X25519 + ML-KEM-768
              </p>
            </div>
            <ArrowRight size={20} style={{ color: "var(--lattice-violet)" }} />
          </div>
        </div>
      </Link>

      {days !== null && (
        <div className="mt-6 text-center">
          <span className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>
            {days.toLocaleString()} days to the CNSA 2.0 SSH deadline (2030)
          </span>
        </div>
      )}
    </div>
  );
}
