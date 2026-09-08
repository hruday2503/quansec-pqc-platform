"use client";

import { useEffect, useState } from "react";
import { Panel } from "@/components/ui-primitives";
import { Gauge, ShieldCheck, X, Check } from "lucide-react";
import { authHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

interface Factors {
  coverage: number;
  algorithm_strength: number;
  downgrade_resistant: boolean;
  hybrid_construction: boolean;
}
interface Score {
  protocol: string;
  score: number;
  grade: string;
  factors: Factors;
}

const PROTOCOL = "tls";
const ACCENT = "var(--pqc-cyan)";

function gradeColor(grade: string) {
  if (grade === "A") return "var(--pqc-cyan)";
  if (grade === "B") return "var(--lattice-violet)";
  if (grade === "C") return "var(--threat-amber)";
  return "var(--danger-red)";
}

export default function TlsReadinessScorePage() {
  const [score, setScore] = useState<Score | null>(null);
  const [overall, setOverall] = useState<{ overall_score: number; grade: string; cnsa_ready: boolean } | null>(null);

  const load = async () => {
    try {
      const [s, o] = await Promise.all([
        mockFetch(`/api/scoring/${PROTOCOL}`, { headers: authHeaders() }).then((r) => r.json()),
        mockFetch(`/api/scoring/overall`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setScore(s); setOverall(o);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  const s = score?.score ?? 0;
  const circumference = 2 * Math.PI * 70;
  const dash = (s / 100) * circumference;

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: ACCENT }}>
          Compliance
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>PQC Readiness Score</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-primary)" }}>
          Weighted assessment of post-quantum migration readiness
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Score gauge */}
        <Panel className="px-6 py-8 flex flex-col items-center justify-center">
          <div className="relative" style={{ width: 180, height: 180 }}>
            <svg width="180" height="180" className="transform -rotate-90">
              <circle cx="90" cy="90" r="70" fill="none" stroke="var(--border-hairline)" strokeWidth="12" />
              <circle cx="90" cy="90" r="70" fill="none" stroke={gradeColor(score?.grade ?? "F")} strokeWidth="12"
                strokeDasharray={`${dash} ${circumference}`} strokeLinecap="round" style={{ transition: "stroke-dasharray 1s ease" }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-5xl font-extrabold font-mono-display" style={{ color: "var(--text-primary)" }}>{s.toFixed(0)}</div>
              <div className="text-xs font-mono-display" style={{ color: "var(--text-primary)" }}>out of 100</div>
            </div>
          </div>
          <div className="mt-5 flex items-center gap-3">
            <span className="text-3xl font-extrabold font-mono-display" style={{ color: gradeColor(score?.grade ?? "F") }}>{score?.grade ?? "—"}</span>
            <span className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--text-primary)" }}>{PROTOCOL}</span>
          </div>
        </Panel>

        {/* Factor breakdown */}
        <Panel className="px-6 py-6">
          <div className="text-sm font-bold mb-4" style={{ color: "var(--text-primary)" }}>Score Factors</div>
          <div className="space-y-4">
            <FactorBar label="Coverage" value={score?.factors.coverage ?? 0} weight="40%" accent={ACCENT} />
            <FactorBar label="Algorithm Strength" value={score?.factors.algorithm_strength ?? 0} weight="35%" accent={ACCENT} />
            <FactorRow label="Downgrade Resistant" ok={score?.factors.downgrade_resistant ?? false} weight="15%" />
            <FactorRow label="Hybrid Construction" ok={score?.factors.hybrid_construction ?? false} weight="10%" />
          </div>
          {/* Downgrade resistance is honestly false for TLS: Python's ssl
              module cannot select TLS 1.3 groups, so a classical-only client
              still completes a handshake. Stated rather than hidden. */}
          {score && !score.factors.downgrade_resistant && (
            <p className="mt-4 pt-3 border-t text-[11px] leading-relaxed" style={{ borderColor: "var(--border-hairline)", color: "var(--text-tertiary)" }}>
              Downgrade resistance scores zero because hybrid key exchange is not
              enforced on this runtime — a classical-only client can still connect.
            </p>
          )}
        </Panel>
      </div>

      {/* Overall platform */}
      {overall && (
        <Panel className="px-6 py-5">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <Gauge size={20} style={{ color: ACCENT }} />
              <div>
                <div className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Overall Platform Score</div>
                <div className="text-xs" style={{ color: "var(--text-primary)" }}>IPsec + SSH + TLS combined</div>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-3xl font-extrabold font-mono-display" style={{ color: gradeColor(overall.grade) }}>{overall.overall_score}</div>
              </div>
              {overall.cnsa_ready && (
                <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display font-bold" style={{ background: "var(--pqc-cyan-glow)", color: "var(--pqc-cyan)" }}>
                  <ShieldCheck size={13} /> CNSA 2.0 READY
                </span>
              )}
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

function FactorBar({ label, value, weight, accent }: { label: string; value: number; weight: string; accent: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-sm" style={{ color: "var(--text-primary)" }}>{label}</span>
        <span className="text-xs font-mono-display" style={{ color: "var(--text-primary)" }}>{value.toFixed(0)}% · <span style={{ color: "var(--text-tertiary)" }}>{weight}</span></span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-hairline)" }}>
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: accent, transition: "width 1s ease" }} />
      </div>
    </div>
  );
}

function FactorRow({ label, ok, weight }: { label: string; ok: boolean; weight: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm" style={{ color: "var(--text-primary)" }}>{label}</span>
      <div className="flex items-center gap-2">
        {ok ? <Check size={15} style={{ color: "var(--pqc-cyan)" }} /> : <X size={15} style={{ color: "var(--threat-amber)" }} />}
        <span className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>{weight}</span>
      </div>
    </div>
  );
}
