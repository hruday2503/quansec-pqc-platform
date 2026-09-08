"use client";

import { Check, Gauge, ShieldCheck, X } from "lucide-react";
import { Panel } from "@/components/ui-primitives";

export interface ReadinessFactors {
  coverage: number;
  algorithm_strength: number;
  downgrade_resistant: boolean;
  hybrid_construction: boolean;
  zero_trust_events?: number;
}

export interface ReadinessScore {
  protocol: string;
  score: number;
  grade: string;
  factors: ReadinessFactors;
}

export interface OverallReadiness {
  overall_score: number;
  grade: string;
  cnsa_ready: boolean;
}

function gradeColor(grade: string) {
  if (grade === "A") return "var(--status-safe)";
  if (grade === "B") return "var(--status-identity)";
  if (grade === "C") return "var(--status-warning)";
  return "var(--status-critical)";
}

/**
 * The circular score gauge + factor breakdown shared by every protocol's
 * readiness page. `note` is for a protocol-specific caveat (e.g. TLS's
 * always-false downgrade resistance) — shown only when passed, so the
 * component stays generic.
 */
export function ReadinessCard({
  protocolLabel,
  accent,
  score,
  note,
}: {
  protocolLabel: string;
  accent: string;
  score: ReadinessScore | null;
  note?: string;
}) {
  const s = score?.score ?? 0;
  const circumference = 2 * Math.PI * 70;
  const dash = (s / 100) * circumference;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
      <Panel className="px-6 py-8 flex flex-col items-center justify-center">
        <div className="relative" style={{ width: 180, height: 180 }}>
          <svg width="180" height="180" className="transform -rotate-90" role="img" aria-label={`${protocolLabel} readiness score: ${s} out of 100, grade ${score?.grade ?? "unknown"}`}>
            <circle cx="90" cy="90" r="70" fill="none" stroke="var(--border-hairline)" strokeWidth="12" />
            <circle
              cx="90" cy="90" r="70" fill="none" stroke={gradeColor(score?.grade ?? "F")} strokeWidth="12"
              strokeDasharray={`${dash} ${circumference}`} strokeLinecap="round"
              style={{ transition: "stroke-dasharray 0.6s ease" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-5xl font-extrabold font-mono-display" style={{ color: "var(--text-primary)" }}>{s.toFixed(0)}</div>
            <div className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>out of 100</div>
          </div>
        </div>
        <div className="mt-5 flex items-center gap-3">
          <span className="text-3xl font-extrabold font-mono-display" style={{ color: gradeColor(score?.grade ?? "F") }}>{score?.grade ?? "—"}</span>
          <span className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--text-primary)" }}>{protocolLabel}</span>
        </div>
      </Panel>

      <Panel className="px-6 py-6">
        <div className="text-sm font-bold mb-4" style={{ color: "var(--text-primary)" }}>Score factors</div>
        <div className="space-y-4">
          <FactorBar label="Coverage" value={score?.factors.coverage ?? 0} weight="40%" accent={accent} />
          <FactorBar label="Algorithm strength" value={score?.factors.algorithm_strength ?? 0} weight="35%" accent={accent} />
          <FactorRow label="Downgrade resistant" ok={score?.factors.downgrade_resistant ?? false} weight="15%" />
          <FactorRow label="Hybrid construction" ok={score?.factors.hybrid_construction ?? false} weight="10%" />
          {score?.factors.zero_trust_events !== undefined && (
            <div className="flex items-center justify-between pt-2 border-t" style={{ borderColor: "var(--border-hairline)" }}>
              <span className="text-sm" style={{ color: "var(--text-primary)" }}>Zero Trust events</span>
              <span className="text-sm font-mono-display font-bold" style={{ color: "var(--status-identity)" }}>{score.factors.zero_trust_events}</span>
            </div>
          )}
        </div>
        {note && score && !score.factors.downgrade_resistant && (
          <p className="mt-4 pt-3 border-t text-[11px] leading-relaxed" style={{ borderColor: "var(--border-hairline)", color: "var(--text-tertiary)" }}>
            {note}
          </p>
        )}
      </Panel>
    </div>
  );
}

export function OverallReadinessCard({ accent, overall }: { accent: string; overall: OverallReadiness | null }) {
  if (!overall) return null;
  return (
    <Panel className="px-6 py-5">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Gauge size={20} style={{ color: accent }} />
          <div>
            <div className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Overall platform score</div>
            <div className="text-xs" style={{ color: "var(--text-tertiary)" }}>IPsec + SSH + TLS combined</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-3xl font-extrabold font-mono-display" style={{ color: gradeColor(overall.grade) }}>{overall.overall_score}</div>
          {overall.cnsa_ready && (
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display font-bold" style={{ background: "var(--status-safe-glow)", color: "var(--status-safe)" }}>
              <ShieldCheck size={13} /> CNSA 2.0 READY
            </span>
          )}
        </div>
      </div>
    </Panel>
  );
}

function FactorBar({ label, value, weight, accent }: { label: string; value: number; weight: string; accent: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-sm" style={{ color: "var(--text-primary)" }}>{label}</span>
        <span className="text-xs font-mono-display" style={{ color: "var(--text-secondary)" }}>
          {value.toFixed(0)}% <span style={{ color: "var(--text-tertiary)" }}>({weight})</span>
        </span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-hairline)" }} role="progressbar" aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: accent, transition: "width 0.6s ease" }} />
      </div>
    </div>
  );
}

function FactorRow({ label, ok, weight }: { label: string; ok: boolean; weight: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm" style={{ color: "var(--text-primary)" }}>{label}</span>
      <div className="flex items-center gap-2">
        {ok ? <Check size={15} style={{ color: "var(--status-safe)" }} /> : <X size={15} style={{ color: "var(--status-warning)" }} />}
        <span className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>({weight})</span>
      </div>
    </div>
  );
}
