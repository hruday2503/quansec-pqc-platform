"use client";

import { ReactNode } from "react";
import { Lock, ShieldAlert, ShieldCheck } from "lucide-react";

export function Panel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border shadow-[0_1px_0_0_rgba(255,255,255,0.03)_inset] ${className}`}
      style={{
        background: "var(--bg-panel)",
        borderColor: "var(--border-hairline-bright)",
      }}
    >
      {children}
    </div>
  );
}

export function PanelHeader({
  eyebrow,
  title,
  right,
}: {
  eyebrow?: string;
  title: string;
  right?: ReactNode;
}) {
  return (
    <div
      className="flex items-center justify-between px-5 py-4 border-b"
      style={{ borderColor: "var(--border-hairline)" }}
    >
      <div>
        {eyebrow && (
          <div
            className="text-[10px] tracking-[0.18em] uppercase mb-1 font-mono-display font-semibold"
            style={{ color: "var(--pqc-cyan-dim)" }}
          >
            {eyebrow}
          </div>
        )}
        <h2 className="text-[15px] font-semibold" style={{ color: "var(--text-primary)" }}>
          {title}
        </h2>
      </div>
      {right}
    </div>
  );
}

export function PqcBadge({ pqc, size = "md" }: { pqc: boolean; size?: "sm" | "md" }) {
  const padding = size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs";
  if (pqc) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full font-mono-display font-medium ${padding}`}
        style={{
          background: "var(--pqc-cyan-glow)",
          color: "var(--pqc-cyan)",
          border: "1px solid var(--pqc-cyan-dim)",
        }}
      >
        <ShieldCheck size={size === "sm" ? 11 : 13} strokeWidth={2.5} />
        QUANTUM-SAFE
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-mono-display font-medium ${padding}`}
      style={{
        background: "var(--threat-amber-glow)",
        color: "var(--threat-amber)",
        border: "1px solid var(--threat-amber-dim)",
      }}
    >
      <ShieldAlert size={size === "sm" ? 11 : 13} strokeWidth={2.5} />
      CLASSICAL
    </span>
  );
}

export function StateBadge({ state }: { state: string }) {
  const s = state.toUpperCase();
  const isUp = s === "ESTABLISHED" || s === "INSTALLED";
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-mono-display font-medium"
      style={{ color: isUp ? "var(--pqc-cyan)" : "var(--text-tertiary)" }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${isUp ? "pulse-dot" : ""}`}
        style={{ background: isUp ? "var(--pqc-cyan)" : "var(--text-tertiary)" }}
      />
      {s}
    </span>
  );
}

export function AttackResultBadge({ result }: { result: string }) {
  const r = result.toUpperCase();
  const isSafe = ["BLOCKED", "RESISTANT", "PROTECTED"].includes(r);
  const isUnsafe = ["VULNERABLE", "BROKEN"].includes(r);
  const color = isSafe ? "var(--pqc-cyan)" : isUnsafe ? "var(--danger-red)" : "var(--text-secondary)";
  const glow = isSafe ? "var(--pqc-cyan-glow)" : isUnsafe ? "var(--danger-glow)" : "transparent";
  const border = isSafe ? "var(--pqc-cyan-dim)" : isUnsafe ? "#7a1f33" : "var(--border-hairline)";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono-display font-bold tracking-wide"
      style={{ background: glow, color, border: `1px solid ${border}` }}
    >
      {isUnsafe ? <Lock size={12} /> : <ShieldCheck size={12} />}
      {r}
    </span>
  );
}

export function MetricValue({
  value,
  unit,
  tone = "default",
}: {
  value: string | number;
  unit?: string;
  tone?: "default" | "cyan" | "amber" | "violet";
}) {
  const colorMap: Record<string, string> = {
    default: "var(--text-primary)",
    cyan: "var(--pqc-cyan)",
    amber: "var(--threat-amber)",
    violet: "var(--lattice-violet)",
  };
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-3xl font-bold font-mono-display tabular-nums" style={{ color: colorMap[tone] }}>
        {value}
      </span>
      {unit && (
        <span className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>
          {unit}
        </span>
      )}
    </div>
  );
}
