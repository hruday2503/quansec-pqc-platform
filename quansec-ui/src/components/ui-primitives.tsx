"use client";

import { ReactNode, useEffect, useId, useRef } from "react";
import { AlertTriangle, Inbox, Lock, ShieldAlert, ShieldCheck, ShieldQuestion, X } from "lucide-react";

/**
 * The one status→color mapping every badge and indicator in the app reads
 * from. Never render a status by color alone — each tone always carries an
 * icon and a readable label alongside it.
 */
export type StatusTone = "safe" | "warning" | "critical" | "identity" | "neutral";

const TONE: Record<StatusTone, { color: string; dim: string; glow: string; Icon: typeof ShieldCheck }> = {
  safe: { color: "var(--status-safe)", dim: "var(--status-safe-dim)", glow: "var(--status-safe-glow)", Icon: ShieldCheck },
  warning: { color: "var(--status-warning)", dim: "var(--status-warning-dim)", glow: "var(--status-warning-glow)", Icon: ShieldAlert },
  critical: { color: "var(--status-critical)", dim: "var(--status-critical-dim)", glow: "var(--status-critical-glow)", Icon: Lock },
  identity: { color: "var(--status-identity)", dim: "var(--status-identity-dim)", glow: "var(--status-identity-glow)", Icon: ShieldCheck },
  neutral: { color: "var(--status-neutral)", dim: "var(--status-neutral-dim)", glow: "var(--status-neutral-glow)", Icon: ShieldQuestion },
};

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

/**
 * Canonical status pill: tone → color is the single source of truth (see
 * TONE above). Always renders an icon alongside the label — color is never
 * the only signal.
 */
export function StatusBadge({
  tone,
  label,
  size = "md",
  icon,
}: {
  tone: StatusTone;
  label: string;
  size?: "sm" | "md";
  icon?: ReactNode;
}) {
  const padding = size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs";
  const t = TONE[tone];
  const { Icon } = t;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-mono-display font-medium ${padding}`}
      style={{ background: t.glow, color: t.color, border: `1px solid ${t.dim}` }}
    >
      {icon ?? <Icon size={size === "sm" ? 11 : 13} strokeWidth={2.5} />}
      {label}
    </span>
  );
}

export function PqcBadge({ pqc, size = "md" }: { pqc: boolean; size?: "sm" | "md" }) {
  return pqc
    ? <StatusBadge tone="safe" label="QUANTUM-SAFE" size={size} />
    : <StatusBadge tone="warning" label="CLASSICAL" size={size} />;
}

export function StateBadge({ state }: { state: string }) {
  const s = state.toUpperCase();
  const isUp = s === "ESTABLISHED" || s === "INSTALLED";
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-mono-display font-medium"
      style={{ color: isUp ? "var(--status-safe)" : "var(--status-neutral)" }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${isUp ? "pulse-dot" : ""}`}
        style={{ background: isUp ? "var(--status-safe)" : "var(--status-neutral)" }}
      />
      {s}
    </span>
  );
}

export function AttackResultBadge({ result }: { result: string }) {
  const r = result.toUpperCase();
  const isSafe = ["BLOCKED", "RESISTANT", "PROTECTED"].includes(r);
  const isUnsafe = ["VULNERABLE", "BROKEN"].includes(r);
  const tone: StatusTone = isSafe ? "safe" : isUnsafe ? "critical" : "neutral";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono-display font-bold tracking-wide"
      style={{ background: TONE[tone].glow, color: TONE[tone].color, border: `1px solid ${TONE[tone].dim}` }}
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

/**
 * The kicker + title + description + trailing-action block that opens every
 * page. One shared header means the label size, tracking, and spacing above
 * an h1 can never drift page to page.
 */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  accent = "var(--pqc-cyan-dim)",
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="mb-8 flex items-start justify-between gap-4 flex-wrap">
      <div>
        {eyebrow && (
          <div
            className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5"
            style={{ color: accent }}
          >
            {eyebrow}
          </div>
        )}
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
          {title}
        </h1>
        {description && (
          <p className="text-sm mt-1.5 max-w-xl" style={{ color: "var(--text-secondary)" }}>
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-3 shrink-0">{actions}</div>}
    </div>
  );
}

/**
 * A table or list with nothing in it, explained rather than left blank. An
 * empty screen is an invitation to act, so a `hint` describing how to
 * populate it is preferred over a bare "nothing here".
 */
export function EmptyState({
  icon,
  title,
  hint,
}: {
  icon?: ReactNode;
  title: string;
  hint?: string;
}) {
  return (
    <div className="px-5 py-12 text-center">
      <div className="mx-auto mb-3 flex items-center justify-center" style={{ color: "var(--text-tertiary)" }}>
        {icon ?? <Inbox size={28} />}
      </div>
      <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{title}</div>
      {hint && (
        <div className="text-xs mt-1 max-w-sm mx-auto leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
          {hint}
        </div>
      )}
    </div>
  );
}

/** A failed load, stated plainly: what happened, and — where known — why. */
export function ErrorState({ message }: { message: string }) {
  return (
    <div
      className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
      style={{ background: "var(--status-critical-glow)", color: "var(--status-critical)", border: `1px solid ${TONE.critical.dim}` }}
      role="alert"
    >
      <AlertTriangle size={14} /> {message}
    </div>
  );
}

/** A pulsing placeholder block. Reserves layout space so content doesn't jump in once it loads. */
export function Skeleton({ className = "", height = 16 }: { className?: string; height?: number }) {
  return (
    <div
      className={`rounded-md animate-pulse ${className}`}
      style={{ height, background: "var(--bg-panel-raised)" }}
      aria-hidden="true"
    />
  );
}

/** A row of stat-card skeletons, for the first paint of a metrics grid. */
export function MetricCardSkeleton() {
  return (
    <Panel className="px-6 py-5">
      <Skeleton className="w-24 mb-3.5" height={12} />
      <Skeleton className="w-16" height={32} />
    </Panel>
  );
}

/**
 * An accessible icon-only control. `label` becomes the accessible name (and
 * the tooltip) — an icon alone is never a sufficient name for a button.
 */
export function IconButton({
  icon,
  label,
  onClick,
  tone = "neutral",
}: {
  icon: ReactNode;
  label: string;
  onClick?: () => void;
  tone?: "neutral" | "critical";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="p-1.5 rounded-lg focus-ring transition-colors"
      style={{ color: tone === "critical" ? "var(--status-critical)" : "var(--text-tertiary)" }}
    >
      {icon}
    </button>
  );
}

/** A row of tabs. Content panel is the caller's responsibility. */
export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
  accent = "var(--pqc-cyan)",
  accentGlow = "var(--pqc-cyan-glow)",
  accentDim = "var(--pqc-cyan-dim)",
}: {
  tabs: { value: T; label: string }[];
  active: T;
  onChange: (value: T) => void;
  accent?: string;
  accentGlow?: string;
  accentDim?: string;
}) {
  return (
    <div role="tablist" className="flex gap-1.5 flex-wrap">
      {tabs.map((t) => {
        const isActive = t.value === active;
        return (
          <button
            key={t.value}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(t.value)}
            className="px-3 py-1.5 rounded-md text-xs font-mono-display transition-colors focus-ring"
            style={{
              background: isActive ? accentGlow : "var(--bg-panel-raised)",
              color: isActive ? accent : "var(--text-tertiary)",
              border: `1px solid ${isActive ? accentDim : "var(--border-hairline)"}`,
            }}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

/**
 * A modal confirmation for a destructive or hard-to-reverse action. Traps
 * focus, closes on Escape, and returns focus to the trigger on close.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  tone = "critical",
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "critical" | "safe";
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const titleId = useId();
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    confirmRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  const color = tone === "critical" ? "var(--status-critical)" : "var(--status-safe)";
  const borderColor = tone === "critical" ? TONE.critical.dim : TONE.safe.dim;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(0,0,0,0.72)" }}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={onCancel}
    >
      <div
        className="w-full max-w-md rounded-2xl p-5 space-y-4"
        style={{ background: "var(--bg-panel)", border: `1px solid ${borderColor}` }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} style={{ color }} />
          <span id={titleId} className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{title}</span>
        </div>
        <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{description}</p>
        <div className="flex gap-2">
          <button
            ref={confirmRef}
            onClick={onConfirm}
            className="px-3.5 py-2 rounded-lg text-xs font-bold focus-ring"
            style={{ background: color, color: tone === "critical" ? "#fff" : "#04201c" }}
          >
            {confirmLabel}
          </button>
          <button
            onClick={onCancel}
            className="px-3.5 py-2 rounded-lg text-xs font-medium focus-ring"
            style={{ color: "var(--text-tertiary)", border: "1px solid var(--border-hairline)" }}
          >
            {cancelLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/** A small "×" dismiss control for panels and modals — always labeled. */
export function DismissButton({ label = "Close", onClick }: { label?: string; onClick: () => void }) {
  return <IconButton icon={<X size={16} />} label={label} onClick={onClick} />;
}
