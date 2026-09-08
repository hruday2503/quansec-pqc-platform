"use client";

import { ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, LucideIcon } from "lucide-react";

export interface AuthStat {
  value: string;
  label: string;
}

/**
 * The split-screen login shell shared by the IPsec, SSH and TLS portals.
 * Only the icon, accent, copy and stat pair change between them — form
 * layout, error handling and the submit affordance stay identical so every
 * portal's login behaves the same way.
 */
export function AuthSplitLayout({
  icon: Icon,
  accent,
  accentGlow,
  accentDim,
  title,
  description,
  stats,
  formTitle,
  formSubtitle,
  children,
}: {
  icon: LucideIcon;
  accent: string;
  accentGlow: string;
  accentDim: string;
  title: string;
  description: string;
  stats: [AuthStat, AuthStat];
  formTitle: string;
  formSubtitle: string;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>
      <div className="hidden lg:flex w-1/2 relative overflow-hidden items-center justify-center">
        <div className="absolute inset-0 lattice-bg-active" style={{ opacity: 0.4 }} />
        <div className="absolute -top-32 -left-32 w-[500px] h-[500px] rounded-full blur-3xl pointer-events-none" style={{ background: accentGlow, opacity: 0.7 }} />
        <div className="absolute inset-0" style={{ background: "radial-gradient(ellipse 700px 700px at 50% 50%, transparent 0%, var(--bg-void) 72%)" }} />
        <div className="relative z-10 max-w-md px-12 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-8" style={{ background: accentGlow, border: `1px solid ${accentDim}` }}>
            <Icon size={30} style={{ color: accent }} strokeWidth={1.8} />
          </div>
          <h1 className="text-3xl font-extrabold mb-4 tracking-tight" style={{ color: "var(--text-primary)" }}>
            {title}
          </h1>
          <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            {description}
          </p>
          <div className="mt-10 flex items-center justify-center gap-8 font-mono-display">
            <div>
              <div className="text-3xl font-extrabold" style={{ color: accent }}>{stats[0].value}</div>
              <div className="text-[10px] font-bold uppercase tracking-widest mt-1" style={{ color: "var(--text-secondary)" }}>{stats[0].label}</div>
            </div>
            <div className="w-px h-10" style={{ background: "var(--border-hairline-bright)" }} />
            <div>
              <div className="text-3xl font-extrabold" style={{ color: accent }}>{stats[1].value}</div>
              <div className="text-[10px] font-bold uppercase tracking-widest mt-1" style={{ color: "var(--text-secondary)" }}>{stats[1].label}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center px-6">
        <div className="w-full max-w-sm">
          <Link href="/" className="inline-flex items-center gap-1.5 text-xs font-mono-display mb-8 focus-ring" style={{ color: "var(--text-tertiary)" }}>
            <ArrowLeft size={13} /> All portals
          </Link>

          <h2 className="text-2xl font-extrabold mb-1" style={{ color: "var(--text-primary)" }}>{formTitle}</h2>
          <p className="text-sm mb-8" style={{ color: "var(--text-secondary)" }}>{formSubtitle}</p>

          {children}
        </div>
      </div>
    </div>
  );
}

export function AuthField({
  label,
  type,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  type: "email" | "password";
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <div>
      <label className="block text-xs font-mono-display font-bold tracking-wide uppercase mb-2" style={{ color: "var(--text-secondary)" }}>
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required
        autoComplete={type === "email" ? "email" : "current-password"}
        className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors focus-ring font-medium"
        style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
        placeholder={placeholder}
      />
    </div>
  );
}

export function AuthSubmit({
  submitting,
  accent,
  onAccent,
  label = "Sign in",
  submittingLabel = "Signing in…",
}: {
  submitting: boolean;
  accent: string;
  onAccent: string;
  label?: string;
  submittingLabel?: string;
}) {
  return (
    <button
      type="submit"
      disabled={submitting}
      className="w-full mt-6 flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-bold transition-opacity focus-ring disabled:opacity-50"
      style={{ background: accent, color: onAccent }}
    >
      {submitting ? submittingLabel : label}
      {!submitting && <ArrowRight size={15} strokeWidth={2.5} />}
    </button>
  );
}

export function AuthError({ message }: { message: string }) {
  return (
    <div
      className="mt-4 px-3.5 py-2.5 rounded-lg text-xs font-mono-display font-semibold"
      style={{ background: "var(--status-critical-glow)", color: "var(--status-critical)", border: "1px solid var(--status-critical-dim)" }}
      role="alert"
    >
      {message}
    </div>
  );
}
