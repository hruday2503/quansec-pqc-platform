"use client";

import { LucideIcon, Loader2, Crosshair, Search, FileText, ShieldAlert, Wrench } from "lucide-react";
import { Panel, StatusBadge, StatusTone } from "@/components/ui-primitives";

export interface AttackDefinition {
  id: string;
  label: string;
  icon: LucideIcon;
  description: string;
}

export interface AttackOutcome {
  attack: string;
  result: string;
  technique?: string;
  target?: string;
  finding?: string;
  detail?: string;
  risk?: string;
  remediation?: string;
  [key: string]: unknown;
}

const HIDDEN_FIELDS = new Set(["attack", "result", "technique", "target", "finding", "detail", "risk", "remediation"]);

function riskTone(risk?: string): StatusTone {
  switch ((risk ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "critical";
    case "medium":
      return "warning";
    default:
      return "safe";
  }
}

function Section({ icon: Icon, label, children }: { icon: LucideIcon; label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5">
        <Icon size={11} style={{ color: "var(--text-tertiary)" }} />
        <span className="text-[10px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-tertiary)" }}>{label}</span>
      </div>
      {children}
    </div>
  );
}

/**
 * One attack technique: a run control, and — once run — the analysis broken
 * into distinct target / findings / evidence / risk / remediation sections
 * rather than one undifferentiated result blob.
 */
export function AttackCard({
  attack,
  outcome,
  running,
  disabled,
  onRun,
}: {
  attack: AttackDefinition;
  outcome?: AttackOutcome;
  running: boolean;
  disabled: boolean;
  onRun: () => void;
}) {
  const Icon = attack.icon;
  const evidence = outcome
    ? Object.entries(outcome).filter(([k]) => !HIDDEN_FIELDS.has(k))
    : [];

  return (
    <Panel className="overflow-hidden">
      <div className="px-5 py-4 flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3.5 min-w-0">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
            style={{ background: "var(--status-identity-glow)", border: "1px solid var(--status-identity-dim)" }}
          >
            <Icon size={16} style={{ color: "var(--status-identity)" }} />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{attack.label}</div>
            <div className="text-xs truncate" style={{ color: "var(--text-tertiary)" }}>{attack.description}</div>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {outcome && <StatusBadge tone={outcome.result === "BROKEN" || outcome.result === "VULNERABLE" ? "critical" : "safe"} label={outcome.result} />}
          <button
            onClick={onRun}
            disabled={disabled}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold font-mono-display transition-opacity disabled:opacity-50 focus-ring"
            style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
          >
            {running && <Loader2 size={13} className="animate-spin" />}
            {running ? "Running…" : "Run analysis"}
          </button>
        </div>
      </div>

      {outcome && (
        <div className="px-5 pb-5 pt-1 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 rounded-lg p-4" style={{ background: "var(--bg-panel-raised)" }}>
            {outcome.target && (
              <Section icon={Crosshair} label="Target configuration">
                <div className="text-xs font-mono-display break-all" style={{ color: "var(--text-primary)" }}>{outcome.target}</div>
              </Section>
            )}
            <Section icon={ShieldAlert} label="Risk">
              <StatusBadge tone={riskTone(outcome.risk)} label={outcome.risk ?? "Unknown"} size="sm" />
            </Section>
            {(outcome.finding || outcome.detail) && (
              <div className="md:col-span-2">
                <Section icon={Search} label="Finding">
                  <p className="text-sm leading-relaxed" style={{ color: "var(--text-primary)" }}>
                    {outcome.finding ?? outcome.detail}
                  </p>
                </Section>
              </div>
            )}
            {evidence.length > 0 && (
              <div className="md:col-span-2">
                <Section icon={FileText} label="Evidence">
                  <div className="space-y-1">
                    {evidence.map(([k, v]) => (
                      <div key={k} className="flex items-start justify-between gap-4 py-1 border-b last:border-0" style={{ borderColor: "var(--border-hairline)" }}>
                        <span className="text-[11px] font-mono-display uppercase tracking-wide shrink-0" style={{ color: "var(--text-tertiary)" }}>
                          {k.replace(/_/g, " ")}
                        </span>
                        <span className="text-xs font-mono-display text-right break-all" style={{ color: "var(--text-secondary)" }}>
                          {typeof v === "object" ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </Section>
              </div>
            )}
            {outcome.remediation && (
              <div className="md:col-span-2">
                <Section icon={Wrench} label="Remediation">
                  <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>{outcome.remediation}</p>
                </Section>
              </div>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}
