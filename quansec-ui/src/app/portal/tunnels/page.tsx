"use client";

import { useLiveStats } from "@/lib/use-live-stats";
import { Panel, PanelHeader, PqcBadge, StateBadge } from "@/components/ui-primitives";
import { ArrowRight } from "lucide-react";

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export default function TunnelsPage() {
  const { tunnels } = useLiveStats();

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display tracking-[0.18em] uppercase mb-1" style={{ color: "var(--text-primary)" }}>
          Network
        </div>
        <h1 className="text-2xl font-bold tracking-tight">IPsec Tunnels</h1>
      </div>

      <div className="space-y-4">
        {tunnels.length === 0 && (
          <Panel className="px-6 py-12 text-center text-sm" >
            <span style={{ color: "var(--text-primary)" }}>No tunnels reporting</span>
          </Panel>
        )}

        {tunnels.map((t) => (
          <Panel key={t.id} className="overflow-hidden">
            <PanelHeader
              title={t.name}
              right={<StateBadge state={t.state} />}
            />
            <div className="px-5 py-5">
              {/* Route */}
              <div className="flex items-center gap-3 mb-6 font-mono-display text-sm">
                <span className="px-3 py-1.5 rounded-md" style={{ background: "var(--bg-panel-raised)", color: "var(--text-primary)" }}>{t.local_host}</span>
                <ArrowRight size={14} style={{ color: "var(--text-primary)" }} />
                <span className="px-3 py-1.5 rounded-md" style={{ background: "var(--bg-panel-raised)", color: "var(--text-primary)" }}>{t.remote_host}</span>
                <span className="ml-auto"><PqcBadge pqc={t.pqc_enabled} /></span>
              </div>

              {/* Grid of details */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
                <div>
                  <div className="text-[10px] font-mono-display uppercase tracking-wider mb-1.5" style={{ color: "var(--text-primary)" }}>IKE Version</div>
                  <div className="text-sm font-mono-display" style={{ color: "var(--text-primary)" }}>IKEv{t.ike_version}</div>
                </div>
                <div>
                  <div className="text-[10px] font-mono-display uppercase tracking-wider mb-1.5" style={{ color: "var(--text-primary)" }}>Key Exchange</div>
                  <div className="text-sm font-mono-display" style={{ color: t.pqc_kem ? "var(--pqc-cyan)" : "var(--text-primary)" }}>
                    {t.pqc_kem ?? "Classical"}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-mono-display uppercase tracking-wider mb-1.5" style={{ color: "var(--text-primary)" }}>Bytes In / Out</div>
                  <div className="text-sm font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>
                    {formatBytes(t.bytes_in)} / {formatBytes(t.bytes_out)}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-mono-display uppercase tracking-wider mb-1.5" style={{ color: "var(--text-primary)" }}>Packets In / Out</div>
                  <div className="text-sm font-mono-display tabular-nums" style={{ color: "var(--text-primary)" }}>
                    {t.packets_in} / {t.packets_out}
                  </div>
                </div>
              </div>

              {(t.ike_proposal || t.esp_proposal) && (
                <div className="mt-5 pt-5 border-t space-y-2" style={{ borderColor: "var(--border-hairline)" }}>
                  {t.ike_proposal && (
                    <div className="text-xs font-mono-display">
                      <span style={{ color: "var(--text-primary)" }}>IKE  </span>
                      <span style={{ color: "var(--text-primary)" }}>{t.ike_proposal}</span>
                    </div>
                  )}
                  {t.esp_proposal && (
                    <div className="text-xs font-mono-display">
                      <span style={{ color: "var(--text-primary)" }}>ESP  </span>
                      <span style={{ color: "var(--text-primary)" }}>{t.esp_proposal}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </Panel>
        ))}
      </div>
    </div>
  );
}
