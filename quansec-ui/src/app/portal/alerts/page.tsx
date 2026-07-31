"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/ui-primitives";
import { Bell, BellOff, AlertTriangle, ShieldAlert, Check } from "lucide-react";
import { authHeaders } from "@/lib/auth-fetch";

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";

interface Alert {
  id: number; rule: string; severity: string; protocol: string;
  message: string; acked: boolean; raised_at: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "var(--danger-red)",
  high: "var(--danger-red)",
  medium: "var(--threat-amber)",
  low: "var(--lattice-violet)",
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [activeCount, setActiveCount] = useState(0);

  const load = async () => {
    try {
      const d = await fetch(`${API_BASE}/api/alerts`, { headers: authHeaders() }).then((r) => r.json());
      setAlerts(d.alerts || []);
      setActiveCount(d.active_count || 0);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  const ack = async (id: number) => {
    await fetch(`${API_BASE}/api/alerts/${id}/ack`, { method: "POST", headers: authHeaders() });
    await load();
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8 flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--threat-amber)" }}>
            Monitoring
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>Alerts</h1>
        </div>
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg" style={{ background: activeCount > 0 ? "var(--danger-glow)" : "var(--pqc-cyan-glow)", border: `1px solid ${activeCount > 0 ? "var(--danger-red)" : "var(--pqc-cyan-dim)"}` }}>
          {activeCount > 0 ? <Bell size={16} style={{ color: "var(--danger-red)" }} /> : <BellOff size={16} style={{ color: "var(--pqc-cyan)" }} />}
          <span className="text-sm font-bold font-mono-display" style={{ color: activeCount > 0 ? "var(--danger-red)" : "var(--pqc-cyan)" }}>
            {activeCount} active
          </span>
        </div>
      </div>

      <Panel>
        <PanelHeader eyebrow={`${alerts.length} total`} title="Alert Feed" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {alerts.length === 0 && (
            <div className="px-5 py-12 text-center">
              <ShieldAlert size={28} className="mx-auto mb-3" style={{ color: "var(--pqc-cyan)" }} />
              <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>All clear</div>
              <div className="text-xs mt-1" style={{ color: "var(--text-primary)" }}>No alerts — all connections quantum-safe</div>
            </div>
          )}
          {alerts.map((a) => (
            <div key={a.id} className="px-5 py-4 flex items-start justify-between gap-4" style={{ opacity: a.acked ? 0.5 : 1 }}>
              <div className="flex items-start gap-3 min-w-0">
                <AlertTriangle size={16} style={{ color: SEV_COLOR[a.severity] || "var(--text-tertiary)" }} className="shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{a.message}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono-display font-bold uppercase px-1.5 py-0.5 rounded" style={{ background: "var(--bg-panel-raised)", color: SEV_COLOR[a.severity] }}>{a.severity}</span>
                    <span className="text-[10px] font-mono-display uppercase px-1.5 py-0.5 rounded" style={{ background: "var(--bg-panel-raised)", color: "var(--text-primary)" }}>{a.protocol}</span>
                    <span className="text-[10px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>{new Date(a.raised_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>
              {!a.acked && (
                <button onClick={() => ack(a.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono-display font-bold shrink-0 focus-ring" style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}>
                  <Check size={12} /> ACK
                </button>
              )}
              {a.acked && <span className="text-[10px] font-mono-display uppercase shrink-0" style={{ color: "var(--text-tertiary)" }}>acknowledged</span>}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
