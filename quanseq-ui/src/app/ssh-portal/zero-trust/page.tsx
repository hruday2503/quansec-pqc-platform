"use client";

import { useEffect, useState } from "react";
import { Panel, PanelHeader, PageHeader, EmptyState } from "@/components/ui-primitives";
import { ShieldCheck, ShieldX, KeyRound, Clock, UserCheck, Ban, Fingerprint, Users } from "lucide-react";
import { authHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

interface ZtEvent {
  event_time: string; identity: string; cert_serial: string; ca_fingerprint: string;
  source_ip: string; principal: string; result: string; reason: string;
}
interface ZtStatus {
  total_auth_events: number; accepted: number; rejected: number; rejected_expired: number;
}
interface ZtPrinciple { principle: string; status: string; detail: string; }
interface ZtPolicy {
  authentication: string; passwords: string; network_trust: string;
  credential_lifetime: string; transport: string; principles: ZtPrinciple[];
}

export default function ZeroTrustPage() {
  const [events, setEvents] = useState<ZtEvent[]>([]);
  const [status, setStatus] = useState<ZtStatus | null>(null);
  const [policy, setPolicy] = useState<ZtPolicy | null>(null);

  const load = async () => {
    try {
      const [e, s, p] = await Promise.all([
        mockFetch(`/api/ssh/zt/events`, { headers: authHeaders() }).then((r) => r.json()),
        mockFetch(`/api/ssh/zt/status`, { headers: authHeaders() }).then((r) => r.json()),
        mockFetch(`/api/ssh/zt/policy`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setEvents(Array.isArray(e) ? e : []);
      setStatus(s); setPolicy(p);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <PageHeader
        eyebrow="Access control"
        title="Zero Trust"
        description="Certificate-based identity, no passwords, no implicit network trust — all on post-quantum transport."
        accent="var(--lattice-violet)"
      />

      {/* Status cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <Panel className="px-5 py-4">
          <div className="flex items-center gap-2 mb-2"><UserCheck size={14} style={{ color: "var(--pqc-cyan)" }} /><span className="text-[10px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>Accepted</span></div>
          <div className="text-3xl font-extrabold font-mono-display" style={{ color: "var(--pqc-cyan)" }}>{status?.accepted ?? 0}</div>
        </Panel>
        <Panel className="px-5 py-4">
          <div className="flex items-center gap-2 mb-2"><Ban size={14} style={{ color: "var(--danger-red)" }} /><span className="text-[10px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>Rejected</span></div>
          <div className="text-3xl font-extrabold font-mono-display" style={{ color: "var(--danger-red)" }}>{status?.rejected ?? 0}</div>
        </Panel>
        <Panel className="px-5 py-4">
          <div className="flex items-center gap-2 mb-2"><Clock size={14} style={{ color: "var(--threat-amber)" }} /><span className="text-[10px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>Expired Blocks</span></div>
          <div className="text-3xl font-extrabold font-mono-display" style={{ color: "var(--threat-amber)" }}>{status?.rejected_expired ?? 0}</div>
        </Panel>
        <Panel className="px-5 py-4">
          <div className="flex items-center gap-2 mb-2"><KeyRound size={14} style={{ color: "var(--lattice-violet)" }} /><span className="text-[10px] font-mono-display font-bold uppercase tracking-wider" style={{ color: "var(--text-primary)" }}>Passwords</span></div>
          <div className="text-lg font-extrabold font-mono-display" style={{ color: "var(--pqc-cyan)" }}>DISABLED</div>
        </Panel>
      </div>

      {/* Policy posture */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Enforcement" title="Zero Trust Posture" />
        <div className="divide-y" style={{ borderColor: "var(--border-hairline)" }}>
          {policy?.principles.map((p) => (
            <div key={p.principle} className="px-5 py-3.5 flex items-center gap-4">
              <ShieldCheck size={16} style={{ color: "var(--pqc-cyan)" }} className="shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{p.principle}</div>
                <div className="text-xs" style={{ color: "var(--text-primary)" }}>{p.detail}</div>
              </div>
              <span className="text-[10px] font-mono-display font-bold uppercase px-2 py-0.5 rounded shrink-0" style={{ background: "var(--pqc-cyan-glow)", color: "var(--pqc-cyan)" }}>{p.status}</span>
            </div>
          ))}
        </div>
      </Panel>

      {/* Audit trail */}
      <Panel>
        <PanelHeader eyebrow="Audit Trail" title="Certificate Authentication Events" />
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left border-b" style={{ borderColor: "var(--border-hairline)" }}>
                {["Time", "Identity", "Serial", "Principal", "Source", "Result"].map((h) => (
                  <th key={h} className="px-4 py-2.5 font-mono-display text-[10px] uppercase tracking-wider font-bold" style={{ color: "var(--text-primary)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr><td colSpan={6}>
                  <EmptyState icon={<Users size={28} />} title="No certificate auth events yet" hint="A row appears here once a user authenticates with a certificate." />
                </td></tr>
              )}
              {events.map((e, i) => (
                <tr key={`${e.cert_serial}-${e.event_time}-${i}`} className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>{e.event_time ? new Date(e.event_time).toLocaleTimeString() : "—"}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--lattice-violet)" }}>
                    <span className="flex items-center gap-1.5"><Fingerprint size={11} />{e.identity}</span>
                  </td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>#{e.cert_serial}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>{e.principal}</td>
                  <td className="px-4 py-3 font-mono-display" style={{ color: "var(--text-primary)" }}>{e.source_ip}</td>
                  <td className="px-4 py-3">
                    {e.result === "accepted" ? (
                      <span className="flex items-center gap-1.5 font-mono-display font-bold" style={{ color: "var(--pqc-cyan)" }}><ShieldCheck size={12} />ACCEPTED</span>
                    ) : (
                      <span className="flex items-center gap-1.5 font-mono-display font-bold" style={{ color: "var(--danger-red)" }}><ShieldX size={12} />{e.reason?.toUpperCase() || "REJECTED"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
