"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, PlugZap, RefreshCw, XCircle } from "lucide-react";
import { quanseq, TlsProbeSuite, TlsSession, TlsStats, TlsStatus } from "@/lib/api";
import { Panel, PanelHeader, MetricValue } from "@/components/ui-primitives";
import { HybridBadge, HybridExplanation } from "@/components/hybrid-badge";

const POLL_MS = 10000;

function Field({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b last:border-b-0"
         style={{ borderColor: "var(--border-hairline)" }}>
      <span className="text-xs shrink-0" style={{ color: "var(--text-tertiary)" }}>{label}</span>
      <span className={`text-xs text-right break-all ${mono ? "font-mono-display" : ""}`}
            style={{ color: "var(--text-primary)" }}>
        {value ?? <span style={{ color: "var(--text-tertiary)" }}>—</span>}
      </span>
    </div>
  );
}

/** Undefined renders nothing, so an unloaded status never reads as a NO. */
function Yes({ on }: { on: boolean | undefined }) {
  if (on === undefined) return null;
  return (
    <span style={{ color: on ? "var(--pqc-cyan)" : "var(--text-tertiary)" }}>
      {on ? "YES" : "NO"}
    </span>
  );
}

export default function TlsOverviewPage() {
  const [status, setStatus] = useState<TlsStatus | null>(null);
  const [stats, setStats] = useState<TlsStats | null>(null);
  const [session, setSession] = useState<TlsSession | null>(null);
  const [probe, setProbe] = useState<TlsProbeSuite | null>(null);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, st] = await Promise.all([quanseq.getTlsStatus(), quanseq.getTlsStats()]);
      setStatus(s);
      setStats(st);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Failed to load TLS status");
    }
    try {
      // Sessions come back newest first, so one row is the latest observation.
      const [latest] = await quanseq.getTlsSessions(1);
      setSession(latest ?? null);
    } catch {
      // An empty log before the collector's first read is expected, not an error.
      setSession(null);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  const runProbes = async () => {
    setProbing(true);
    setProbeError(null);
    try {
      setProbe(await quanseq.runTlsProbe());
      await load();
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : "Probe suite could not run");
    } finally {
      setProbing(false);
    }
  };

  const listening = status?.service.listening ?? false;

  return (
    <div className="p-8 max-w-6xl space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
            TLS 1.3 Transport
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Real handshakes against QUANSEQ&apos;s NGINX data plane
            {status && (
              <span className="font-mono-display"> · {status.service.host}:{status.service.port}</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <HybridBadge status={status} />
          <button onClick={runProbes} disabled={probing}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold focus-ring disabled:opacity-50"
            style={{ background: "var(--pqc-cyan)", color: "#04231f" }}>
            {probing ? <RefreshCw size={13} className="animate-spin" /> : <PlugZap size={13} strokeWidth={2.5} />}
            {probing ? "Probing…" : "Run probe suite"}
          </button>
        </div>
      </div>

      {loadError && (
        <div className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
             style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>
          <XCircle size={14} /> {loadError}
        </div>
      )}
      {probeError && (
        <div className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
             style={{ background: "var(--threat-amber-glow)", color: "var(--threat-amber)", border: "1px solid var(--threat-amber-dim)" }}>
          <AlertTriangle size={14} /> {probeError}
        </div>
      )}

      {/* A negative probe PASSES when the handshake is refused, so the passed
          count is not readable as "things that worked". Only enforcement_proven
          justifies the enforced claim. */}
      {probe && (
        <div className="px-4 py-3 rounded-lg text-xs flex items-center gap-2 font-mono-display"
             style={{
               background: probe.enforcement_proven ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
               color: probe.enforcement_proven ? "var(--pqc-cyan)" : "var(--text-secondary)",
               border: `1px solid ${probe.enforcement_proven ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
             }}>
          {probe.enforcement_proven ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          {probe.passed}/{probe.total} probes met their expected outcome · {probe.summary}
        </div>
      )}

      {/* ── Data plane ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Panel>
          <div className="p-5">
            <div className="text-[10px] tracking-[0.18em] uppercase font-mono-display font-semibold mb-2"
                 style={{ color: "var(--pqc-cyan-dim)" }}>Data plane</div>
            <div className="flex items-center gap-2">
              {listening
                ? <CheckCircle2 size={20} style={{ color: "var(--pqc-cyan)" }} />
                : <XCircle size={20} style={{ color: "var(--danger-red)" }} />}
              <span className="text-lg font-bold font-mono-display"
                    style={{ color: listening ? "var(--pqc-cyan)" : "var(--danger-red)" }}>
                {listening ? "LISTENING" : "DOWN"}
              </span>
            </div>
            <div className="text-xs font-mono-display mt-1" style={{ color: "var(--text-tertiary)" }}>
              {status?.service.running
                ? `nginx pid ${status.service.pid ?? "?"}`
                : "nginx not running"}
            </div>
            {status?.service.error && (
              <div className="text-[10px] font-mono-display mt-2 break-words" style={{ color: "var(--text-tertiary)" }}>
                {status.service.error}
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <div className="p-5">
            <div className="text-[10px] tracking-[0.18em] uppercase font-mono-display font-semibold mb-2"
                 style={{ color: "var(--pqc-cyan-dim)" }}>Sessions</div>
            <MetricValue value={stats?.total_sessions ?? 0} />
            <div className="text-xs font-mono-display mt-1" style={{ color: "var(--text-tertiary)" }}>
              {stats?.active_sessions ?? 0} active
              {stats && ` · ${stats.active_window_seconds}s window`}
            </div>
          </div>
        </Panel>

        <Panel>
          <div className="p-5">
            <div className="text-[10px] tracking-[0.18em] uppercase font-mono-display font-semibold mb-2"
                 style={{ color: "var(--pqc-cyan-dim)" }}>Hybrid coverage</div>
            <MetricValue
              value={stats?.has_evidence ? stats.hybrid_coverage : "—"}
              unit={stats?.has_evidence ? "%" : undefined}
              tone={stats && stats.hybrid_coverage > 0 ? "cyan" : "amber"}
            />
            {/* An empty table and a measured zero are different facts, and the
                UI distinguishes them rather than printing 0% for both. */}
            <div className="text-[10px] font-mono-display mt-1 leading-snug" style={{ color: "var(--text-tertiary)" }}>
              {!stats?.has_evidence
                ? "No session recorded yet"
                : `${stats.hybrid_sessions} hybrid · ${stats.classical_sessions} classical · ${stats.unknown_sessions} unknown`}
            </div>
          </div>
        </Panel>

        <Panel>
          <div className="p-5">
            <div className="text-[10px] tracking-[0.18em] uppercase font-mono-display font-semibold mb-2"
                 style={{ color: "var(--pqc-cyan-dim)" }}>TLS 1.3 coverage</div>
            <MetricValue
              value={stats?.has_evidence ? stats.tls13_coverage : "—"}
              unit={stats?.has_evidence ? "%" : undefined}
              tone={stats && stats.tls13_coverage === 100 ? "cyan" : "amber"}
            />
            <div className="text-xs font-mono-display mt-1" style={{ color: "var(--text-tertiary)" }}>
              {stats?.failed_handshakes ?? 0} failed handshake
              {stats?.failed_handshakes === 1 ? "" : "s"}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Latest observed session ─────────────────────────────────────── */}
        <Panel>
          <PanelHeader
            eyebrow="Observed"
            title="Latest handshake"
            right={session?.occurred_at && (
              <span className="text-[10px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>
                {new Date(session.occurred_at).toLocaleTimeString()}
              </span>
            )}
          />
          <div className="px-5 py-3">
            {!session ? (
              <p className="text-xs py-4" style={{ color: "var(--text-tertiary)" }}>
                No observation recorded yet. The collector tails the NGINX access
                log — use Run probe suite above to generate a handshake.
              </p>
            ) : (
              <>
                <Field label="HTTP status" value={
                  session.http_status == null ? undefined : (
                    <span style={{ color: session.http_status < 400 ? "var(--pqc-cyan)" : "var(--danger-red)" }}>
                      {session.http_status}
                    </span>
                  )
                } />
                <Field label="TLS version" value={session.tls_protocol} />
                <Field label="Cipher suite" value={session.cipher} />
                {/* Rendered explicitly rather than hidden: a null here means
                    "NGINX did not report one", not "no group was used". A
                    resumed session performs no key exchange at all. */}
                <Field label="Negotiated group" value={
                  session.negotiated_group
                    ? <span style={{ color: session.pqc_enabled ? "var(--pqc-cyan)" : "var(--text-primary)" }}>
                        {session.negotiated_group}
                        {session.kem_label && ` (${session.kem_label})`}
                      </span>
                    : <span style={{ color: "var(--text-tertiary)" }}>
                        {session.session_reused
                          ? "resumed session — no key exchange"
                          : "not reported by NGINX"}
                      </span>
                } />
                <Field label="Client groups offered" value={session.client_groups} />
                <Field label="Client certificate" value={
                  session.client_verify === "SUCCESS"
                    ? <span style={{ color: "var(--pqc-cyan)" }}>SUCCESS — mTLS</span>
                    : <span style={{ color: "var(--text-tertiary)" }}>{session.client_verify ?? "NONE"}</span>
                } />
                <Field label="Client DN" value={session.client_s_dn} />
                <Field label="SNI" value={session.server_name} />
                <Field label="Request time" value={
                  session.request_time != null && `${(session.request_time * 1000).toFixed(2)} ms`
                } />
                <Field label="Source" value={
                  session.log_source && `${session.log_source} @ ${session.log_offset}`
                } />
              </>
            )}
          </div>
        </Panel>

        {/* ── Post-quantum status ─────────────────────────────────────────── */}
        <Panel>
          <PanelHeader eyebrow="Post-quantum" title="Hybrid key exchange" right={
            <HybridBadge status={status} size="sm" />
          } />
          <div className="px-5 py-4 space-y-4">
            <HybridExplanation status={status} />

            {/* Listed in ladder order — configured, negotiated, enforced —
                because only the last one is a guarantee. */}
            <div className="pt-1">
              <Field label="Requested group" value={status?.evidence.configured_groups} />
              <Field label="Group configured" value={<Yes on={status?.hybrid_group_configured} />} />
              <Field label="Group negotiated" value={<Yes on={status?.hybrid_group_negotiated} />} />
              <Field label="Classical refused" value={<Yes on={status?.hybrid_only_enforced} />} />
              <Field label="TLS 1.3 enforced" value={<Yes on={status?.tls13_enforced} />} />
              <Field label="Runtime lists group" value={<Yes on={status?.runtime_supported} />} />
              <Field label="NGINX OpenSSL" value={status?.build.nginx_openssl} />
              <Field label="Certificate verified" value={<Yes on={status?.certificate_verified} />} />
            </div>
          </div>
        </Panel>
      </div>

      {/* ── Key-establishment breakdown ─────────────────────────────────── */}
      {stats?.has_evidence && (
        <Panel>
          <PanelHeader
            eyebrow="History"
            title="Key establishment across observed sessions"
            right={stats.last_observed_at && (
              <span className="text-[10px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>
                last {new Date(stats.last_observed_at).toLocaleString()}
              </span>
            )}
          />
          <div className="px-5 py-4 flex flex-wrap gap-3">
            {([
              ["hybrid", stats.hybrid_sessions, "var(--pqc-cyan)"],
              ["classical", stats.classical_sessions, "var(--threat-amber)"],
              ["group not reported", stats.unknown_sessions, "var(--text-tertiary)"],
            ] as const).map(([label, count, color]) => (
              <div key={label} className="px-3 py-2 rounded-lg"
                   style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline)" }}>
                <div className="text-[10px] font-mono-display uppercase tracking-wider" style={{ color }}>
                  {label}
                </div>
                <div className="text-lg font-bold font-mono-display tabular-nums"
                     style={{ color: "var(--text-primary)" }}>{count}</div>
              </div>
            ))}
          </div>
          {/* Said explicitly, because a reader seeing "0 classical" will
              otherwise assume classical was refused. On the portal listener it
              is permitted; only the probes establish refusal. */}
          <div className="px-5 pb-4 text-[11px] leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
            Counts describe what clients negotiated, not what the server required.
            A session with no reported group was resumed and performed no key
            exchange — that is not the same as classical.
          </div>
        </Panel>
      )}

      <p className="text-[11px] leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
        This page reports the NGINX TLS data plane QUANSEQ runs and probes, in the
        same way the IPsec and SSH modules report StrongSwan and sshd. Traffic
        between your browser and this dashboard is separate and is not covered by
        these measurements.
      </p>
    </div>
  );
}
