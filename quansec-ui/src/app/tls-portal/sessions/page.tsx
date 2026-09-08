"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, XCircle } from "lucide-react";
import { quansec, TlsSession } from "@/lib/api";
import { Panel, PanelHeader } from "@/components/ui-primitives";

/**
 * Observed TLS sessions.
 *
 * The IPsec portal calls its equivalent "Tunnels". That word does not apply
 * here: a TLS session is a connection, not a tunnel, and nothing in this view
 * is a persistent negotiated channel between two gateways.
 *
 * Every row came from a line NGINX wrote. There is no synthesised row, and a
 * field NGINX did not report is rendered as "not reported" rather than being
 * filled in with a default that would read as a measurement.
 */

const GROUP_FILTERS = ["all", "hybrid", "classical", "unknown"] as const;
type GroupFilter = (typeof GROUP_FILTERS)[number];

function classify(s: TlsSession): Exclude<GroupFilter, "all"> {
  if (!s.negotiated_group) return "unknown";
  return s.pqc_enabled ? "hybrid" : "classical";
}

function GroupBadge({ session }: { session: TlsSession }) {
  const kind = classify(session);
  const style =
    kind === "hybrid"
      ? { color: "var(--pqc-cyan)", background: "var(--pqc-cyan-glow)", border: "var(--pqc-cyan-dim)" }
      : kind === "classical"
        ? { color: "var(--threat-amber)", background: "var(--threat-amber-glow)", border: "var(--threat-amber-dim)" }
        : { color: "var(--text-tertiary)", background: "var(--bg-panel-raised)", border: "var(--border-hairline)" };

  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-mono-display font-medium"
      style={{ color: style.color, background: style.background, border: `1px solid ${style.border}` }}
      title={
        kind === "unknown"
          ? session.session_reused
            ? "Session was resumed — a resumed session performs no key exchange, so there is no group to report"
            : "NGINX reported no group for this session"
          : session.negotiated_group ?? ""
      }
    >
      {kind === "unknown" ? "NO GROUP" : session.negotiated_group}
    </span>
  );
}

function Cell({ children, mono = true }: { children: React.ReactNode; mono?: boolean }) {
  return (
    <td className={`px-4 py-2.5 text-xs align-top ${mono ? "font-mono-display" : ""}`}
        style={{ color: "var(--text-primary)" }}>
      {children ?? <span style={{ color: "var(--text-tertiary)" }}>—</span>}
    </td>
  );
}

export default function TlsSessionsPage() {
  const [sessions, setSessions] = useState<TlsSession[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [group, setGroup] = useState<GroupFilter>("all");
  const [protocol, setProtocol] = useState<string>("all");
  const [limit, setLimit] = useState(50);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSessions(await quansec.getTlsSessions(limit));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load sessions");
      setSessions(null);
    } finally {
      setLoading(false);
    }
  }, [limit]);

  useEffect(() => { load(); }, [load]);

  // Protocol values come from the data rather than a hardcoded list, so a
  // TLS 1.2 session — which should be impossible under strict-hybrid — shows
  // up as a filter option instead of being invisible.
  const protocols = useMemo(() => {
    const seen = new Set((sessions ?? []).map((s) => s.tls_protocol).filter(Boolean));
    return ["all", ...Array.from(seen).sort()] as string[];
  }, [sessions]);

  const visible = useMemo(
    () => (sessions ?? []).filter(
      (s) => (group === "all" || classify(s) === group) &&
             (protocol === "all" || s.tls_protocol === protocol)
    ),
    [sessions, group, protocol]
  );

  return (
    <div className="p-8 max-w-7xl space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
            TLS Sessions
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Connections observed in the NGINX access log, newest first
          </p>
        </div>
        <button onClick={load} disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold focus-ring disabled:opacity-50"
          style={{ background: "var(--pqc-cyan)", color: "#04231f" }}>
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} strokeWidth={2.5} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
             style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>
          <XCircle size={14} /> {error}
        </div>
      )}

      {/* ── Filters ─────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider font-mono-display"
                style={{ color: "var(--text-tertiary)" }}>Key exchange</span>
          {GROUP_FILTERS.map((g) => (
            <button key={g} onClick={() => setGroup(g)}
              className="px-2.5 py-1 rounded-lg text-[11px] font-mono-display focus-ring"
              style={{
                background: group === g ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
                color: group === g ? "var(--pqc-cyan)" : "var(--text-secondary)",
                border: `1px solid ${group === g ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
              }}>
              {g}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider font-mono-display"
                style={{ color: "var(--text-tertiary)" }}>Protocol</span>
          {protocols.map((p) => (
            <button key={p} onClick={() => setProtocol(p)}
              className="px-2.5 py-1 rounded-lg text-[11px] font-mono-display focus-ring"
              style={{
                background: protocol === p ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
                color: protocol === p ? "var(--pqc-cyan)" : "var(--text-secondary)",
                border: `1px solid ${protocol === p ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
              }}>
              {p}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 ml-auto">
          <span className="text-[10px] uppercase tracking-wider font-mono-display"
                style={{ color: "var(--text-tertiary)" }}>Limit</span>
          {[50, 100, 250].map((n) => (
            <button key={n} onClick={() => setLimit(n)}
              className="px-2.5 py-1 rounded-lg text-[11px] font-mono-display focus-ring"
              style={{
                background: limit === n ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
                color: limit === n ? "var(--pqc-cyan)" : "var(--text-secondary)",
                border: `1px solid ${limit === n ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
              }}>
              {n}
            </button>
          ))}
        </div>
      </div>

      <Panel>
        <PanelHeader
          eyebrow="Observed"
          title="Sessions"
          right={sessions && (
            <span className="text-[10px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>
              {visible.length} of {sessions.length} shown
            </span>
          )}
        />

        {/* Three distinct empty states. "Loading", "nothing recorded" and
            "filtered to nothing" are different facts and are not collapsed
            into one message. */}
        {sessions === null && !error ? (
          <p className="px-5 py-8 text-xs" style={{ color: "var(--text-tertiary)" }}>Loading…</p>
        ) : sessions && sessions.length === 0 ? (
          <p className="px-5 py-8 text-xs" style={{ color: "var(--text-tertiary)" }}>
            No session recorded yet. The collector tails the NGINX access log; a
            handshake has to happen before anything appears here.
          </p>
        ) : visible.length === 0 ? (
          <p className="px-5 py-8 text-xs" style={{ color: "var(--text-tertiary)" }}>
            No session matches these filters.
          </p>
        ) : (
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  {["Time", "Connection", "Client", "SNI", "Protocol", "Cipher",
                    "Negotiated group", "Client cert", "Status", "Evidence"].map((h) => (
                    <th key={h}
                        className="px-4 py-3 text-[10px] font-mono-display font-semibold uppercase tracking-wider whitespace-nowrap"
                        style={{ color: "var(--pqc-cyan-dim)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map((s) => (
                  <tr key={s.id} className="border-b last:border-b-0"
                      style={{ borderColor: "var(--border-hairline)" }}>
                    <Cell>{new Date(s.occurred_at).toLocaleTimeString()}</Cell>
                    <Cell>{s.connection_id}</Cell>
                    <Cell>{s.remote_addr}{s.remote_port && `:${s.remote_port}`}</Cell>
                    <Cell>{s.server_name}</Cell>
                    <Cell>
                      <span style={{
                        color: s.tls_protocol === "TLSv1.3" ? "var(--text-primary)" : "var(--danger-red)",
                      }}>{s.tls_protocol}</span>
                    </Cell>
                    <Cell>{s.cipher}</Cell>
                    <Cell><GroupBadge session={s} /></Cell>
                    {/* NONE means no client certificate was requested. That is
                        an absence of a check, not a failed one. */}
                    <Cell>
                      {s.client_verify == null || s.client_verify.toUpperCase() === "NONE" ? (
                        <span style={{ color: "var(--text-tertiary)" }}>not required</span>
                      ) : (
                        <span style={{
                          color: s.client_verify.toUpperCase() === "SUCCESS"
                            ? "var(--pqc-cyan)" : "var(--danger-red)",
                        }}>{s.client_verify}</span>
                      )}
                    </Cell>
                    <Cell>
                      {s.http_status == null ? undefined : (
                        <span style={{
                          color: s.http_status < 400 ? "var(--text-primary)" : "var(--threat-amber)",
                        }}>{s.http_status}</span>
                      )}
                    </Cell>
                    <Cell>
                      <span style={{ color: "var(--text-tertiary)" }}>
                        {s.log_source?.split("/").pop()}
                        {s.log_offset != null && `@${s.log_offset}`}
                      </span>
                    </Cell>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <p className="text-[11px] leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
        A refused handshake produces no row here. NGINX writes an access-log line
        only once a request reaches the HTTP layer, so a client rejected during
        the handshake — which is what the strict policy does to classical
        clients — is visible in the probe evidence, not in this table.
      </p>
    </div>
  );
}
