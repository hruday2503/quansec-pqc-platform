"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, XCircle } from "lucide-react";
import { quanseq, TlsDowngradeTest, TlsPolicy, TlsPolicyView } from "@/lib/api";
import { Panel, PanelHeader } from "@/components/ui-primitives";

/**
 * Intended versus running TLS policy.
 *
 * "Intended" is what the policy engine would render. "Running" is what was
 * parsed back out of the nginx.conf actually on disk, and is null when nothing
 * has been rendered yet — which is not the same as "running something else",
 * so the two cases are shown differently.
 */

const ROWS: { field: keyof TlsPolicyView; label: string }[] = [
  { field: "protocols", label: "Protocols" },
  { field: "groups", label: "Groups" },
  { field: "ciphersuites", label: "Cipher suites" },
  { field: "listen", label: "Listen" },
  { field: "mtls", label: "Mutual TLS" },
  { field: "early_data", label: "Early data (0-RTT)" },
  { field: "tls13_only", label: "TLS 1.3 only" },
  { field: "hybrid_group_only", label: "Hybrid group only" },
  { field: "fail_closed", label: "Fail closed" },
  { field: "config_sha256", label: "Config SHA-256" },
];

function Cell({ value }: { value: TlsPolicyView[keyof TlsPolicyView] | undefined }) {
  if (value === undefined || value === null) {
    return <span className="text-xs" style={{ color: "var(--text-tertiary)" }}>—</span>;
  }
  if (typeof value === "boolean") {
    return (
      <span className="font-mono-display text-xs"
            style={{ color: value ? "var(--pqc-cyan)" : "var(--threat-amber)" }}>
        {value ? "YES" : "NO"}
      </span>
    );
  }
  if (Array.isArray(value)) {
    return (
      <span className="text-xs font-mono-display" style={{ color: "var(--text-primary)" }}>
        {value.length ? value.join(", ") : "none"}
      </span>
    );
  }
  return (
    <span className="text-xs font-mono-display break-all" style={{ color: "var(--text-primary)" }}>
      {String(value)}
    </span>
  );
}

export default function TlsPolicyPage() {
  const [policy, setPolicy] = useState<TlsPolicy | null>(null);
  const [test, setTest] = useState<TlsDowngradeTest | null>(null);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setPolicy(await quanseq.getTlsPolicy());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the policy");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const runDowngradeTest = async () => {
    setTesting(true);
    setError(null);
    try {
      setTest(await quanseq.testHybridDowngrade());
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The test could not run");
    } finally {
      setTesting(false);
    }
  };

  const drift = policy?.drift;

  return (
    <div className="p-8 max-w-5xl space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
            Policy
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
            Intended versus running TLS 1.3 configuration
          </p>
        </div>
        {drift && (
          <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-mono-display font-medium"
                style={{
                  background: drift.in_sync ? "var(--pqc-cyan-glow)" : "var(--threat-amber-glow)",
                  color: drift.in_sync ? "var(--pqc-cyan)" : "var(--threat-amber)",
                  border: `1px solid ${drift.in_sync ? "var(--pqc-cyan-dim)" : "var(--threat-amber-dim)"}`,
                }}>
            {drift.in_sync ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}
            {drift.in_sync ? "IN SYNC" : "DRIFT"}
          </span>
        )}
      </div>

      {error && (
        <div className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
             style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>
          <XCircle size={14} /> {error}
        </div>
      )}

      {/* The fail-closed state is stated before the table, so nobody reads the
          table as a description of what is currently guaranteed. */}
      {policy && !policy.fail_closed && (
        <div className="px-4 py-3.5 rounded-lg text-xs leading-relaxed flex gap-3"
             style={{ background: "var(--threat-amber-glow)", color: "var(--threat-amber)", border: "1px solid var(--threat-amber-dim)" }}>
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div>
            <div className="font-bold mb-1 font-mono-display">POLICY IS NOT FAIL-CLOSED</div>
            <p>
              Fallback groups are configured alongside the hybrid group, so a
              client offering only classical groups can still complete a
              handshake. Hybrid is available, not required.
            </p>
          </div>
        </div>
      )}

      {drift && !drift.in_sync && (
        <div className="px-4 py-3.5 rounded-lg text-xs leading-relaxed"
             style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)", border: "1px solid var(--border-hairline)" }}>
          <div className="font-bold mb-1 font-mono-display" style={{ color: "var(--threat-amber)" }}>
            {drift.reason}
          </div>
          <p>{drift.detail}</p>
          {drift.differences.length > 0 && (
            <ul className="mt-2 space-y-1 font-mono-display text-[11px]">
              {drift.differences.map((d) => (
                <li key={d.field}>
                  <span style={{ color: "var(--text-primary)" }}>{d.field}</span>: intended{" "}
                  <span style={{ color: "var(--pqc-cyan)" }}>{String(d.intended)}</span> · running{" "}
                  <span style={{ color: "var(--threat-amber)" }}>{String(d.running)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {policy && (
        <Panel>
          <PanelHeader
            eyebrow="Comparison"
            title="Intended versus running"
            right={
              <span className="text-[10px] font-mono-display" style={{ color: "var(--text-tertiary)" }}>
                {policy.running ? `source: ${policy.running.source}` : "no nginx.conf rendered"}
              </span>
            }
          />
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Scrollable table">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b" style={{ borderColor: "var(--border-hairline)" }}>
                  {["", "Intended", "Running"].map((h) => (
                    <th key={h} className="px-5 py-3 text-[10px] font-mono-display font-semibold uppercase tracking-wider"
                        style={{ color: "var(--pqc-cyan-dim)" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ROWS.map((row) => (
                  <tr key={row.field} className="border-b last:border-b-0 align-top"
                      style={{ borderColor: "var(--border-hairline)" }}>
                    <td className="px-5 py-3 text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
                      {row.label}
                    </td>
                    <td className="px-5 py-3"><Cell value={policy.intended[row.field]} /></td>
                    <td className="px-5 py-3"><Cell value={policy.running?.[row.field]} /></td>
                  </tr>
                ))}
                {/* Fallback groups are the reason a policy is or is not
                    fail-closed, so they are shown rather than summarised away. */}
                <tr className="align-top">
                  <td className="px-5 py-3 text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
                    Fallback groups
                  </td>
                  <td className="px-5 py-3"><Cell value={policy.intended.fallback_groups} /></td>
                  <td className="px-5 py-3"><Cell value={policy.running?.fallback_groups} /></td>
                </tr>
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* ── Fail-closed proof ───────────────────────────────────────────── */}
      <Panel>
        <PanelHeader
          eyebrow="Evidence"
          title="Prove classical clients are refused"
          right={
            <button onClick={runDowngradeTest} disabled={testing}
              className="px-3.5 py-2 rounded-lg text-xs font-bold focus-ring disabled:opacity-50"
              style={{ background: "var(--pqc-cyan)", color: "#04231f" }}>
              {testing ? "Testing…" : "Run downgrade test"}
            </button>
          }
        />
        <div className="px-5 py-4 space-y-3">
          <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            Configuration alone cannot show that hybrid is required. This test
            points the runtime OpenSSL client at the data plane twice — once
            offering only X25519, once only prime256v1 — and records what
            happened. The policy is proven fail-closed only when{" "}
            <em>both</em> handshakes are refused; anything less means a classical
            client can still connect.
          </p>

          {test && (
            <div className="px-3.5 py-3 rounded-lg text-xs space-y-2"
                 style={{
                   background: test.rejected ? "var(--pqc-cyan-glow)" : "var(--danger-glow)",
                   border: `1px solid ${test.rejected ? "var(--pqc-cyan-dim)" : "#7a1f33"}`,
                 }}>
              <div className="flex items-center gap-2 font-mono-display font-bold"
                   style={{ color: test.rejected ? "var(--pqc-cyan)" : "var(--danger-red)" }}>
                {test.rejected ? <ShieldCheck size={14} /> : <AlertTriangle size={14} />}
                {test.rejected ? "CLASSICAL CLIENTS REFUSED" : "CLASSICAL CLIENT CONNECTED"}
              </div>
              <div style={{ color: "var(--text-secondary)" }}>{test.verdict}</div>

              {test.results.map((r) => (
                <div key={r.probe_type} className="font-mono-display text-[11px] break-all"
                     style={{ color: "var(--text-tertiary)" }}>
                  <span style={{ color: r.passed ? "var(--pqc-cyan)" : "var(--danger-red)" }}>
                    {r.passed ? "PASS" : "FAIL"}
                  </span>{" "}
                  {r.probe_type} · expected {r.expected_outcome}, got {r.actual_outcome}
                  {r.negotiated_group && ` · group ${r.negotiated_group}`}
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
