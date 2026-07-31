"use client";

import { ShieldAlert, ShieldCheck, ShieldHalf, ShieldQuestion, ShieldX } from "lucide-react";
import type { TlsStatus } from "@/lib/api";

/**
 * Renders TLS post-quantum status from the backend's `overall_status`.
 *
 * Deliberately NOT the shared PqcBadge from ui-primitives: that component takes
 * a boolean and prints "QUANTUM-SAFE", which is the exact claim this module must
 * not make. Whether a TLS handshake was post-quantum is not a boolean the
 * frontend can derive — it depends on runtime capability, on the group actually
 * appearing in an NGINX log line, and on classical clients having been refused.
 *
 * `overall_status` already encodes that ladder, so the badge renders it rather
 * than recomputing it in the browser. The enforcement qualifier is always shown
 * alongside, and reads ENFORCED only when `hybrid_only_enforced` is true — the
 * one field backed by refused handshakes.
 */

const STATE = {
  unavailable: {
    text: "HYBRID UNAVAILABLE",
    color: "var(--text-tertiary)",
    glow: "var(--bg-panel-raised)",
    border: "var(--border-hairline)",
    Icon: ShieldX,
  },
  classical: {
    text: "CLASSICAL",
    color: "var(--danger-red)",
    glow: "var(--danger-glow)",
    border: "#7a1f33",
    Icon: ShieldAlert,
  },
  configured_unproven: {
    text: "HYBRID CONFIGURED",
    color: "var(--threat-amber)",
    glow: "var(--threat-amber-glow)",
    border: "var(--threat-amber-dim)",
    Icon: ShieldQuestion,
  },
  hybrid_observed: {
    text: "HYBRID OBSERVED",
    color: "var(--threat-amber)",
    glow: "var(--threat-amber-glow)",
    border: "var(--threat-amber-dim)",
    Icon: ShieldHalf,
  },
  hybrid_enforced: {
    text: "HYBRID ENFORCED",
    color: "var(--pqc-cyan)",
    glow: "var(--pqc-cyan-glow)",
    border: "var(--pqc-cyan-dim)",
    Icon: ShieldCheck,
  },
  degraded: {
    text: "DEGRADED",
    color: "var(--danger-red)",
    glow: "var(--danger-glow)",
    border: "#7a1f33",
    Icon: ShieldAlert,
  },
} as const;

export function HybridBadge({
  status,
  size = "md",
}: {
  status: TlsStatus | null | undefined;
  size?: "sm" | "md";
}) {
  const padding = size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs";

  if (!status) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 rounded-full font-mono-display font-medium ${padding}`}
        style={{
          background: "var(--bg-panel-raised)",
          color: "var(--text-tertiary)",
          border: "1px solid var(--border-hairline)",
        }}
      >
        <ShieldQuestion size={size === "sm" ? 11 : 13} strokeWidth={2.5} />
        STATUS UNKNOWN
      </span>
    );
  }

  const state = STATE[status.overall_status] ?? STATE.unavailable;
  const { Icon } = state;
  const enforced = status.hybrid_only_enforced;

  return (
    <span className="inline-flex items-center gap-2 flex-wrap">
      <span
        className={`inline-flex items-center gap-1.5 rounded-full font-mono-display font-medium ${padding}`}
        style={{
          background: state.glow,
          color: state.color,
          border: `1px solid ${state.border}`,
        }}
        title={status.label}
      >
        <Icon size={size === "sm" ? 11 : 13} strokeWidth={2.5} />
        {state.text}
      </span>

      {/* Always shown. Without both classical probes refused, a classical-only
          client can still complete a handshake, however good the badge looks. */}
      <span
        className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-mono-display font-medium"
        style={{
          background: enforced ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
          color: enforced ? "var(--pqc-cyan)" : "var(--text-tertiary)",
          border: `1px solid ${enforced ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
        }}
        title={
          enforced
            ? "X25519-only and prime256v1-only clients were both refused"
            : "No probe has shown a classical-only client being refused"
        }
      >
        {enforced ? "ENFORCED" : "NOT ENFORCED"}
      </span>
    </span>
  );
}

/**
 * The full explanation, for panels that have room for it. Uses the server's
 * `label` verbatim rather than composing a sentence in the browser, so there is
 * one source of truth for the wording.
 */
export function HybridExplanation({ status }: { status: TlsStatus | null | undefined }) {
  if (!status) return null;

  const { evidence, build } = status;

  return (
    <div className="space-y-2.5 text-xs" style={{ color: "var(--text-secondary)" }}>
      <p style={{ color: "var(--text-primary)" }}>{status.label}</p>

      <p>
        The running config asks NGINX for{" "}
        <code className="font-mono-display" style={{ color: "var(--pqc-cyan)" }}>
          {evidence.configured_groups}
        </code>
        . That is an intention. It becomes evidence only when a log line records
        the group as negotiated, and a guarantee only when classical clients are
        refused.
      </p>

      {!status.runtime_supported && (
        <p>
          The runtime OpenSSL does not list the hybrid group. NGINX here is
          linked against{" "}
          <span className="font-mono-display">{build.nginx_openssl ?? "an unknown OpenSSL"}</span>
          , and the group needs 3.5+, so no post-quantum key exchange is possible
          on this data plane at all.
        </p>
      )}

      {status.runtime_supported && !status.hybrid_group_negotiated && (
        <p>
          The group is available in this runtime, but no NGINX log line has
          recorded it as negotiated yet. Run the probe suite to produce one.
        </p>
      )}

      {status.hybrid_group_negotiated && !status.hybrid_only_enforced && (
        <p>
          {evidence.observed_hybrid_sessions} session
          {evidence.observed_hybrid_sessions === 1 ? " has" : "s have"} negotiated
          the hybrid group. Enforcement is a separate question: until an
          X25519-only and a prime256v1-only client have both been refused, a
          classical client may still connect.
        </p>
      )}

      {/* Reported separately on purpose: hybrid key exchange protects the
          session key, it does not change how the certificate is signed. */}
      <p>
        Certificate authentication is{" "}
        <span
          style={{
            color: status.authentication_quantum_safe
              ? "var(--pqc-cyan)"
              : "var(--threat-amber)",
          }}
        >
          {status.authentication_quantum_safe ? "post-quantum" : "classical"}
        </span>
        . Key establishment and signature algorithm are independent — a hybrid
        exchange with an RSA or ECDSA certificate is still classically
        authenticated.
      </p>
    </div>
  );
}
