"use client";

import Link from "next/link";
import { ShieldHalf, Network, Terminal, Globe, ArrowRight } from "lucide-react";

export default function LandingPage() {
  return (
    <div className="min-h-screen relative overflow-hidden" style={{ background: "var(--bg-void)" }}>
      {/* Ambient background */}
      <div className="absolute inset-0 lattice-bg opacity-40" />
      <div className="absolute -top-40 left-1/4 w-[600px] h-[600px] rounded-full blur-3xl pointer-events-none" style={{ background: "var(--pqc-cyan-glow)", opacity: 0.4 }} />
      <div className="absolute -bottom-40 right-1/4 w-[500px] h-[500px] rounded-full blur-3xl pointer-events-none" style={{ background: "var(--lattice-violet-glow)", opacity: 0.35 }} />

      <div className="relative z-10 max-w-5xl mx-auto px-6 py-16">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-6" style={{ background: "var(--lattice-violet-glow)", border: "1px solid var(--lattice-violet-dim)" }}>
            <ShieldHalf size={32} style={{ color: "var(--lattice-violet)" }} strokeWidth={1.8} />
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight mb-3" style={{ color: "var(--text-primary)" }}>
            QUANSEC
          </h1>
          <p className="text-base max-w-xl mx-auto leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            Post-quantum cryptography management. Choose a protocol module to
            access its integration portal.
          </p>
        </div>

        {/* Protocol cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* IPsec — live */}
          <Link href="/ipsec/login" className="group focus-ring rounded-2xl">
            <div
              className="relative rounded-2xl border p-7 h-full transition-all group-hover:scale-[1.02] overflow-hidden"
              style={{ background: "var(--bg-panel)", borderColor: "var(--pqc-cyan-dim)" }}
            >
              <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-2xl" style={{ background: "var(--pqc-cyan-glow)" }} />
              <div className="relative">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5" style={{ background: "var(--pqc-cyan-glow)", border: "1px solid var(--pqc-cyan-dim)" }}>
                  <Network size={22} style={{ color: "var(--pqc-cyan)" }} />
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>IPsec</h2>
                  <span className="text-[9px] font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--pqc-cyan-glow)", color: "var(--pqc-cyan)" }}>LIVE</span>
                </div>
                <p className="text-xs leading-relaxed mb-5" style={{ color: "var(--text-secondary)" }}>
                  IKEv2 tunnels secured with pure ML-KEM-1024. NIST FIPS 203 Level 5.
                </p>
                <div className="flex items-center gap-1.5 text-xs font-mono-display font-bold" style={{ color: "var(--pqc-cyan)" }}>
                  Enter portal <ArrowRight size={13} strokeWidth={2.5} />
                </div>
              </div>
            </div>
          </Link>

          {/* SSH — live */}
          <Link href="/ssh/login" className="group focus-ring rounded-2xl">
            <div
              className="relative rounded-2xl border p-7 h-full transition-all group-hover:scale-[1.02] overflow-hidden"
              style={{ background: "var(--bg-panel)", borderColor: "var(--lattice-violet-dim)" }}
            >
              <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-2xl" style={{ background: "var(--lattice-violet-glow)" }} />
              <div className="relative">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5" style={{ background: "var(--lattice-violet-glow)", border: "1px solid var(--lattice-violet-dim)" }}>
                  <Terminal size={22} style={{ color: "var(--lattice-violet)" }} />
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>SSH</h2>
                  <span className="text-[9px] font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--lattice-violet-glow)", color: "var(--lattice-violet)" }}>LIVE</span>
                </div>
                <p className="text-xs leading-relaxed mb-5" style={{ color: "var(--text-secondary)" }}>
                  Hybrid X25519 + ML-KEM-768 key exchange. OpenSSH 10, NIST Level 3.
                </p>
                <div className="flex items-center gap-1.5 text-xs font-mono-display font-bold" style={{ color: "var(--lattice-violet)" }}>
                  Enter portal <ArrowRight size={13} strokeWidth={2.5} />
                </div>
              </div>
            </div>
          </Link>

          {/* TLS — live.
              The description deliberately says "TLS 1.3" and not "post-quantum".
              The transport is real; whether hybrid key exchange is available or
              was ever negotiated depends on the runtime and on verification
              evidence, and the portal reports that per-state. Promising PQC on
              the landing card would be a claim the platform cannot back. */}
          <Link href="/tls/login" className="group focus-ring rounded-2xl">
            <div
              className="relative rounded-2xl border p-7 h-full transition-all group-hover:scale-[1.02] overflow-hidden"
              style={{ background: "var(--bg-panel)", borderColor: "var(--pqc-cyan-dim)" }}
            >
              <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-2xl" style={{ background: "var(--pqc-cyan-glow)" }} />
              <div className="relative">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5" style={{ background: "var(--pqc-cyan-glow)", border: "1px solid var(--pqc-cyan-dim)" }}>
                  <Globe size={22} style={{ color: "var(--pqc-cyan)" }} />
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>TLS</h2>
                  <span className="text-[9px] font-mono-display font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--pqc-cyan-glow)", color: "var(--pqc-cyan)" }}>LIVE</span>
                </div>
                <p className="text-xs leading-relaxed mb-5" style={{ color: "var(--text-secondary)" }}>
                  Real TLS 1.3 transport with certificate verification and mTLS.
                  Hybrid X25519 + ML-KEM-768 status is reported from evidence.
                </p>
                <div className="flex items-center gap-1.5 text-xs font-mono-display font-bold" style={{ color: "var(--pqc-cyan)" }}>
                  Enter portal <ArrowRight size={13} strokeWidth={2.5} />
                </div>
              </div>
            </div>
          </Link>
        </div>

        {/* Footer note */}
        <div className="text-center mt-14">
          <p className="text-xs font-mono-display" style={{ color: "var(--text-tertiary)" }}>
            Samsung PRISM Research · NIST FIPS 203 · CNSA 2.0
          </p>
        </div>
      </div>
    </div>
  );
}
