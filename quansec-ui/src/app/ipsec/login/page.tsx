"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Network, ArrowRight, ArrowLeft } from "lucide-react";
import { useAuth } from "@/lib/auth-context";

export default function IpsecLoginPage() {
  const [email, setEmail] = useState("admin@quansec.io");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { login, user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) router.replace("/portal");
  }, [loading, user, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(email, password, "ipsec");
      router.push("/portal");
    } catch {
      setError("Invalid credentials for the IPsec portal.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>
      <div className="hidden lg:flex w-1/2 relative overflow-hidden items-center justify-center">
        <div className="absolute inset-0 lattice-bg-active" />
        <div className="absolute -top-32 -left-32 w-[500px] h-[500px] rounded-full blur-3xl pointer-events-none" style={{ background: "var(--pqc-cyan-glow)", opacity: 0.7 }} />
        <div className="absolute inset-0" style={{ background: "radial-gradient(ellipse 700px 700px at 50% 50%, transparent 0%, var(--bg-void) 72%)" }} />
        <div className="relative z-10 max-w-md px-12 text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-8" style={{ background: "var(--pqc-cyan-glow)", border: "1px solid var(--pqc-cyan-dim)" }}>
            <Network size={30} style={{ color: "var(--pqc-cyan)" }} strokeWidth={1.8} />
          </div>
          <h1 className="text-3xl font-extrabold mb-4 tracking-tight" style={{ color: "var(--text-primary)" }}>
            IPsec Portal
          </h1>
          <p className="text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            Manage IKEv2 tunnels secured with pure ML-KEM-1024 — NIST FIPS 203
            Level 5 post-quantum key exchange.
          </p>
          <div className="mt-10 flex items-center justify-center gap-8 font-mono-display">
            <div>
              <div className="text-3xl font-extrabold gradient-cyan-text">1024</div>
              <div className="text-[10px] font-bold uppercase tracking-widest mt-1" style={{ color: "var(--text-secondary)" }}>ML-KEM</div>
            </div>
            <div className="w-px h-10" style={{ background: "var(--border-hairline-bright)" }} />
            <div>
              <div className="text-3xl font-extrabold" style={{ color: "var(--pqc-cyan)" }}>L5</div>
              <div className="text-[10px] font-bold uppercase tracking-widest mt-1" style={{ color: "var(--text-secondary)" }}>NIST LEVEL</div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center px-6">
        <form onSubmit={handleSubmit} className="w-full max-w-sm">
          <Link href="/" className="inline-flex items-center gap-1.5 text-xs font-mono-display mb-8 focus-ring" style={{ color: "var(--text-tertiary)" }}>
            <ArrowLeft size={13} /> All portals
          </Link>

          <h2 className="text-2xl font-extrabold mb-1" style={{ color: "var(--text-primary)" }}>IPsec sign in</h2>
          <p className="text-sm mb-8" style={{ color: "var(--text-secondary)" }}>Access your IPsec integration portal</p>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-mono-display font-bold tracking-wide uppercase mb-2" style={{ color: "var(--text-secondary)" }}>Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required
                className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors focus-ring font-medium"
                style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
                placeholder="you@company.com" />
            </div>
            <div>
              <label className="block text-xs font-mono-display font-bold tracking-wide uppercase mb-2" style={{ color: "var(--text-secondary)" }}>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required
                className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors focus-ring"
                style={{ background: "var(--bg-panel-raised)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-primary)" }}
                placeholder="••••••••" />
            </div>
          </div>

          {error && (
            <div className="mt-4 px-3.5 py-2.5 rounded-lg text-xs font-mono-display font-semibold" style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>
              {error}
            </div>
          )}

          <button type="submit" disabled={submitting}
            className="w-full mt-6 flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-bold transition-opacity focus-ring disabled:opacity-50"
            style={{ background: "var(--pqc-cyan)", color: "#04201c" }}>
            {submitting ? "Signing in…" : "Sign in"}
            {!submitting && <ArrowRight size={15} strokeWidth={2.5} />}
          </button>
        </form>
      </div>
    </div>
  );
}
