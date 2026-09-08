"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { PortalSidebar } from "@/components/portal-sidebar";
import { Globe, LayoutGrid, FileBadge, GitCompareArrows, Network, KeyRound, Gauge } from "lucide-react";

const NAV = [
  { href: "/tls-portal", label: "Overview", icon: LayoutGrid },
  { href: "/tls-portal/keys", label: "API Keys", icon: KeyRound },
  { href: "/tls-portal/sessions", label: "TLS Sessions", icon: Network },
  { href: "/tls-portal/certificate", label: "Certificate", icon: FileBadge },
  { href: "/tls-portal/policy", label: "Policy", icon: GitCompareArrows },
  { href: "/tls-portal/readiness", label: "Readiness", icon: Gauge },
];

export default function TlsPortalLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (!loading && !user) router.replace("/tls/login");
  }, [loading, user, router]);

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg-void)" }}>
      <div className="text-sm font-mono-display animate-pulse" style={{ color: "var(--text-tertiary)" }}>AUTHENTICATING…</div>
    </div>
  );
  if (!user) return null;

  return (
    <div className="min-h-screen flex flex-col lg:flex-row" style={{ background: "var(--bg-void)" }}>
      <PortalSidebar
        moduleLabel="TLS MODULE"
        accent="var(--pqc-cyan)"
        accentGlow="var(--pqc-cyan-glow)"
        accentDim="var(--pqc-cyan-dim)"
        navItems={NAV}
        note={
          <>
            <Globe size={11} className="inline mr-1" />
            This portal observes QUANSEQ&apos;s own TLS service. Browser traffic to
            this dashboard is not part of that measurement.
          </>
        }
      />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}
