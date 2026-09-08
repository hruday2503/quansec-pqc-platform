"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { PortalSidebar } from "@/components/portal-sidebar";
import { Terminal, FilePlus, SlidersHorizontal, Bell, Gauge, ShieldCheck, LayoutGrid, GitCompareArrows, KeyRound, BookOpen } from "lucide-react";

const NAV = [
  { href: "/ssh-portal", label: "Overview", icon: LayoutGrid },
  { href: "/ssh-portal/keys", label: "API Keys", icon: KeyRound },
  { href: "/ssh-portal/sessions", label: "Sessions", icon: Terminal },
  { href: "/ssh-portal/docs", label: "Integration", icon: BookOpen },
  { href: "/ssh-portal/policy", label: "Policy", icon: GitCompareArrows },
  { href: "/ssh-portal/zero-trust", label: "Zero Trust", icon: ShieldCheck },
  { href: "/ssh-portal/certificates", label: "Issue Cert", icon: FilePlus },
  { href: "/ssh-portal/readiness", label: "Readiness", icon: Gauge },
  { href: "/ssh-portal/alerts", label: "Alerts", icon: Bell },
  { href: "/ssh-portal/integrations", label: "Integrations", icon: SlidersHorizontal },
];

export default function SshPortalLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (!loading && !user) router.replace("/ssh/login");
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
        moduleLabel="SSH MODULE"
        accent="var(--lattice-violet)"
        accentGlow="var(--lattice-violet-glow)"
        accentDim="var(--lattice-violet-dim)"
        navItems={NAV}
      />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}
