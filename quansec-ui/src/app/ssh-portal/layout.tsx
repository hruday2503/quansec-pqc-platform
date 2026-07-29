"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { Terminal, FilePlus, SlidersHorizontal, Bell, Gauge, ShieldCheck, LogOut, ShieldHalf, LayoutGrid, GitCompareArrows, KeyRound, BookOpen } from "lucide-react";

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

function SshSidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  return (
    <aside className="w-60 shrink-0 h-screen sticky top-0 flex flex-col border-r" style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}>
      <div className="px-5 py-5 flex items-center gap-3 border-b" style={{ borderColor: "var(--border-hairline-bright)" }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: "var(--lattice-violet-glow)", border: "1px solid var(--lattice-violet-dim)" }}>
          <ShieldHalf size={18} style={{ color: "var(--lattice-violet)" }} strokeWidth={2} />
        </div>
        <div>
          <div className="text-sm font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>QUANSEC</div>
          <div className="text-[10px] font-mono-display font-semibold tracking-wider" style={{ color: "var(--text-tertiary)" }}>SSH MODULE</div>
        </div>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map((item) => {
          const active = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link key={item.href} href={item.href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all focus-ring"
              style={{ background: active ? "var(--bg-panel-hover)" : "transparent", color: active ? "var(--lattice-violet)" : "var(--text-secondary)", fontWeight: active ? 600 : 500 }}>
              <Icon size={16} strokeWidth={active ? 2.5 : 2} />
              <span>{item.label}</span>
              {active && <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: "var(--lattice-violet)" }} />}
            </Link>
          );
        })}
      </nav>
      <div className="px-3 py-4 border-t" style={{ borderColor: "var(--border-hairline-bright)" }}>
        <div className="px-3 py-2 mb-1">
          <div className="text-xs font-semibold truncate" style={{ color: "var(--text-primary)" }}>{user?.email}</div>
          <div className="text-[10px] font-mono-display font-bold uppercase tracking-wider mt-0.5" style={{ color: "var(--lattice-violet)" }}>{user?.role}</div>
        </div>
        <button onClick={logout} className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium focus-ring" style={{ color: "var(--text-tertiary)" }}>
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </aside>
  );
}

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
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>
      <SshSidebar />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}
