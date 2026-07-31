"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { Globe, LayoutGrid, FileBadge, LogOut, ShieldHalf, GitCompareArrows, Network } from "lucide-react";

const NAV = [
  { href: "/tls-portal", label: "Overview", icon: LayoutGrid },
  { href: "/tls-portal/sessions", label: "TLS Sessions", icon: Network },
  { href: "/tls-portal/certificate", label: "Certificate", icon: FileBadge },
  { href: "/tls-portal/policy", label: "Policy", icon: GitCompareArrows },
];

function TlsSidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  return (
    <aside className="w-60 shrink-0 h-screen sticky top-0 flex flex-col border-r" style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}>
      <div className="px-5 py-5 flex items-center gap-3 border-b" style={{ borderColor: "var(--border-hairline-bright)" }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: "var(--pqc-cyan-glow)", border: "1px solid var(--pqc-cyan-dim)" }}>
          <ShieldHalf size={18} style={{ color: "var(--pqc-cyan)" }} strokeWidth={2} />
        </div>
        <div>
          <div className="text-sm font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>QUANSEC</div>
          <div className="text-[10px] font-mono-display font-semibold tracking-wider" style={{ color: "var(--text-tertiary)" }}>TLS MODULE</div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map((item) => {
          const active = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link key={item.href} href={item.href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all focus-ring"
              style={{ background: active ? "var(--bg-panel-hover)" : "transparent", color: active ? "var(--pqc-cyan)" : "var(--text-secondary)", fontWeight: active ? 600 : 500 }}>
              <Icon size={16} strokeWidth={active ? 2.5 : 2} />
              <span>{item.label}</span>
              {active && <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: "var(--pqc-cyan)" }} />}
            </Link>
          );
        })}
      </nav>

      <div className="px-3 pb-2">
        <div className="px-3 py-2.5 rounded-lg text-[10px] leading-relaxed font-mono-display"
             style={{ background: "var(--bg-panel-raised)", color: "var(--text-tertiary)", border: "1px solid var(--border-hairline)" }}>
          <Globe size={11} className="inline mr-1" />
          This portal observes QUANSEC&apos;s own TLS service. Browser traffic to
          this dashboard is not part of that measurement.
        </div>
      </div>

      <div className="px-3 py-4 border-t" style={{ borderColor: "var(--border-hairline-bright)" }}>
        <div className="px-3 py-2 mb-1">
          <div className="text-xs font-semibold truncate" style={{ color: "var(--text-primary)" }}>{user?.email}</div>
          <div className="text-[10px] font-mono-display font-bold uppercase tracking-wider mt-0.5" style={{ color: "var(--pqc-cyan)" }}>{user?.role}</div>
        </div>
        <button onClick={logout} className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium focus-ring" style={{ color: "var(--text-tertiary)" }}>
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </aside>
  );
}

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
    <div className="min-h-screen flex" style={{ background: "var(--bg-void)" }}>
      <TlsSidebar />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}
