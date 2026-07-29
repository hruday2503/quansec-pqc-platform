"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutGrid, Network, GitCompareArrows, Swords, BookOpen, LogOut, ShieldHalf, KeyRound, Gauge, Bell, SlidersHorizontal } from "lucide-react";
import { useAuth } from "@/lib/auth-context";

const NAV_ITEMS = [
  { href: "/portal", label: "Overview", icon: LayoutGrid },
  { href: "/portal/keys", label: "API Keys", icon: KeyRound },
  { href: "/portal/tunnels", label: "Tunnels", icon: Network },
  { href: "/portal/docs", label: "Integration", icon: BookOpen },
  { href: "/portal/policy", label: "Policy", icon: GitCompareArrows },
  { href: "/portal/readiness", label: "Readiness", icon: Gauge },
  { href: "/portal/alerts", label: "Alerts", icon: Bell },
  { href: "/portal/integrations", label: "Integrations", icon: SlidersHorizontal },
  { href: "/portal/attacks", label: "Attack Lab", icon: Swords },
];

export function Sidebar() {
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
          <div className="text-[10px] font-mono-display font-semibold tracking-wider" style={{ color: "var(--text-tertiary)" }}>IPSEC MODULE</div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV_ITEMS.map((item) => {
          const active = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all focus-ring"
              style={{
                background: active ? "var(--bg-panel-hover)" : "transparent",
                color: active ? "var(--pqc-cyan)" : "var(--text-secondary)",
                fontWeight: active ? 600 : 500,
              }}
            >
              <Icon size={16} strokeWidth={active ? 2.5 : 2} />
              <span>{item.label}</span>
              {active && <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: "var(--pqc-cyan)" }} />}
            </Link>
          );
        })}
      </nav>

      <div className="px-3 py-4 border-t" style={{ borderColor: "var(--border-hairline-bright)" }}>
        <div className="px-3 py-2 mb-1">
          <div className="text-xs font-semibold truncate" style={{ color: "var(--text-primary)" }}>{user?.email}</div>
          <div className="text-[10px] font-mono-display font-bold uppercase tracking-wider mt-0.5" style={{ color: user?.role === "admin" ? "var(--lattice-violet)" : "var(--text-tertiary)" }}>
            {user?.role}
          </div>
        </div>
        <button onClick={logout} className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors focus-ring" style={{ color: "var(--text-tertiary)" }}>
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
