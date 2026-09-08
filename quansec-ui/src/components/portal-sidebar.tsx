"use client";

import { ReactNode, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LogOut, Menu, ShieldHalf, X, LucideIcon } from "lucide-react";
import { useAuth } from "@/lib/auth-context";

export interface PortalNavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

function NavLinks({
  navItems,
  pathname,
  accent,
  onNavigate,
}: {
  navItems: PortalNavItem[];
  pathname: string;
  accent: string;
  onNavigate?: () => void;
}) {
  return (
    <>
      {navItems.map((item) => {
        const active = pathname === item.href;
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            onClick={onNavigate}
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all focus-ring"
            style={{
              background: active ? "var(--bg-panel-hover)" : "transparent",
              color: active ? accent : "var(--text-secondary)",
              fontWeight: active ? 600 : 500,
            }}
          >
            <Icon size={16} strokeWidth={active ? 2.5 : 2} />
            <span>{item.label}</span>
            {active && <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: accent }} />}
          </Link>
        );
      })}
    </>
  );
}

function Brand({ moduleLabel, accent, accentGlow, accentDim }: { moduleLabel: string; accent: string; accentGlow: string; accentDim: string }) {
  return (
    <div className="px-5 py-5 flex items-center gap-3 border-b" style={{ borderColor: "var(--border-hairline-bright)" }}>
      <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: accentGlow, border: `1px solid ${accentDim}` }}>
        <ShieldHalf size={18} style={{ color: accent }} strokeWidth={2} />
      </div>
      <div>
        <div className="text-sm font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>QUANSEC</div>
        <div className="text-[10px] font-mono-display font-semibold tracking-wider" style={{ color: "var(--text-tertiary)" }}>{moduleLabel}</div>
      </div>
    </div>
  );
}

function AccountFooter({ accent, logout }: { accent: string; logout: () => void }) {
  const { user } = useAuth();
  return (
    <div className="px-3 py-4 border-t" style={{ borderColor: "var(--border-hairline-bright)" }}>
      <div className="px-3 py-2 mb-1">
        <div className="text-xs font-semibold truncate" style={{ color: "var(--text-primary)" }}>{user?.email}</div>
        <div className="text-[10px] font-mono-display font-bold uppercase tracking-wider mt-0.5" style={{ color: accent }}>
          {user?.role}
        </div>
      </div>
      <button
        onClick={logout}
        className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors focus-ring"
        style={{ color: "var(--text-tertiary)" }}
      >
        <LogOut size={14} />
        Sign out
      </button>
    </div>
  );
}

/**
 * The one navigation shell for all three portals. Module identity (name,
 * accent color, nav items) is the only thing that varies — icon size,
 * spacing, active-state treatment and the sign-out control stay identical
 * so switching modules never feels like switching products.
 *
 * Below `lg` the full sidebar would leave no room for content, so it
 * collapses to a top bar with a menu button that opens the same navigation
 * as a slide-in drawer.
 */
export function PortalSidebar({
  moduleLabel,
  accent,
  accentGlow,
  accentDim,
  navItems,
  note,
}: {
  moduleLabel: string;
  accent: string;
  accentGlow: string;
  accentDim: string;
  navItems: PortalNavItem[];
  note?: ReactNode;
}) {
  const pathname = usePathname();
  const { logout } = useAuth();
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Close the drawer whenever the route changes.
  useEffect(() => {
    setDrawerOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setDrawerOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  return (
    <>
      {/* Desktop sidebar — lg and up */}
      <aside
        className="hidden lg:flex w-60 shrink-0 h-screen sticky top-0 flex-col border-r"
        style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}
      >
        <Brand moduleLabel={moduleLabel} accent={accent} accentGlow={accentGlow} accentDim={accentDim} />
        <nav className="flex-1 px-3 py-4 space-y-0.5" aria-label={`${moduleLabel} navigation`}>
          <NavLinks navItems={navItems} pathname={pathname} accent={accent} />
        </nav>
        {note && (
          <div className="px-3 pb-2">
            <div
              className="px-3 py-2.5 rounded-lg text-[10px] leading-relaxed font-mono-display"
              style={{ background: "var(--bg-panel-raised)", color: "var(--text-tertiary)", border: "1px solid var(--border-hairline)" }}
            >
              {note}
            </div>
          </div>
        )}
        <AccountFooter accent={accent} logout={logout} />
      </aside>

      {/* Mobile / tablet top bar — below lg */}
      <header
        className="lg:hidden sticky top-0 z-30 flex items-center justify-between px-4 py-3 border-b"
        style={{ background: "var(--bg-panel)", borderColor: "var(--border-hairline-bright)" }}
      >
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: accentGlow, border: `1px solid ${accentDim}` }}>
            <ShieldHalf size={16} style={{ color: accent }} strokeWidth={2} />
          </div>
          <div>
            <div className="text-xs font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>QUANSEC</div>
            <div className="text-[9px] font-mono-display font-semibold tracking-wider" style={{ color: "var(--text-tertiary)" }}>{moduleLabel}</div>
          </div>
        </div>
        <button
          onClick={() => setDrawerOpen(true)}
          aria-label="Open navigation menu"
          aria-expanded={drawerOpen}
          className="p-2 rounded-lg focus-ring"
          style={{ color: "var(--text-secondary)" }}
        >
          <Menu size={20} />
        </button>
      </header>

      {/* Mobile drawer */}
      {drawerOpen && (
        <div className="lg:hidden fixed inset-0 z-40 flex">
          <div
            className="absolute inset-0"
            style={{ background: "rgba(0,0,0,0.6)" }}
            onClick={() => setDrawerOpen(false)}
            aria-hidden="true"
          />
          <aside
            className="relative z-50 w-72 max-w-[85vw] h-full flex flex-col"
            style={{ background: "var(--bg-panel)", borderRight: "1px solid var(--border-hairline-bright)" }}
            role="dialog"
            aria-modal="true"
            aria-label={`${moduleLabel} navigation`}
          >
            <div className="flex items-center justify-between border-b" style={{ borderColor: "var(--border-hairline-bright)" }}>
              <div className="flex-1"><Brand moduleLabel={moduleLabel} accent={accent} accentGlow={accentGlow} accentDim={accentDim} /></div>
              <button
                onClick={() => setDrawerOpen(false)}
                aria-label="Close navigation menu"
                className="p-2 mr-3 rounded-lg focus-ring shrink-0"
                style={{ color: "var(--text-tertiary)" }}
              >
                <X size={18} />
              </button>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto" aria-label={`${moduleLabel} navigation`}>
              <NavLinks navItems={navItems} pathname={pathname} accent={accent} onNavigate={() => setDrawerOpen(false)} />
            </nav>
            <AccountFooter accent={accent} logout={logout} />
          </aside>
        </div>
      )}
    </>
  );
}
