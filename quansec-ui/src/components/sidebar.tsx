"use client";

import { LayoutGrid, Network, GitCompareArrows, Swords, BookOpen, KeyRound, Gauge, Bell, SlidersHorizontal } from "lucide-react";
import { PortalSidebar } from "@/components/portal-sidebar";

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
  return (
    <PortalSidebar
      moduleLabel="IPSEC MODULE"
      accent="var(--pqc-cyan)"
      accentGlow="var(--pqc-cyan-glow)"
      accentDim="var(--pqc-cyan-dim)"
      navItems={NAV_ITEMS}
    />
  );
}
