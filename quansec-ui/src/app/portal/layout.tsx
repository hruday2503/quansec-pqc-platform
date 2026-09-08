"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { Sidebar } from "@/components/sidebar";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/ipsec/login");
    }
  }, [loading, user, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg-void)" }}>
        <div className="text-sm font-mono-display animate-pulse" style={{ color: "var(--text-tertiary)" }}>
          AUTHENTICATING…
        </div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="min-h-screen flex flex-col lg:flex-row" style={{ background: "var(--bg-void)" }}>
      <Sidebar />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}
