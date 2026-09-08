"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Globe } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { AuthSplitLayout, AuthField, AuthSubmit, AuthError } from "@/components/auth-split";

export default function TlsLoginPage() {
  const [email, setEmail] = useState("admin@quanseq.io");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { login, user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) router.replace("/tls-portal");
  }, [loading, user, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(email, password, "tls");
      router.push("/tls-portal");
    } catch {
      setError("Invalid credentials for the TLS portal.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthSplitLayout
      icon={Globe}
      accent="var(--pqc-cyan)"
      accentGlow="var(--pqc-cyan-glow)"
      accentDim="var(--pqc-cyan-dim)"
      title="TLS Portal"
      description="Observe a real TLS 1.3 transport service — certificate verification, mutual TLS, and an evidence-based view of how far post-quantum key exchange actually gets on this runtime."
      stats={[{ value: "1.3", label: "TLS Only" }, { value: "2030", label: "CNSA 2.0" }]}
      formTitle="TLS sign in"
      formSubtitle="Access your TLS monitoring portal"
    >
      <form onSubmit={handleSubmit}>
        <div className="space-y-4">
          <AuthField label="Email" type="email" value={email} onChange={setEmail} placeholder="you@company.com" />
          <AuthField label="Password" type="password" value={password} onChange={setPassword} placeholder="••••••••" />
        </div>
        {error && <AuthError message={error} />}
        <AuthSubmit submitting={submitting} accent="var(--pqc-cyan)" onAccent="#04231f" />
      </form>
    </AuthSplitLayout>
  );
}
