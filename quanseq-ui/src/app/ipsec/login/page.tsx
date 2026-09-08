"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Network } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { AuthSplitLayout, AuthField, AuthSubmit, AuthError } from "@/components/auth-split";

export default function IpsecLoginPage() {
  const [email, setEmail] = useState("admin@quanseq.io");
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
    <AuthSplitLayout
      icon={Network}
      accent="var(--pqc-cyan)"
      accentGlow="var(--pqc-cyan-glow)"
      accentDim="var(--pqc-cyan-dim)"
      title="IPsec Portal"
      description="Manage IKEv2 tunnels secured with pure ML-KEM-1024 — NIST FIPS 203 Level 5 post-quantum key exchange."
      stats={[{ value: "1024", label: "ML-KEM" }, { value: "L5", label: "NIST Level" }]}
      formTitle="IPsec sign in"
      formSubtitle="Access your IPsec integration portal"
    >
      <form onSubmit={handleSubmit}>
        <div className="space-y-4">
          <AuthField label="Email" type="email" value={email} onChange={setEmail} placeholder="you@company.com" />
          <AuthField label="Password" type="password" value={password} onChange={setPassword} placeholder="••••••••" />
        </div>
        {error && <AuthError message={error} />}
        <AuthSubmit submitting={submitting} accent="var(--pqc-cyan)" onAccent="#04201c" />
      </form>
    </AuthSplitLayout>
  );
}
