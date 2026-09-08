"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Terminal } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { AuthSplitLayout, AuthField, AuthSubmit, AuthError } from "@/components/auth-split";

export default function SshLoginPage() {
  const [email, setEmail] = useState("ssh-admin@quanseq.io");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { login, user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) router.replace("/ssh-portal");
  }, [loading, user, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(email, password, "ssh");
      router.push("/ssh-portal");
    } catch {
      setError("Invalid credentials for the SSH portal.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthSplitLayout
      icon={Terminal}
      accent="var(--lattice-violet)"
      accentGlow="var(--lattice-violet-glow)"
      accentDim="var(--lattice-violet-dim)"
      title="SSH Portal"
      description="Monitor SSH sessions secured with hybrid X25519 + ML-KEM-768 — the OpenSSH post-quantum key exchange at NIST Level 3."
      stats={[{ value: "768", label: "ML-KEM" }, { value: "HYBRID", label: "+ X25519" }]}
      formTitle="SSH sign in"
      formSubtitle="Access your SSH monitoring portal"
    >
      <form onSubmit={handleSubmit}>
        <div className="space-y-4">
          <AuthField label="Email" type="email" value={email} onChange={setEmail} placeholder="you@company.com" />
          <AuthField label="Password" type="password" value={password} onChange={setPassword} placeholder="••••••••" />
        </div>
        {error && <AuthError message={error} />}
        <AuthSubmit submitting={submitting} accent="var(--lattice-violet)" onAccent="#1a0f3d" />
      </form>
    </AuthSplitLayout>
  );
}
