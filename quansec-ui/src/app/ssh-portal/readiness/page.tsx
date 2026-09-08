"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/ui-primitives";
import { ReadinessCard, OverallReadinessCard, ReadinessScore, OverallReadiness } from "@/components/readiness-gauge";
import { authHeaders } from "@/lib/auth-fetch";
import { mockFetch } from "@/lib/mock/fetch";

const PROTOCOL = "ssh";
const ACCENT = "var(--lattice-violet)";

export default function SshReadinessScorePage() {
  const [score, setScore] = useState<ReadinessScore | null>(null);
  const [overall, setOverall] = useState<OverallReadiness | null>(null);

  const load = async () => {
    try {
      const [s, o] = await Promise.all([
        mockFetch(`/api/scoring/${PROTOCOL}`, { headers: authHeaders() }).then((r) => r.json()),
        mockFetch(`/api/scoring/overall`, { headers: authHeaders() }).then((r) => r.json()),
      ]);
      setScore(s); setOverall(o);
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <PageHeader
        eyebrow="Compliance"
        title="PQC readiness score"
        description="Weighted assessment of post-quantum migration readiness."
        accent={ACCENT}
      />
      <ReadinessCard protocolLabel={PROTOCOL} accent={ACCENT} score={score} />
      <OverallReadinessCard accent={ACCENT} overall={overall} />
    </div>
  );
}
