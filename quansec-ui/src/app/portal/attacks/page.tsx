"use client";

import { useState } from "react";
import { quansec } from "@/lib/api";
import { PageHeader } from "@/components/ui-primitives";
import { AttackCard, AttackOutcome } from "@/components/attack-card";
import { Atom, Clock, Key, Radio, ShieldQuestion } from "lucide-react";

const ATTACKS = [
  { id: "downgrade", label: "IKE Downgrade", icon: Radio, description: "MITM strips PQC proposal, forces classical fallback" },
  { id: "shors", label: "Shor's Algorithm", icon: Atom, description: "Quantum factoring attack on the key exchange" },
  { id: "harvest", label: "Harvest Now, Decrypt Later", icon: Clock, description: "Captured traffic decrypted retroactively by future quantum computers" },
  { id: "factoring", label: "Key Factoring", icon: Key, description: "Pollard rho factoring of a classical reference key" },
  { id: "kyber-resist", label: "Kyber Brute Force", icon: ShieldQuestion, description: "10,000 attempts against the ML-KEM-1024 lattice" },
];

export default function AttacksPage() {
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AttackOutcome>>({});

  const run = async (id: string) => {
    setRunning(id);
    try {
      const res = await quansec.runAttack(id);
      setResults((prev) => ({ ...prev, [id]: res as AttackOutcome }));
    } catch {
      setResults((prev) => ({ ...prev, [id]: { attack: id, result: "ERROR" } }));
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <PageHeader
        eyebrow="Cryptanalysis"
        title="Attack Lab"
        description="Cryptographic attack techniques evaluated against the active tunnel policy."
      />

      <div className="space-y-4">
        {ATTACKS.map((attack) => (
          <AttackCard
            key={attack.id}
            attack={attack}
            outcome={results[attack.id]}
            running={running === attack.id}
            disabled={running !== null}
            onRun={() => run(attack.id)}
          />
        ))}
      </div>
    </div>
  );
}
