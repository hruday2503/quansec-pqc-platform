"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Panel, PanelHeader } from "@/components/ui-primitives";

const SNIPPETS = {
  curl: {
    label: "cURL",
    code: `# Check your SSH sessions' quantum-safe status
curl https://api.quansec.io/api/ssh/stats \\
  -H "Authorization: Bearer $QUANSEC_API_KEY"

# List active SSH connections and their KEX
curl https://api.quansec.io/api/ssh/connections \\
  -H "Authorization: Bearer $QUANSEC_API_KEY"`,
  },
  connect: {
    label: "Connect (PQC SSH)",
    code: `# Connect to a QUANSEC-protected host using hybrid ML-KEM-768
ssh -p 2222 user@your-host

# Force the PQC hybrid KEX explicitly
ssh -o KexAlgorithms=mlkem768x25519-sha256 \\
    -p 2222 user@your-host

# Verify the negotiated algorithm
ssh -vv -p 2222 user@your-host exit 2>&1 \\
  | grep "kex: algorithm"
# -> kex: algorithm: mlkem768x25519-sha256`,
  },
  python: {
    label: "Python",
    code: `import os, requests

KEY = os.environ["QUANSEC_API_KEY"]
BASE = "https://api.quansec.io"

def ssh_coverage():
    r = requests.get(f"{BASE}/api/ssh/stats",
        headers={"Authorization": f"Bearer {KEY}"})
    return r.json()

print(f"SSH PQC coverage: {ssh_coverage()['pqc_coverage']}%")`,
  },
  config: {
    label: "sshd_config",
    code: `# Require hybrid ML-KEM-768 on your SSH server
# (OpenSSH 9.9+ required)

KexAlgorithms mlkem768x25519-sha256
LogLevel VERBOSE

# Classical clients are refused — downgrade-proof.
# Reload: sudo systemctl restart ssh`,
  },
};

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="rounded-lg px-4 py-4 text-xs font-mono-display overflow-x-auto leading-relaxed"
        style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)", border: "1px solid var(--border-hairline)" }}>
        {code}
      </pre>
      <button onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-mono-display focus-ring"
        style={{ background: "var(--bg-panel)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-tertiary)" }}>
        {copied ? <Check size={11} style={{ color: "var(--lattice-violet)" }} /> : <Copy size={11} />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export default function SshDocsPage() {
  const [active, setActive] = useState<keyof typeof SNIPPETS>("curl");
  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display font-semibold tracking-[0.18em] uppercase mb-1.5" style={{ color: "var(--lattice-violet-dim)" }}>
          Developer Reference
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>SSH Integration Guide</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Connect and monitor SSH sessions secured with hybrid X25519 + ML-KEM-768.
        </p>
      </div>

      <Panel className="mb-6">
        <PanelHeader eyebrow="Reference" title="Code Examples" />
        <div className="px-5 pt-4 pb-5">
          <div className="flex gap-1.5 mb-4 flex-wrap">
            {(Object.keys(SNIPPETS) as Array<keyof typeof SNIPPETS>).map((k) => (
              <button key={k} onClick={() => setActive(k)}
                className="px-3 py-1.5 rounded-md text-xs font-mono-display font-medium focus-ring"
                style={{ background: active === k ? "var(--lattice-violet-glow)" : "var(--bg-panel-raised)", color: active === k ? "var(--lattice-violet)" : "var(--text-tertiary)", border: `1px solid ${active === k ? "var(--lattice-violet-dim)" : "var(--border-hairline)"}` }}>
                {SNIPPETS[k].label}
              </button>
            ))}
          </div>
          <CodeBlock code={SNIPPETS[active].code} />
        </div>
      </Panel>

      <Panel>
        <PanelHeader eyebrow="Endpoints" title="SSH API" />
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono-display">
            <tbody>
              {[
                ["GET", "/api/ssh/stats", "PQC coverage and session counts"],
                ["GET", "/api/ssh/connections", "Active SSH sessions with KEX"],
                ["GET", "/api/ssh/policies/compare", "Classical vs hybrid comparison"],
                ["POST", "/api/ssh/policies/apply", "Switch server KEX policy"],
                ["POST", "/api/ssh/attacks/{name}", "Run an attack technique"],
              ].map(([m, path, desc]) => (
                <tr key={path} className="border-t" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-5 py-3 w-16">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                      style={{ background: m === "GET" ? "var(--lattice-violet-glow)" : "var(--pqc-cyan-glow)", color: m === "GET" ? "var(--lattice-violet)" : "var(--pqc-cyan)" }}>{m}</span>
                  </td>
                  <td className="px-2 py-3" style={{ color: "var(--text-primary)" }}>{path}</td>
                  <td className="px-5 py-3 text-right" style={{ color: "var(--text-secondary)" }}>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
