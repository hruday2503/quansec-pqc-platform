"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Panel, PanelHeader } from "@/components/ui-primitives";

const SNIPPETS = {
  curl: {
    label: "cURL",
    code: `# Check your tunnel's quantum-safe status
curl https://api.quansec.io/api/ipsec/stats \\
  -H "Authorization: Bearer $QUANSEC_API_KEY"

# Apply post-quantum policy to your tunnel
curl -X POST https://api.quansec.io/api/ipsec/policies/apply \\
  -H "Authorization: Bearer $QUANSEC_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"policy_name": "pqc-level5"}'`,
  },
  node: {
    label: "Node.js",
    code: `const QUANSEC_API_KEY = process.env.QUANSEC_API_KEY;
const BASE_URL = "https://api.quansec.io";

async function getTunnelStatus() {
  const res = await fetch(\`\${BASE_URL}/api/ipsec/stats\`, {
    headers: { Authorization: \`Bearer \${QUANSEC_API_KEY}\` },
  });
  return res.json();
}

const status = await getTunnelStatus();
console.log(\`PQC coverage: \${status.pqc_coverage}%\`);`,
  },
  python: {
    label: "Python",
    code: `import os
import requests

QUANSEC_API_KEY = os.environ["QUANSEC_API_KEY"]
BASE_URL = "https://api.quansec.io"

def get_tunnel_status():
    response = requests.get(
        f"{BASE_URL}/api/ipsec/stats",
        headers={"Authorization": f"Bearer {QUANSEC_API_KEY}"},
    )
    return response.json()

status = get_tunnel_status()
print(f"PQC coverage: {status['pqc_coverage']}%")`,
  },
  websocket: {
    label: "WebSocket (live)",
    code: `const ws = new WebSocket(
  "wss://api.quansec.io/api/ws/live"
);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.kind === "lifecycle") {
    console.log(\`Tunnel event: \${data.event}\`);
  } else {
    console.log(\`PQC coverage: \${data.pqc_pct}%\`);
  }
};`,
  },
};

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="relative group">
      <pre
        className="rounded-lg px-4 py-4 text-xs font-mono-display overflow-x-auto leading-relaxed"
        style={{ background: "var(--bg-panel-raised)", color: "var(--text-secondary)" }}
      >
        {code}
      </pre>
      <button
        onClick={copy}
        className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-mono-display focus-ring"
        style={{ background: "var(--bg-panel)", border: "1px solid var(--border-hairline-bright)", color: "var(--text-tertiary)" }}
      >
        {copied ? <Check size={11} style={{ color: "var(--pqc-cyan)" }} /> : <Copy size={11} />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export default function DocsPage() {
  const [active, setActive] = useState<keyof typeof SNIPPETS>("curl");

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <div className="text-[11px] font-mono-display tracking-[0.18em] uppercase mb-1" style={{ color: "var(--text-tertiary)" }}>
          Developer Reference
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Integration Guide</h1>
        <p className="text-sm mt-1.5" style={{ color: "var(--text-secondary)" }}>
          Connect your application to a quantum-safe IPsec tunnel in minutes.
        </p>
      </div>

      {/* Step 1 */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Step 1" title="Generate an API key" />
        <div className="px-5 py-5 text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
          Go to <strong style={{ color: "var(--text-primary)" }}>API Keys</strong> and create a new key.
          Store it as an environment variable — it&apos;s shown once and never displayed again.
        </div>
      </Panel>

      {/* Step 2 — code examples */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Step 2" title="Authenticate your requests" />
        <div className="px-5 pt-4 pb-5">
          <div className="flex gap-1.5 mb-4 flex-wrap">
            {(Object.keys(SNIPPETS) as Array<keyof typeof SNIPPETS>).map((key) => (
              <button
                key={key}
                onClick={() => setActive(key)}
                className="px-3 py-1.5 rounded-md text-xs font-mono-display transition-colors focus-ring"
                style={{
                  background: active === key ? "var(--pqc-cyan-glow)" : "var(--bg-panel-raised)",
                  color: active === key ? "var(--pqc-cyan)" : "var(--text-tertiary)",
                  border: `1px solid ${active === key ? "var(--pqc-cyan-dim)" : "var(--border-hairline)"}`,
                }}
              >
                {SNIPPETS[key].label}
              </button>
            ))}
          </div>
          <CodeBlock code={SNIPPETS[active].code} />
        </div>
      </Panel>

      {/* Step 3 — what you get */}
      <Panel className="mb-6">
        <PanelHeader eyebrow="Step 3" title="What your application gets" />
        <div className="px-5 py-5 space-y-4">
          {[
            { name: "ML-KEM-1024 key exchange", desc: "NIST FIPS 203 Level 5 post-quantum cryptography on every tunnel" },
            { name: "Real-time tunnel monitoring", desc: "Live coverage, traffic, and handshake data via REST and WebSocket" },
            { name: "Policy automation", desc: "Switch between classical and quantum-safe configurations with one call" },
            { name: "Compliance audit trail", desc: "Timestamped evidence of every policy change for CNSA 2.0 reporting" },
          ].map((item) => (
            <div key={item.name} className="flex items-start gap-3">
              <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: "var(--pqc-cyan)" }} />
              <div>
                <div className="text-sm font-medium">{item.name}</div>
                <div className="text-xs mt-0.5" style={{ color: "var(--text-tertiary)" }}>{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* API reference table */}
      <Panel>
        <PanelHeader eyebrow="Reference" title="Available endpoints" />
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono-display">
            <tbody>
              {[
                ["GET", "/api/ipsec/stats", "Live coverage and traffic summary"],
                ["GET", "/api/ipsec/tunnels", "Detailed tunnel list"],
                ["GET", "/api/ipsec/policies/compare", "Classical vs PQC comparison"],
                ["POST", "/api/ipsec/policies/apply", "Switch tunnel policy"],
                ["GET", "/api/ws/live", "WebSocket live event stream"],
              ].map(([method, path, desc]) => (
                <tr key={path} className="border-t" style={{ borderColor: "var(--border-hairline)" }}>
                  <td className="px-5 py-3 w-16">
                    <span
                      className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                      style={{
                        background: method === "GET" ? "var(--pqc-cyan-glow)" : "var(--lattice-violet-glow)",
                        color: method === "GET" ? "var(--pqc-cyan)" : "var(--lattice-violet)",
                      }}
                    >
                      {method}
                    </span>
                  </td>
                  <td className="px-2 py-3" style={{ color: "var(--text-primary)" }}>{path}</td>
                  <td className="px-5 py-3 text-right" style={{ color: "var(--text-tertiary)" }}>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
