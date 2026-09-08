"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { quanseq, TlsCertificate } from "@/lib/api";
import { Panel, PanelHeader } from "@/components/ui-primitives";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b last:border-b-0"
         style={{ borderColor: "var(--border-hairline)" }}>
      <span className="text-xs shrink-0" style={{ color: "var(--text-tertiary)" }}>{label}</span>
      <span className="text-xs font-mono-display text-right break-all" style={{ color: "var(--text-primary)" }}>
        {value ?? <span style={{ color: "var(--text-tertiary)" }}>—</span>}
      </span>
    </div>
  );
}

export default function TlsCertificatePage() {
  const [cert, setCert] = useState<TlsCertificate | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setCert(await quanseq.getTlsCertificate());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read the certificate");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const expiringSoon = cert?.days_until_expiry != null && cert.days_until_expiry < 30;

  return (
    <div className="p-8 max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: "var(--text-primary)" }}>
          Server certificate
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-secondary)" }}>
          The certificate the TLS service presents, and a real chain verification
          against the configured CA.
        </p>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-lg text-xs font-mono-display flex items-center gap-2"
             style={{ background: "var(--danger-glow)", color: "var(--danger-red)", border: "1px solid #7a1f33" }}>
          <XCircle size={14} /> {error}
        </div>
      )}

      {cert && (
        <>
          <Panel>
            <PanelHeader eyebrow="Identity" title="Subject and issuer" right={
              cert.chain_verified ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-mono-display" style={{ color: "var(--pqc-cyan)" }}>
                  <CheckCircle2 size={13} /> CHAIN VERIFIED
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs font-mono-display" style={{ color: "var(--danger-red)" }}>
                  <XCircle size={13} /> CHAIN INVALID
                </span>
              )
            } />
            <div className="px-5 py-3">
              <Row label="Subject" value={cert.subject} />
              <Row label="Issuer" value={cert.issuer} />
              <Row label="Serial" value={cert.serial_number} />
              <Row label="SAN" value={cert.san.join(", ")} />
            </div>
          </Panel>

          <Panel>
            <PanelHeader eyebrow="Cryptography" title="Algorithms" />
            <div className="px-5 py-3">
              <Row label="Signature algorithm" value={cert.signature_algorithm} />
              <Row label="Public key" value={
                cert.key_size ? `${cert.public_key_algorithm} ${cert.key_size} bit` : cert.public_key_algorithm
              } />
              <Row label="Post-quantum signature" value={
                cert.pqc_signature
                  ? <span style={{ color: "var(--pqc-cyan)" }}>YES</span>
                  : <span style={{ color: "var(--threat-amber)" }}>NO — classical</span>
              } />
            </div>
            {cert.note && (
              <div className="px-5 pb-4 pt-1 text-[11px] leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
                {cert.note}
              </div>
            )}
          </Panel>

          <Panel>
            <PanelHeader eyebrow="Validity" title="Lifetime" />
            <div className="px-5 py-3">
              <Row label="Not before" value={cert.not_before && new Date(cert.not_before).toLocaleString()} />
              <Row label="Not after" value={cert.not_after && new Date(cert.not_after).toLocaleString()} />
              <Row label="Days remaining" value={
                <span style={{ color: expiringSoon ? "var(--threat-amber)" : "var(--text-primary)" }}>
                  {cert.days_until_expiry}
                </span>
              } />
            </div>
          </Panel>

          <p className="text-[11px] leading-relaxed" style={{ color: "var(--text-tertiary)" }}>
            This is a development PKI: the CA private key sits on disk beside the
            server key. Certificates are generated from the command line with
            <code className="font-mono-display"> scripts/generate_tls_certs.py</code> — there is
            no HTTP route for it, because generating a CA rotates the trust anchor
            for the whole module.
          </p>
        </>
      )}
    </div>
  );
}
