import type {
  IPsecStats,
  IPsecTunnel,
  Policy,
  PolicyCompare,
  AttackResult,
  ApiKey,
  ApiKeyCreated,
  GrantableScopes,
  TlsStatus,
  TlsStats,
  TlsReadiness,
  TlsSession,
  TlsEvent,
  TlsPolicy,
  TlsCertificate,
  TlsSignatureAlgorithms,
  TlsProbeSuite,
  TlsProbeResult,
  TlsDowngradeTest,
} from "@/lib/api";

/**
 * Single in-memory source of truth for showcase mode. Every reader (the typed
 * QUANSEC client and the raw-fetch endpoints used by the SSH pages) derives
 * its numbers from this store, so a dashboard total and its detail view can
 * never drift apart — they're computed from the same underlying records.
 */

let nextId = 1000;
const id = () => nextId++;

// ── Scoring ──────────────────────────────────────────────────────────────
//
// Mirrors protocols/scoring/router.py field-for-field (ALGO_STRENGTH table,
// weights, grade thresholds) so the showcase score is the same number the
// real backend would compute from equivalent data — not an approximation.

const ALGO_STRENGTH: Record<string, number> = {
  mlkem1024: 100, "ml-kem-1024": 100,
  mlkem768: 85, "ml-kem-768": 85, "mlkem768x25519-sha256": 90,
  sntrup761: 80, "sntrup761x25519-sha512@openssh.com": 82,
  x25519mlkem768: 90, secp256r1mlkem768: 88, x25519kyber768draft00: 80,
  x25519: 30, prime256v1: 25, secp256r1: 25, secp384r1: 28,
  curve25519: 30, "curve25519-sha256": 30,
  ecdh: 25, dh: 20,
};

function algoStrength(kex: string | null | undefined): number {
  if (!kex) return 0;
  const k = kex.toLowerCase();
  for (const [name, score] of Object.entries(ALGO_STRENGTH)) {
    if (k.includes(name)) return score;
  }
  if (k.includes("mlkem") || k.includes("kyber")) return 85;
  return 20;
}

function scoreFactors(coverage: number, avgStrength: number, downgradeResistant: boolean, hybridBonus: number): number {
  const score = coverage * 0.4 + avgStrength * 0.35 + (downgradeResistant ? 100 : 0) * 0.15 + hybridBonus * 0.1;
  return Math.round(Math.min(score, 100) * 10) / 10;
}

function grade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

function nowIso(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

// ── IPsec ────────────────────────────────────────────────────────────────

const IPSEC_POLICIES: Policy[] = [
  {
    name: "pqc-level5",
    label: "Post-Quantum (ML-KEM-1024)",
    description: "Pure ML-KEM-1024 key exchange. NIST FIPS 203 Level 5 — the highest post-quantum security category.",
    ike_proposal: "aes256gcm16-prfsha384-ml_kem_1024",
    esp_proposal: "aes256gcm16-ml_kem_1024",
    pqc: true,
    algorithms: { kem: "ML-KEM-1024", cipher: "AES-256-GCM", prf: "PRF-HMAC-SHA384" },
    threat: null,
  },
  {
    name: "classical-baseline",
    label: "Classical (ECDH P-384)",
    description: "Elliptic-curve Diffie-Hellman on the NIST P-384 curve. Vulnerable to a sufficiently large quantum computer running Shor's algorithm.",
    ike_proposal: "aes256gcm16-prfsha384-ecp384",
    esp_proposal: "aes256gcm16-ecp384",
    pqc: false,
    algorithms: { kex: "ECDH-P384", cipher: "AES-256-GCM" },
    threat: "Harvest-now, decrypt-later",
  },
];

let ipsecCurrentPolicy = "pqc-level5";

const ipsecTunnels: IPsecTunnel[] = [
  {
    id: id(),
    name: "pqc-tunnel-primary",
    local_host: "10.20.0.1",
    remote_host: "10.20.0.2",
    state: "ESTABLISHED",
    ike_version: 2,
    ike_proposal: "aes256gcm16-prfsha384-ml_kem_1024",
    esp_proposal: "aes256gcm16-ml_kem_1024",
    pqc_kem: "ML-KEM-1024",
    pqc_enabled: true,
    bytes_in: 48_230_112,
    bytes_out: 51_884_224,
    packets_in: 96_120,
    packets_out: 98_014,
    established_at: nowIso(-1000 * 60 * 47),
    last_seen: nowIso(),
  },
  {
    id: id(),
    name: "pqc-tunnel-secondary",
    local_host: "10.20.0.1",
    remote_host: "10.20.0.3",
    state: "ESTABLISHED",
    ike_version: 2,
    ike_proposal: "aes256gcm16-prfsha384-ml_kem_1024",
    esp_proposal: "aes256gcm16-ml_kem_1024",
    pqc_kem: "ML-KEM-1024",
    pqc_enabled: true,
    bytes_in: 12_004_882,
    bytes_out: 11_552_010,
    packets_in: 25_441,
    packets_out: 24_998,
    established_at: nowIso(-1000 * 60 * 22),
    last_seen: nowIso(),
  },
];

function computeIpsecStats(): IPsecStats {
  const established = ipsecTunnels.filter((t) => t.state === "ESTABLISHED").length;
  const pqcEnabled = ipsecTunnels.filter((t) => t.pqc_enabled).length;
  const totalBytesIn = ipsecTunnels.reduce((s, t) => s + t.bytes_in, 0);
  const totalBytesOut = ipsecTunnels.reduce((s, t) => s + t.bytes_out, 0);
  return {
    total_tunnels: ipsecTunnels.length,
    established,
    down: ipsecTunnels.length - established,
    pqc_enabled: pqcEnabled,
    pqc_coverage: ipsecTunnels.length ? (pqcEnabled / ipsecTunnels.length) * 100 : 0,
    total_bytes_in: totalBytesIn,
    total_bytes_out: totalBytesOut,
    last_updated: nowIso(),
  };
}

function computeIpsecCompare(): PolicyCompare {
  return {
    comparison: [
      { field: "Key exchange", classical: "ECDH-P384", pqc: "ML-KEM-1024", why_changed: "ECDH is broken by Shor's algorithm on a cryptographically relevant quantum computer.", standard: "NIST FIPS 203" },
      { field: "NIST security category", classical: "Category 3 (equiv.)", pqc: "Category 5", why_changed: "ML-KEM-1024 targets the highest NIST PQC security category.", standard: "NIST FIPS 203" },
      { field: "Quantum resistant", classical: false, pqc: true, why_changed: "Lattice-based hardness assumptions have no known efficient quantum attack.", standard: "CNSA 2.0" },
      { field: "Harvest-now-decrypt-later safe", classical: false, pqc: true, why_changed: "Traffic captured today stays unreadable even after large-scale quantum computers arrive.", standard: "CNSA 2.0" },
    ],
    current_policy: ipsecCurrentPolicy,
    cnsa_deadline: "2030-01-01",
    days_remaining: Math.max(0, Math.ceil((new Date("2030-01-01").getTime() - Date.now()) / 86_400_000)),
  };
}

function runIpsecAttack(name: string): AttackResult {
  switch (name) {
    case "downgrade":
      return { attack: name, result: "BLOCKED", technique: "IKE proposal stripping", detail: "Fail-closed policy rejected the connection instead of falling back to a classical proposal.", duration_ms: 812 };
    case "shors":
      return { attack: name, result: "RESISTANT", technique: "Quantum factoring / discrete-log attack", detail: "ML-KEM's lattice hardness assumption has no known efficient quantum algorithm.", complexity_class: "Believed BQP-hard" };
    case "harvest":
      return { attack: name, result: "PROTECTED", technique: "Store-now, decrypt-later", detail: "Captured ciphertext remains computationally protected against future quantum decryption.", captured_bytes: 2_048_000 };
    case "factoring":
      return { attack: name, result: "BROKEN", technique: "Pollard rho factorization", detail: "A 512-bit classical RSA-style key factored in under a second — illustrating why classical key exchange is being retired.", key_bits: 512, factor_time_ms: 340 };
    case "kyber-resist":
      return { attack: name, result: "RESISTANT", technique: "Brute-force lattice search", detail: "10,000 attempts against the ML-KEM-1024 lattice problem, all unsuccessful.", attempts: 10_000 };
    default:
      return { attack: name, result: "RESISTANT" };
  }
}

// ── SSH ──────────────────────────────────────────────────────────────────

export interface SshConn {
  id: number;
  session_key: string;
  local_host: string;
  remote_host: string;
  kex_algorithm: string;
  kem_label: string;
  pqc_enabled: boolean;
  state: string;
}

const sshConnections: SshConn[] = [
  { id: id(), session_key: "a1f9c2", local_host: "10.20.0.1:22", remote_host: "10.20.0.10:52344", kex_algorithm: "mlkem768x25519-sha256", kem_label: "ML-KEM-768 + X25519", pqc_enabled: true, state: "ESTABLISHED" },
  { id: id(), session_key: "b73de0", local_host: "10.20.0.1:22", remote_host: "10.20.0.11:60122", kex_algorithm: "mlkem768x25519-sha256", kem_label: "ML-KEM-768 + X25519", pqc_enabled: true, state: "ESTABLISHED" },
  { id: id(), session_key: "c04a17", local_host: "10.20.0.1:22", remote_host: "10.20.0.12:44810", kex_algorithm: "mlkem768x25519-sha256", kem_label: "ML-KEM-768 + X25519", pqc_enabled: true, state: "ESTABLISHED" },
];

const SSH_POLICIES = [
  { name: "hybrid-pqc", label: "Hybrid (ML-KEM-768 + X25519)", description: "Hybrid post-quantum key exchange combining ML-KEM-768 with classical X25519. NIST Level 3.", kex: "mlkem768x25519-sha256", pqc: true },
  { name: "classical-baseline", label: "Classical (X25519)", description: "Curve25519 Diffie-Hellman. No post-quantum protection.", kex: "curve25519-sha256", pqc: false },
];
let sshCurrentPolicy = "hybrid-pqc";

function computeSshStats() {
  const active = sshConnections.filter((c) => c.state === "ESTABLISHED").length;
  const pqcEnabled = sshConnections.filter((c) => c.pqc_enabled).length;
  return {
    total_connections: sshConnections.length,
    active,
    closed: sshConnections.length - active,
    pqc_enabled: pqcEnabled,
    pqc_coverage: sshConnections.length ? (pqcEnabled / sshConnections.length) * 100 : 0,
  };
}

function runSshAttack(attackId: string) {
  switch (attackId) {
    case "downgrade":
      return { attack: attackId, result: "BLOCKED", detail: "Server rejected the connection rather than negotiating a classical-only KEX.", duration_ms: 640 };
    case "shors":
      return { attack: attackId, result: "RESISTANT", detail: "The ML-KEM-768 half of the hybrid exchange has no known efficient quantum attack." };
    case "harvest":
      return { attack: attackId, result: "PROTECTED", detail: "Recorded traffic stays protected even if the classical X25519 half is later broken by a quantum computer." };
    default:
      return { attack: attackId, result: "RESISTANT" };
  }
}

const ztEvents = Array.from({ length: 6 }).map((_, i) => ({
  event_time: nowIso(-1000 * 60 * (i * 7 + 2)),
  identity: ["alice@bank.com", "bob@bank.com", "svc-deploy@bank.com"][i % 3],
  cert_serial: String(4000 + i),
  ca_fingerprint: "SHA256:9fJ2k...QUANSEC-CA",
  source_ip: `10.20.0.${10 + (i % 5)}`,
  principal: "hd6441",
  result: i === 4 ? "rejected" : "accepted",
  reason: i === 4 ? "expired" : "",
}));

const caInfo = { ca_public_key: "ssh-ed25519-cert-v01 AAAAC3NzaC1lZDI1NTE5LWNlcnQtdjAxQEAAA...", fingerprint: "SHA256:9fJ2kQx7mNc3vRzT8pL1wY6bH4gK0sD5aE2fC9uV7bA" };
let caIssuedCerts: Array<{ serial: number; identity: string; principals: string; valid_hours: number; issued_at: string; expires_at: string; revoked: boolean; expired: boolean }> = [
  { serial: 4001, identity: "alice@bank.com", principals: "hd6441", valid_hours: 8, issued_at: nowIso(-1000 * 60 * 60 * 3), expires_at: nowIso(1000 * 60 * 60 * 5), revoked: false, expired: false },
];

// ── Shared: API keys ─────────────────────────────────────────────────────

const apiKeys: Array<ApiKey & { rawPrefix: string }> = [
  { id: id(), name: "Production server", key_prefix: "qsk_live_a1b2...c3d4", scopes: ["ipsec:read"], protocol: null, last_used: nowIso(-1000 * 60 * 4), created_at: nowIso(-1000 * 60 * 60 * 24 * 12), expires_at: null, revoked: false, expired: false, rawPrefix: "qsk_live_a1b2" },
];

export const GRANTABLE_SCOPES: GrantableScopes = {
  grantable: ["ipsec:read", "ipsec:admin", "ssh:read", "ssh:admin", "tls:read", "tls:probe", "tls:admin", "system:admin"],
  descriptions: {
    "ipsec:read": "Read IPsec tunnel status, policy and telemetry.",
    "ipsec:admin": "Apply IPsec policy changes.",
    "ssh:read": "Read SSH session status, policy and telemetry.",
    "ssh:admin": "Apply SSH policy changes and issue certificates.",
    "tls:read": "Status, stats, sessions, events, policy and readiness.",
    "tls:probe": "Run enforcement probes and validation tests. Implies read.",
    "tls:admin": "Apply and roll back policy, control the data plane. Implies read and probe.",
    "system:admin": "Full administrative authority, including non-expiring keys.",
  },
};

function randomKeySuffix() {
  return Array.from({ length: 24 }).map(() => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)]).join("");
}

// ── Alerts ───────────────────────────────────────────────────────────────

interface AlertRow {
  id: number; rule: string; severity: string; protocol: string;
  message: string; acked: boolean; raised_at: string;
}

const alerts: AlertRow[] = [
  { id: id(), rule: "cert-expiry", severity: "medium", protocol: "tls", message: "Server certificate renews in 27 days", acked: false, raised_at: nowIso(-1000 * 60 * 60 * 6) },
];

// ── Failmode ─────────────────────────────────────────────────────────────

const failmode = {
  ipsec: { mode: "fail-closed", proposal: "aes256gcm16-ml_kem_1024", desc: "No classical downgrade permitted." },
  ssh: { mode: "fail-closed", kex: "mlkem768x25519-sha256", desc: "No classical downgrade permitted." },
};

// ── TLS ──────────────────────────────────────────────────────────────────

const tlsSessions: TlsSession[] = Array.from({ length: 14 }).map((_, i) => {
  const hybrid = true;
  return {
    id: id(),
    occurred_at: nowIso(-1000 * 60 * (i * 3 + 1)),
    remote_addr: `203.0.113.${20 + i}`,
    remote_port: String(50000 + i),
    tls_protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    negotiated_group: hybrid ? "X25519MLKEM768" : "x25519",
    client_groups: hybrid ? "X25519MLKEM768:x25519" : "x25519:secp256r1",
    client_verify: i % 6 === 0 ? "SUCCESS" : "NONE",
    client_s_dn: i % 6 === 0 ? "CN=client-svc,O=QUANSEC" : null,
    server_name: "quansec.local",
    session_reused: false,
    http_status: 200,
    request_time: 0.012 + i * 0.001,
    bytes_sent: 4096 + i * 128,
    request_line: "GET /api/tls/status HTTP/1.1",
    pqc_enabled: hybrid,
    kem_label: hybrid ? "ML-KEM-768" : null,
    log_source: "/var/log/nginx/access.log",
    log_offset: 10_000 + i * 220,
    recorded_at: nowIso(-1000 * 60 * (i * 3 + 1)),
    raw_line: null,
    connection_id: `8444:${1000 + i}`,
    hybrid_negotiated: hybrid,
    mtls_enabled: false,
    client_certificate_verified: i % 6 === 0 ? true : null,
    certificate_signature_algorithm: "ecdsa-with-SHA384",
    started_at: nowIso(-1000 * 60 * (i * 3 + 1)),
    last_seen: nowIso(-1000 * 60 * (i * 3)),
    request_count: 1,
    evidence_source: "nginx-access-log",
  };
});

const tlsEvents: TlsEvent[] = [
  { id: id(), event_type: "service_start", severity: "info", summary: "TLS data plane started", detail: null, occurred_at: nowIso(-1000 * 60 * 90) },
  { id: id(), event_type: "probe_suite", severity: "info", summary: "Probe suite executed", detail: { passed: 6, total: 6 }, occurred_at: nowIso(-1000 * 60 * 40) },
];

let tlsPolicyApplied = true;
let tlsProbeHistory: TlsProbeSuite | null = null;
let tlsDowngradeTestRun: TlsDowngradeTest | null = null;

function computeTlsStats(): TlsStats {
  const hybrid = tlsSessions.filter((s) => s.pqc_enabled).length;
  const withGroup = tlsSessions.filter((s) => s.negotiated_group).length;
  const classical = withGroup - hybrid;
  const unknown = tlsSessions.length - withGroup;
  const tls13 = tlsSessions.filter((s) => s.tls_protocol === "TLSv1.3").length;
  return {
    total_sessions: tlsSessions.length,
    active_sessions: Math.min(tlsSessions.length, 3),
    hybrid_sessions: hybrid,
    classical_sessions: classical,
    unknown_sessions: unknown,
    hybrid_coverage: withGroup ? (hybrid / withGroup) * 100 : 0,
    tls13_coverage: tlsSessions.length ? (tls13 / tlsSessions.length) * 100 : 0,
    failed_handshakes: 0,
    active_alerts: alerts.filter((a) => !a.acked).length,
    last_observed_at: tlsSessions[0]?.occurred_at ?? null,
    has_evidence: tlsSessions.length > 0,
    active_window_seconds: 300,
  };
}

function computeTlsStatus(): TlsStatus {
  const stats = computeTlsStats();
  const enforced = tlsDowngradeTestRun?.rejected ?? false;
  const negotiated = stats.hybrid_sessions > 0;
  const overall: TlsStatus["overall_status"] = enforced
    ? "hybrid_enforced"
    : negotiated
      ? "hybrid_observed"
      : "configured_unproven";
  return {
    enabled: true,
    runtime_supported: true,
    tls13_enforced: true,
    hybrid_group_configured: true,
    hybrid_group_negotiated: negotiated,
    hybrid_only_enforced: enforced,
    certificate_verified: true,
    mtls_enabled: false,
    authentication_quantum_safe: false,
    overall_status: overall,
    label: enforced
      ? "Hybrid key exchange is negotiated and classical-only clients are refused."
      : negotiated
        ? "Hybrid key exchange has been negotiated by real clients; classical clients have not yet been proven refused."
        : "Hybrid group is configured but has not yet been observed in a real handshake.",
    service: { host: "0.0.0.0", port: 8444, running: true, pid: 4821, listening: true, config_path: "/etc/quansec/nginx.conf", config_sha256: "9c2f...ab41", error: null },
    build: { runtime_dir: "/opt/quansec/tls", nginx_binary: "/usr/sbin/nginx", nginx_version: "1.27.3", nginx_openssl: "OpenSSL 3.5.0", openssl_binary: "/usr/bin/openssl", openssl_version: "OpenSSL 3.5.0", system_openssl: "OpenSSL 3.5.0", hybrid_group_available: true, runtime_built: true },
    evidence: {
      observed_hybrid_sessions: stats.hybrid_sessions,
      probe_results: { classical_refused: enforced },
      configured_groups: "X25519MLKEM768:x25519",
      configured_protocols: "TLSv1.3",
      configured_ciphersuites: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
      config_sha256: "9c2f...ab41",
    },
    last_updated: nowIso(),
  };
}

function computeTlsReadiness(): TlsReadiness {
  const status = computeTlsStatus();
  const checks = [
    { check: "Runtime lists hybrid group", passed: status.runtime_supported, detail: "OpenSSL build advertises X25519MLKEM768." },
    { check: "Hybrid group configured", passed: status.hybrid_group_configured, detail: "nginx.conf requests the hybrid group." },
    { check: "Hybrid group negotiated", passed: status.hybrid_group_negotiated, detail: "At least one real handshake used it." },
    { check: "Certificate verified", passed: status.certificate_verified, detail: "Chain validates against the configured CA." },
  ];
  return {
    ready: checks.every((c) => c.passed),
    checks,
    blocking: checks.filter((c) => !c.passed).map((c) => c.check),
    warnings: status.hybrid_only_enforced ? [] : ["Classical clients have not yet been proven refused — run the downgrade test."],
    runtime: { nginx_version: status.build.nginx_version, openssl_version: status.build.openssl_version },
  };
}

const tlsCertificate: TlsCertificate = {
  server_name: "quansec.local",
  subject: "CN=quansec.local, O=QUANSEC",
  issuer: "CN=QUANSEC Development CA, O=QUANSEC",
  serial_number: "7A:3F:2C:19:BE:04",
  signature_algorithm: "ecdsa-with-SHA384",
  public_key_algorithm: "EC",
  key_size: 384,
  san: ["quansec.local", "localhost"],
  not_before: nowIso(-1000 * 60 * 60 * 24 * 40),
  not_after: nowIso(1000 * 60 * 60 * 24 * 50),
  days_until_expiry: 50,
  chain_verified: true,
  pqc_signature: false,
  authentication_class: "classical",
  note: "Certificate authentication uses a classical ECDSA signature. Key establishment (hybrid ML-KEM-768 + X25519) is independent of certificate authentication.",
};

const tlsSignatureAlgorithms: TlsSignatureAlgorithms = {
  openssl_binary: "/usr/bin/openssl",
  total_advertised: 12,
  ml_dsa_advertised: [],
  ml_dsa_available: false,
  note: "This OpenSSL build does not advertise ML-DSA signature algorithms.",
};

function computeTlsPolicy(): TlsPolicy {
  const view = {
    source: "rendered",
    protocols: "TLSv1.3",
    groups: "X25519MLKEM768:x25519",
    ciphersuites: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    mtls: false,
    early_data: false,
    listen: "0.0.0.0:8444",
    config_sha256: "9c2f...ab41",
    tls13_only: true,
    hybrid_group_only: false,
    fail_closed: false,
    fallback_groups: ["x25519", "secp256r1"],
  };
  return {
    intended: view,
    running: tlsPolicyApplied ? { ...view } : null,
    drift: { in_sync: tlsPolicyApplied, reason: tlsPolicyApplied ? "" : "No configuration has been applied yet.", detail: tlsPolicyApplied ? "Running configuration matches the intended policy." : "Apply the policy to render nginx.conf.", differences: [] },
    active_state: { pid: 4821, listening: true },
    fail_closed: false,
  };
}

function runTlsProbeSuite(): TlsProbeSuite {
  const results: TlsProbeResult[] = [
    { probe_type: "hybrid-positive", expected_outcome: "connect", actual_outcome: "connect", passed: true, description: "Hybrid-capable client connects", target_host: "quansec.local", target_port: 8444, negotiated_group: "X25519MLKEM768", negotiated_cipher: "TLS_AES_256_GCM_SHA384", tls_protocol: "TLSv1.3", verify_result: "OK", http_status: 200, openssl_binary: "/usr/bin/openssl", openssl_version: "OpenSSL 3.5.0", command: "openssl s_client -groups X25519MLKEM768", exit_code: 0, stdout_excerpt: "Server Temp Key: X25519MLKEM768", evidence_path: null, duration_ms: 84, run_at: nowIso() },
    { probe_type: "tls13-required", expected_outcome: "connect", actual_outcome: "connect", passed: true, description: "TLS 1.3 client connects", target_host: "quansec.local", target_port: 8444, negotiated_group: "X25519MLKEM768", negotiated_cipher: "TLS_AES_256_GCM_SHA384", tls_protocol: "TLSv1.3", verify_result: "OK", http_status: 200, openssl_binary: "/usr/bin/openssl", openssl_version: "OpenSSL 3.5.0", command: "openssl s_client -tls1_3", exit_code: 0, stdout_excerpt: null, evidence_path: null, duration_ms: 71, run_at: nowIso() },
  ];
  const suite: TlsProbeSuite = {
    total: results.length,
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
    results,
    enforcement_proven: tlsDowngradeTestRun?.rejected ?? false,
    summary: "Hybrid key exchange and TLS 1.3 both confirmed by a live handshake.",
  };
  tlsProbeHistory = suite;
  // A probe that connects with the hybrid group counts as an observation.
  tlsEvents.unshift({ id: id(), event_type: "probe_suite", severity: "info", summary: "Probe suite executed", detail: { passed: suite.passed, total: suite.total }, occurred_at: nowIso() });
  return suite;
}

function runTlsDowngrade(kind: "hybrid" | "tls12" | "cipher"): TlsDowngradeTest {
  const label = kind === "hybrid" ? "hybrid-downgrade" : kind === "tls12" ? "tls12-downgrade" : "cipher-downgrade";
  const results: TlsProbeResult[] = [
    { probe_type: `${label}-x25519-only`, expected_outcome: "reject", actual_outcome: "reject", passed: true, description: "X25519-only client is refused", target_host: "quansec.local", target_port: 8444, negotiated_group: null, negotiated_cipher: null, tls_protocol: null, verify_result: null, http_status: null, openssl_binary: "/usr/bin/openssl", openssl_version: "OpenSSL 3.5.0", command: "openssl s_client -groups x25519", exit_code: 1, stdout_excerpt: "handshake failure", evidence_path: null, duration_ms: 46, run_at: nowIso() },
    { probe_type: `${label}-prime256v1-only`, expected_outcome: "reject", actual_outcome: "reject", passed: true, description: "prime256v1-only client is refused", target_host: "quansec.local", target_port: 8444, negotiated_group: null, negotiated_cipher: null, tls_protocol: null, verify_result: null, http_status: null, openssl_binary: "/usr/bin/openssl", openssl_version: "OpenSSL 3.5.0", command: "openssl s_client -groups prime256v1", exit_code: 1, stdout_excerpt: "handshake failure", evidence_path: null, duration_ms: 41, run_at: nowIso() },
  ];
  const test: TlsDowngradeTest = {
    test: label,
    rejected: true,
    description: "Both a classical-only X25519 client and a classical-only prime256v1 client attempted the handshake.",
    results,
    verdict: "Both classical-only clients were refused. Hybrid key exchange is required, not merely offered.",
  };
  if (kind === "hybrid") tlsDowngradeTestRun = test;
  tlsEvents.unshift({ id: id(), event_type: label, severity: "info", summary: `${label} test: classical clients refused`, detail: null, occurred_at: nowIso() });
  return test;
}

// ── Live jitter ──────────────────────────────────────────────────────────

let tickStarted = false;
function startTicking() {
  if (tickStarted || typeof window === "undefined") return;
  tickStarted = true;
  setInterval(() => {
    for (const t of ipsecTunnels) {
      if (t.state !== "ESTABLISHED") continue;
      t.bytes_in += Math.floor(400 + Math.random() * 4000);
      t.bytes_out += Math.floor(400 + Math.random() * 4000);
      t.packets_in += Math.floor(1 + Math.random() * 8);
      t.packets_out += Math.floor(1 + Math.random() * 8);
      t.last_seen = nowIso();
    }
  }, 4000);
}
startTicking();

// ── Public store API ────────────────────────────────────────────────────

export const showcaseStore = {
  // IPsec
  getIpsecStats: () => computeIpsecStats(),
  getIpsecTunnels: () => ipsecTunnels.map((t) => ({ ...t })),
  getIpsecPolicies: () => IPSEC_POLICIES.map((p) => ({ ...p })),
  getIpsecCompare: () => computeIpsecCompare(),
  applyIpsecPolicy: (policyName: string) => {
    const policy = IPSEC_POLICIES.find((p) => p.name === policyName);
    ipsecCurrentPolicy = policyName;
    for (const t of ipsecTunnels) {
      t.pqc_enabled = policy?.pqc ?? t.pqc_enabled;
      t.pqc_kem = policy?.pqc ? "ML-KEM-1024" : null;
      t.ike_proposal = policy?.ike_proposal ?? t.ike_proposal;
      t.esp_proposal = policy?.esp_proposal ?? t.esp_proposal;
    }
    return { status: "applied", policy: policyName, pqc_enabled: policy?.pqc ?? false };
  },
  runIpsecAttack,

  // SSH
  getSshStats: () => computeSshStats(),
  getSshConnections: () => sshConnections.map((c) => ({ ...c })),
  getSshPolicies: () => SSH_POLICIES.map((p) => ({ ...p })),
  getSshCompare: () => ({
    comparison: [
      { field: "Key exchange", classical: "curve25519-sha256", pqc: "mlkem768x25519-sha256", why_changed: "Adds ML-KEM-768 alongside X25519 for quantum resistance.", standard: "NIST FIPS 203" },
      { field: "NIST security category", classical: "N/A", pqc: "Category 3", why_changed: "ML-KEM-768 targets NIST PQC security category 3.", standard: "NIST FIPS 203" },
      { field: "Quantum resistant", classical: false, pqc: true, why_changed: "Hybrid construction keeps classical assurance while adding lattice-based resistance.", standard: "CNSA 2.0" },
    ],
    days_remaining: Math.max(0, Math.ceil((new Date("2030-01-01").getTime() - Date.now()) / 86_400_000)),
  }),
  applySshPolicy: (name: string) => {
    const policy = SSH_POLICIES.find((p) => p.name === name);
    sshCurrentPolicy = name;
    for (const c of sshConnections) {
      c.pqc_enabled = policy?.pqc ?? c.pqc_enabled;
      c.kex_algorithm = policy?.kex ?? c.kex_algorithm;
      c.kem_label = policy?.pqc ? "ML-KEM-768 + X25519" : "X25519";
    }
    return { policy: name, kex: policy?.kex ?? sshCurrentPolicy };
  },
  runSshAttack,
  getZtEvents: () => ztEvents.map((e) => ({ ...e })),
  getZtStatus: () => {
    const accepted = ztEvents.filter((e) => e.result === "accepted").length;
    const rejected = ztEvents.filter((e) => e.result === "rejected").length;
    const rejectedExpired = ztEvents.filter((e) => e.result === "rejected" && e.reason === "expired").length;
    return { total_auth_events: ztEvents.length, accepted, rejected, rejected_expired: rejectedExpired };
  },
  getZtPolicy: () => ({
    authentication: "certificate", passwords: "disabled", network_trust: "none",
    credential_lifetime: "short-lived (max 168h)", transport: "hybrid ML-KEM-768 + X25519",
    principles: [
      { principle: "No implicit trust", status: "enforced", detail: "Every connection is authenticated regardless of network origin." },
      { principle: "Certificate-based identity", status: "enforced", detail: "Passwords are disabled; identity is proven with a short-lived signed certificate." },
      { principle: "Least privilege", status: "enforced", detail: "Certificates are scoped to specific principals." },
      { principle: "Post-quantum transport", status: "enforced", detail: "All sessions negotiate hybrid ML-KEM-768 + X25519." },
    ],
  }),
  getCaInfo: () => ({ ...caInfo }),
  getCaIssued: () => caIssuedCerts.map((c) => ({ ...c })),
  issueCaCert: (publicKey: string, identity: string, principals: string, validHours: number) => {
    const serial = 4000 + caIssuedCerts.length + 1;
    const cert = {
      serial, identity, principals, valid_hours: validHours,
      issued_at: nowIso(), expires_at: nowIso(1000 * 60 * 60 * validHours),
      revoked: false, expired: false,
    };
    caIssuedCerts = [cert, ...caIssuedCerts];
    ztEvents.unshift({
      event_time: nowIso(), identity, cert_serial: String(serial), ca_fingerprint: caInfo.fingerprint,
      source_ip: "10.20.0.5", principal: principals, result: "accepted", reason: "",
    });
    return {
      certificate: `ssh-ed25519-cert-v01@openssh.com AAAAIHNoYS1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAII${serial} user-cert for ${identity}`,
      filename: `${identity.replace(/[^a-z0-9]+/gi, "_")}-cert.pub`,
      serial,
    };
  },

  // Shared keys
  listApiKeys: (protocol?: string, includeRevoked = true) =>
    apiKeys
      .filter((k) => !protocol || k.protocol === protocol)
      .filter((k) => includeRevoked || !k.revoked)
      .map(({ rawPrefix: _rawPrefix, ...rest }) => rest),
  createApiKey: (name: string, scopes: string[], protocol: string | null, expiresInDays: number | null, neverExpires: boolean): ApiKeyCreated => {
    const suffix = randomKeySuffix();
    const prefix = `qsk_${protocol ?? "live"}_${suffix.slice(0, 4)}`;
    const rawKey = `qsk_${protocol ?? "live"}_${suffix}`;
    const grantedScopes = scopes.length ? scopes : GRANTABLE_SCOPES.grantable.filter((s) => s.endsWith(":read"));
    const expiresAt = neverExpires ? null : nowIso(1000 * 60 * 60 * 24 * (expiresInDays ?? 90));
    const row: ApiKey & { rawPrefix: string } = {
      id: id(), name, key_prefix: `${prefix}...`, scopes: grantedScopes, protocol: protocol ?? null,
      last_used: null, created_at: nowIso(), expires_at: expiresAt, revoked: false, expired: false,
      rawPrefix: prefix,
    };
    apiKeys.push(row);
    return {
      id: row.id, name, api_key: rawKey, key_prefix: row.key_prefix, scopes: grantedScopes,
      protocol: row.protocol, created_at: row.created_at, expires_at: row.expires_at,
      warning: "This key will not be shown again. Store it securely.",
    };
  },
  revokeApiKey: (keyId: number) => {
    const row = apiKeys.find((k) => k.id === keyId);
    if (row) row.revoked = true;
    return { status: "revoked", key_id: keyId };
  },
  getGrantableScopes: () => GRANTABLE_SCOPES,

  // Alerts
  getAlerts: () => ({ alerts: alerts.map((a) => ({ ...a })), active_count: alerts.filter((a) => !a.acked).length }),
  ackAlert: (alertId: number) => {
    const row = alerts.find((a) => a.id === alertId);
    if (row) row.acked = true;
    return { status: "acknowledged" };
  },

  // Scoring — mirrors protocols/scoring/router.py's three scorers exactly.
  getScore: (protocol: "ipsec" | "ssh" | "tls") => {
    if (protocol === "ipsec") {
      const rows = ipsecTunnels.filter((t) => t.state === "ESTABLISHED");
      const evaluated = rows.length ? rows : ipsecTunnels;
      const total = evaluated.length || 1;
      const pqc = evaluated.filter((t) => t.pqc_enabled).length;
      const coverage = (pqc / total) * 100;
      const strengths = evaluated.map((t) => algoStrength(t.pqc_kem));
      const avgStrength = strengths.length ? strengths.reduce((a, b) => a + b, 0) / strengths.length : 0;
      const downgradeResistant = pqc === total && total > 0;
      const hasHybrid = evaluated.some((t) => (t.pqc_kem ?? "").toLowerCase().includes("x25519") && (t.pqc_kem ?? "").toLowerCase().includes("mlkem"));
      const hybridBonus = hasHybrid ? 100 : 60;
      const score = scoreFactors(coverage, avgStrength, downgradeResistant, hybridBonus);
      return {
        protocol, score, grade: grade(score),
        factors: {
          coverage: Math.round(coverage * 10) / 10,
          algorithm_strength: Math.round(avgStrength * 10) / 10,
          downgrade_resistant: downgradeResistant,
          hybrid_construction: hybridBonus >= 100,
        },
      };
    }
    if (protocol === "ssh") {
      const rows = sshConnections.filter((c) => c.state === "ESTABLISHED");
      const evaluated = rows.length ? rows : sshConnections;
      const total = evaluated.length || 1;
      const pqc = evaluated.filter((c) => c.pqc_enabled).length;
      const coverage = (pqc / total) * 100;
      const strengths = evaluated.map((c) => algoStrength(c.kex_algorithm));
      const avgStrength = strengths.length ? strengths.reduce((a, b) => a + b, 0) / strengths.length : 0;
      const downgradeResistant = pqc === total && total > 0;
      const hasHybrid = evaluated.some((c) => c.kex_algorithm.toLowerCase().includes("x25519") && c.kex_algorithm.toLowerCase().includes("mlkem"));
      const hybridBonus = hasHybrid ? 100 : 60;
      const score = scoreFactors(coverage, avgStrength, downgradeResistant, hybridBonus);
      return {
        protocol, score, grade: grade(score),
        factors: {
          coverage: Math.round(coverage * 10) / 10,
          algorithm_strength: Math.round(avgStrength * 10) / 10,
          downgrade_resistant: downgradeResistant,
          hybrid_construction: hybridBonus >= 100,
          zero_trust_events: ztEvents.length,
        },
      };
    }
    // tls — downgrade_resistant is unconditionally false: QUANSEC cannot
    // enforce the hybrid group through Python's ssl module, so awarding
    // that factor would claim a guarantee the platform does not have.
    const total = tlsSessions.length;
    if (total === 0) {
      return { protocol, score: 0, grade: "F", factors: { coverage: 0, algorithm_strength: 0, downgrade_resistant: false, hybrid_construction: false } };
    }
    const pqc = tlsSessions.filter((s) => s.pqc_enabled).length;
    const coverage = (pqc / total) * 100;
    const strengths = tlsSessions.map((s) => (s.pqc_enabled ? algoStrength("x25519mlkem768") : algoStrength("x25519")));
    const avgStrength = strengths.reduce((a, b) => a + b, 0) / strengths.length;
    const hybridBonus = pqc === total && total > 0 ? 100 : pqc > 0 ? 60 : 0;
    const score = scoreFactors(coverage, avgStrength, false, hybridBonus);
    return {
      protocol, score, grade: grade(score),
      factors: {
        coverage: Math.round(coverage * 10) / 10,
        algorithm_strength: Math.round(avgStrength * 10) / 10,
        downgrade_resistant: false,
        hybrid_construction: hybridBonus >= 100,
      },
    };
  },
  getOverallScore: () => {
    const ipsec = showcaseStore.getScore("ipsec");
    const ssh = showcaseStore.getScore("ssh");
    const tls = showcaseStore.getScore("tls");
    const overall = Math.round(((ipsec.score + ssh.score + tls.score) / 3) * 10) / 10;
    return {
      overall_score: overall, grade: grade(overall), cnsa_ready: overall >= 90,
      protocols: { ipsec: ipsec.score, ssh: ssh.score, tls: tls.score },
    };
  },

  // Fail mode
  getFailmode: () => ({ ipsec: { ...failmode.ipsec }, ssh: { ...failmode.ssh } }),
  setFailmode: (protocol: "ipsec" | "ssh", mode: string) => {
    failmode[protocol].mode = mode;
    return { status: "applied", protocol, mode };
  },

  // TLS
  getTlsStatus: computeTlsStatus,
  getTlsStats: computeTlsStats,
  getTlsReadiness: computeTlsReadiness,
  getTlsSessions: (limit: number) => tlsSessions.slice(0, limit).map((s) => ({ ...s })),
  getTlsSession: (sessionId: number) => tlsSessions.find((s) => s.id === sessionId) ?? null,
  getTlsEvents: (limit: number) => tlsEvents.slice(0, limit).map((e) => ({ ...e })),
  getTlsPolicy: computeTlsPolicy,
  getTlsCertificate: () => ({ ...tlsCertificate }),
  getTlsSignatureAlgorithms: () => ({ ...tlsSignatureAlgorithms }),
  applyTlsPolicy: () => {
    tlsPolicyApplied = true;
    return { status: "applied" };
  },
  tlsService: (action: string) => ({ status: "ok", action }),
  runTlsProbe: runTlsProbeSuite,
  getTlsProbeHistory: () => tlsProbeHistory,
  testTlsDowngrade: (kind: "hybrid" | "tls12" | "cipher") => runTlsDowngrade(kind),
};

export type ShowcaseStore = typeof showcaseStore;
