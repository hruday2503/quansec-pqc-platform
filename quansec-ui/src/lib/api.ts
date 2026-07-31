// lib/api.ts — QUANSEC API client

const API_BASE = process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";

export interface IPsecStats {
  total_tunnels: number;
  established: number;
  down: number;
  pqc_enabled: number;
  pqc_coverage: number;
  total_bytes_in: number;
  total_bytes_out: number;
  last_updated: string;
}

export interface IPsecTunnel {
  id: number;
  name: string;
  local_host: string;
  remote_host: string;
  state: string;
  ike_version: number;
  ike_proposal: string | null;
  esp_proposal: string | null;
  pqc_kem: string | null;
  pqc_enabled: boolean;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  established_at: string | null;
  last_seen: string;
}

export interface HandshakeEvent {
  tunnel_name: string;
  event_type: string;
  detail: Record<string, unknown>;
  occurred_at: string;
  stage_order: number;
}

export interface PolicyCompareRow {
  field: string;
  classical: string | boolean;
  pqc: string | boolean;
  why_changed: string;
  standard: string;
}

export interface PolicyCompare {
  comparison: PolicyCompareRow[];
  current_policy: string;
  cnsa_deadline: string;
  days_remaining: number;
}

export interface Policy {
  name: string;
  label: string;
  description: string;
  ike_proposal: string;
  esp_proposal: string;
  pqc: boolean;
  algorithms: Record<string, unknown>;
  threat: string | null;
}

export interface AttackResult {
  attack: string;
  result: string;
  [key: string]: unknown;
}

// ── TLS ──────────────────────────────────────────────────────────────────────
//
// Post-quantum status has two independent axes and both must be rendered.
// `availability` says whether the runtime can do the hybrid group and whether a
// real negotiation was verified out of band. `enforcement` says whether hybrid
// is mandatory — it never is today, because Python's ssl module cannot select
// TLS 1.3 groups, so a classical-only client still connects. A high
// availability is therefore NOT a guarantee.
//
// Prefer `label` for display text: it is generated server-side and always
// carries the enforcement qualifier, so the UI cannot accidentally render a
// bare reassurance.

/**
 * TLS types — these mirror protocols/tls/models.py exactly.
 *
 * The status booleans are deliberately NOT collapsed into a single flag. They
 * answer different questions and only some are guarantees:
 *
 *   hybrid_group_configured   we asked NGINX for the hybrid group (an intention)
 *   hybrid_group_negotiated   a real handshake used it (per the NGINX log)
 *   hybrid_only_enforced      classical clients were actually refused
 *
 * Only the third is a guarantee. Rendering the first as "protected" would be a
 * claim the evidence does not support.
 */
export interface TlsStatus {
  enabled: boolean;
  runtime_supported: boolean;
  tls13_enforced: boolean;
  hybrid_group_configured: boolean;
  hybrid_group_negotiated: boolean;
  hybrid_only_enforced: boolean;
  certificate_verified: boolean;
  mtls_enabled: boolean;
  /** The CERTIFICATE's signature algorithm. Hybrid key exchange does not set this. */
  authentication_quantum_safe: boolean;
  overall_status:
    | "unavailable"
    | "classical"
    | "configured_unproven"
    | "hybrid_observed"
    | "hybrid_enforced"
    | "degraded";
  label: string;
  service: {
    host: string;
    port: number;
    running: boolean;
    pid: number | null;
    listening: boolean;
    config_path: string | null;
    config_sha256: string | null;
    error: string | null;
  };
  build: {
    runtime_dir: string;
    nginx_binary: string;
    nginx_version: string | null;
    /** The load-bearing value: NGINX built against 3.0 cannot enforce the group. */
    nginx_openssl: string | null;
    openssl_binary: string;
    openssl_version: string | null;
    system_openssl: string | null;
    hybrid_group_available: boolean;
    runtime_built: boolean;
  };
  evidence: {
    observed_hybrid_sessions: number;
    probe_results: Record<string, boolean>;
    configured_groups: string;
    configured_protocols: string | null;
    configured_ciphersuites: string | null;
    config_sha256: string | null;
    [key: string]: unknown;
  };
  last_updated: string;
}

/**
 * Aggregates over observed sessions. Mirrors TlsStatsResponse in
 * protocols/tls/models.py field for field.
 *
 * `pqc_coverage` is a share of what was OBSERVED. It is not enforcement — a
 * hundred percent coverage still permits a classical client unless
 * TlsStatus.hybrid_only_enforced is true.
 */
export interface TlsStats {
  /** One CONNECTION, not one request. Keep-alive requests share a session. */
  total_sessions: number;
  /**
   * Seen within `active_window_seconds`. NGINX logs no connection-close event,
   * so liveness can only ever be inferred from recency.
   */
  active_sessions: number;
  hybrid_sessions: number;
  classical_sessions: number;
  /** No group recorded. A resumed session performs no key exchange — not classical. */
  unknown_sessions: number;
  /**
   * Percentage of sessions WITH a recorded group that were hybrid. Unknown-group
   * sessions are excluded from the denominator, not counted as classical.
   */
  hybrid_coverage: number;
  tls13_coverage: number;
  /**
   * Probes that expected to connect and did not. A refused handshake writes no
   * access-log line, so this is not countable from the log; an HTTP 5xx is a
   * failed request on a SUCCESSFUL handshake and is excluded.
   */
  failed_handshakes: number;
  active_alerts: number;
  last_observed_at: string | null;
  /** False when nothing has ever been recorded — a measured zero vs an empty table. */
  has_evidence: boolean;
  active_window_seconds: number;
}

export interface TlsReadinessCheck {
  check: string;
  passed: boolean;
  detail: string;
}

export interface TlsReadiness {
  ready: boolean;
  checks: TlsReadinessCheck[];
  blocking: string[];
  warnings: string[];
  runtime: Record<string, unknown>;
}

/** One session, parsed from a line NGINX wrote. Never synthesised. */
export interface TlsSession {
  id: number;
  occurred_at: string;
  remote_addr: string | null;
  remote_port: string | null;
  tls_protocol: string | null;
  cipher: string | null;
  /** $ssl_curve as logged. Null for a resumed session, which performs no key exchange. */
  negotiated_group: string | null;
  client_groups: string | null;
  client_verify: string | null;
  client_s_dn: string | null;
  server_name: string | null;
  session_reused: boolean;
  http_status: number | null;
  request_time: number | null;
  bytes_sent: number | null;
  request_line: string | null;
  pqc_enabled: boolean;
  kem_label: string | null;
  log_source: string | null;
  log_offset: number | null;
  recorded_at: string | null;
  raw_line?: string | null;

  /** Namespaced `<listener_port>:<$connection>`. Null on pre-010 rows. */
  connection_id: string | null;
  /** Null means NGINX reported no group — not the same as classical. */
  hybrid_negotiated: boolean | null;
  mtls_enabled: boolean;
  /** Null when no client certificate was requested: no check, not a failed one. */
  client_certificate_verified: boolean | null;
  certificate_signature_algorithm: string | null;
  started_at: string | null;
  last_seen: string | null;
  request_count: number;
  evidence_source: string | null;
}

export interface TlsEvent {
  id: number;
  event_type: string;
  severity: "info" | "warning" | "critical";
  summary: string;
  detail: Record<string, unknown> | null;
  occurred_at: string;
}

export interface TlsPolicyView {
  source: string;
  protocols: string;
  groups: string;
  ciphersuites: string;
  mtls: boolean;
  early_data: boolean;
  listen: string | null;
  config_sha256: string | null;
  tls13_only: boolean;
  hybrid_group_only: boolean;
  fail_closed: boolean;
  fallback_groups: string[];
}

export interface TlsPolicy {
  intended: TlsPolicyView;
  /** Null when no nginx.conf has been rendered — distinct from "running something else". */
  running: TlsPolicyView | null;
  drift: {
    in_sync: boolean;
    reason: string;
    detail: string;
    differences: { field: string; intended: unknown; running: unknown }[];
    intended_sha256?: string | null;
    running_sha256?: string | null;
  };
  active_state: Record<string, unknown> | null;
  fail_closed: boolean;
}

export interface TlsCertificate {
  server_name: string;
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  signature_algorithm: string | null;
  public_key_algorithm: string | null;
  key_size: number | null;
  san: string[];
  not_before: string | null;
  not_after: string | null;
  days_until_expiry: number | null;
  chain_verified: boolean;
  pqc_signature: boolean;
  authentication_class: string;
  note: string;
}

export interface TlsSignatureAlgorithms {
  openssl_binary: string;
  total_advertised: number;
  ml_dsa_advertised: string[];
  ml_dsa_available: boolean;
  note: string;
}

/** `passed` is relative to `expected_outcome`: a negative probe passes when REFUSED. */
export interface TlsProbeResult {
  probe_type: string;
  expected_outcome: "connect" | "reject";
  actual_outcome: "connect" | "reject" | "error";
  passed: boolean;
  description: string;
  target_host: string;
  target_port: number;
  negotiated_group: string | null;
  negotiated_cipher: string | null;
  tls_protocol: string | null;
  verify_result: string | null;
  http_status: number | null;
  openssl_binary: string;
  openssl_version: string | null;
  command: string;
  exit_code: number | null;
  stdout_excerpt: string | null;
  evidence_path: string | null;
  duration_ms: number | null;
  run_at: string | null;
}

export interface TlsProbeSuite {
  total: number;
  passed: number;
  failed: number;
  results: TlsProbeResult[];
  /** The only field that justifies showing "ENFORCED". */
  enforcement_proven: boolean;
  summary: string;
}

export interface TlsDowngradeTest {
  test: string;
  /** True means the downgrade attempt FAILED — the desired outcome. */
  rejected: boolean;
  description: string;
  results: TlsProbeResult[];
  verdict: string;
}

// ── API keys ─────────────────────────────────────────────────────────────

export interface ApiKey {
  id: number;
  name: string;
  /** Already masked by the backend. The hash is never returned. */
  key_prefix: string;
  scopes: string[];
  protocol: string | null;
  last_used: string | null;
  created_at: string;
  /** Null only for a non-expiring key, which requires system:admin to issue. */
  expires_at: string | null;
  revoked: boolean;
  expired: boolean;
}

/** Revoked and expired are different terminal states and are shown as such. */
export type ApiKeyState = "active" | "expired" | "revoked";

export function apiKeyState(key: ApiKey): ApiKeyState {
  if (key.revoked) return "revoked";
  if (key.expired) return "expired";
  return "active";
}

export interface ApiKeyCreated {
  id: number;
  name: string;
  /** Returned once and never again. Only its SHA-256 hash is stored. */
  api_key: string;
  key_prefix: string;
  scopes: string[];
  protocol: string | null;
  created_at: string;
  expires_at: string | null;
  warning: string;
}

/** GET /api/keys/scopes — exactly what the caller may put on a key. */
export interface GrantableScopes {
  grantable: string[];
  descriptions: Record<string, string>;
}

/** The only scopes the TLS portal offers. Server-side the request is still
 *  intersected with the caller's own authority, so this list is convenience,
 *  never the control. */
export const TLS_KEY_SCOPES = [
  {
    scope: "tls:read",
    label: "Read",
    detail: "Status, stats, sessions, events, policy and readiness.",
  },
  {
    scope: "tls:probe",
    label: "Probe",
    detail: "Run enforcement probes and validation tests. Implies read. Cannot change policy.",
  },
  {
    scope: "tls:admin",
    label: "Admin",
    detail: "Apply and roll back policy, control the data plane. Implies read and probe.",
  },
] as const;

class QuansecClient {
  /** In memory only. Never persisted. */
  private token: string | null = null;
  /** Read from the readable CSRF cookie; echoed on cookie-authenticated calls. */
  private csrfToken: string | null = null;
  /** De-duplicates concurrent refreshes so parallel 401s trigger only one. */
  private refreshInFlight: Promise<boolean> | null = null;

  private readonly LEGACY_TOKEN_KEY = "quansec_token";

  setToken(token: string) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  /**
   * Deprecated. Older pages call this expecting a token from localStorage.
   * Retained so they compile, but it no longer reads storage — use `restore()`.
   */
  loadToken(): string | null {
    return this.token;
  }

  clearToken() {
    this.token = null;
    this.csrfToken = null;
    this.purgeLegacyStorage();
  }

  /** Remove any access token left in localStorage by an older build. */
  private purgeLegacyStorage() {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.removeItem(this.LEGACY_TOKEN_KEY);
      window.sessionStorage.removeItem(this.LEGACY_TOKEN_KEY);
    } catch {
      /* storage disabled — nothing to purge */
    }
  }

  /** The CSRF cookie is deliberately readable; that is how double-submit works. */
  private readCsrfCookie(): string | null {
    if (typeof document === "undefined") return null;
    const match = document.cookie.match(/(?:^|;\s*)quansec_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  }

  private csrfHeaders(): Record<string, string> {
    const value = this.csrfToken ?? this.readCsrfCookie();
    return value ? { "X-CSRF-Token": value } : {};
  }

  /**
   * Re-establish a session after a page load, using the refresh cookie.
   * Returns false when there is no usable session and the user must log in.
   */
  async restore(): Promise<boolean> {
    this.purgeLegacyStorage();
    return this.refresh();
  }

  /**
   * Exchange the refresh cookie for a new access token.
   *
   * Concurrent callers share one in-flight request: the refresh token rotates
   * on every use, so two parallel refreshes would make the second present an
   * already-rotated token and trip the reuse detector, logging the user out.
   */
  async refresh(): Promise<boolean> {
    if (this.refreshInFlight) return this.refreshInFlight;

    this.refreshInFlight = (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/auth/refresh`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json", ...this.csrfHeaders() },
          body: "{}",
        });
        if (!res.ok) {
          this.token = null;
          return false;
        }
        const data = await res.json();
        this.token = data.access_token;
        if (data.csrf_token) this.csrfToken = data.csrf_token;
        return true;
      } catch {
        this.token = null;
        return false;
      } finally {
        this.refreshInFlight = null;
      }
    })();

    return this.refreshInFlight;
  }

  /**
   * Perform an authenticated request, refreshing once on a 401.
   *
   * The retry is what makes a 15-minute access token invisible to the user: the
   * token expires mid-session, one call fails, the cookie buys a new one, and
   * the call succeeds. `retry` guards against looping when the session is
   * genuinely dead.
   */
  private async request<T>(
    path: string,
    options: RequestInit = {},
    retry = true
  ): Promise<T> {
    const send = () =>
      fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: "include",
        headers: {
          ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...options.headers,
        },
      });

    let res = await send();

    if (res.status === 401 && retry) {
      if (await this.refresh()) {
        res = await send();
      }
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`${res.status}: ${body}`);
    }
    return res.json();
  }

  async login(email: string, password: string, portal?: string) {
    const base = portal
      ? `${API_BASE}/api/auth/login-scoped?portal=${encodeURIComponent(portal)}`
      : `${API_BASE}/api/auth/login`;
    // use_cookie=true: the refresh token comes back as an HttpOnly cookie and
    // is deliberately absent from the response body.
    const url = `${base}${base.includes("?") ? "&" : "?"}use_cookie=true`;

    const res = await fetch(url, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`,
    });
    if (!res.ok) {
      // The backend returns one generic message for every credential failure,
      // so there is nothing more specific to surface here.
      throw new Error("Login failed");
    }

    const data = await res.json();
    this.token = data.access_token;
    this.csrfToken = data.csrf_token ?? null;
    this.purgeLegacyStorage();
    return data;
  }

  /** Revoke this session server-side and clear local state. */
  async logout() {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", ...this.csrfHeaders() },
        body: "{}",
      });
    } catch {
      /* clear local state regardless */
    }
    this.clearToken();
  }

  /** Revoke every session for this user, on all devices. */
  async revokeAll() {
    const result = await this.request<{ revoked: number; detail: string }>(
      "/api/auth/revoke-all",
      { method: "POST" }
    );
    this.clearToken();
    return result;
  }

  /** Live sessions for the current user. */
  async sessions() {
    return this.request<Record<string, unknown>[]>("/api/auth/sessions");
  }

  async me() {
    return this.request<{
      id: number;
      email: string;
      role: string;
      portal: string | null;
      scopes: string[];
      scope_descriptions: Record<string, string>;
      auth_method: string;
    }>("/api/auth/me");
  }

  async getStats() {
    return this.request<IPsecStats>("/api/ipsec/stats");
  }

  async getTunnels() {
    return this.request<IPsecTunnel[]>("/api/ipsec/tunnels");
  }

  async getHandshakes(limit = 20) {
    return this.request<HandshakeEvent[]>(`/api/ipsec/handshakes?limit=${limit}`);
  }

  async getPolicies() {
    return this.request<Policy[]>("/api/ipsec/policies");
  }

  async getCompare() {
    return this.request<PolicyCompare>("/api/ipsec/policies/compare");
  }

  async applyPolicy(policyName: string, tunnelName = "pqc-tunnel") {
    return this.request<{ status: string; policy: string; pqc_enabled: boolean }>(
      "/api/ipsec/policies/apply",
      { method: "POST", body: JSON.stringify({ policy_name: policyName, tunnel_name: tunnelName }) }
    );
  }

  async runAttack(name: string) {
    return this.request<AttackResult>(`/api/ipsec/attacks/${name}`, { method: "POST" });
  }

  async getAttackResults() {
    return this.request<{ detail: AttackResult; severity: string; occurred_at: string }[]>(
      "/api/ipsec/attacks/results"
    );
  }

  // ── TLS ────────────────────────────────────────────────────────────────
  //
  // These mirror protocols/tls/router.py. The endpoints of the earlier
  // Python-`ssl` generation (/test-connection, /session, /policies/compare,
  // /hybrid/verify) no longer exist and returned 404; the NGINX data plane
  // replaced them with evidence-derived equivalents.

  /** The nine evidence-derived status fields. */
  async getTlsStatus() {
    return this.request<TlsStatus>("/api/tls/status");
  }

  /** Counts and percentiles over the sessions the collector has recorded. */
  async getTlsStats() {
    return this.request<TlsStats>("/api/tls/stats");
  }

  /** Whether the data plane can be relied on, and what is blocking it. */
  async getTlsReadiness() {
    return this.request<TlsReadiness>("/api/tls/readiness");
  }

  /** Observed sessions, each parsed from a real NGINX log line. */
  async getTlsSessions(limit = 50) {
    return this.request<TlsSession[]>(`/api/tls/sessions?limit=${limit}`);
  }

  /** One session, including the raw log line it came from. */
  async getTlsSession(id: number) {
    return this.request<TlsSession>(`/api/tls/sessions/${id}`);
  }

  /** Service, policy and probe lifecycle events. */
  async getTlsEvents(limit = 50) {
    return this.request<TlsEvent[]>(`/api/tls/events?limit=${limit}`);
  }

  /** Intended vs running policy, and the drift between them. */
  async getTlsPolicy() {
    return this.request<TlsPolicy>("/api/tls/policy");
  }

  /** Certificate facts. Authentication is reported separately from key exchange. */
  async getTlsCertificate() {
    return this.request<TlsCertificate>("/api/tls/certificate");
  }

  /** What the runtime OpenSSL advertises — input to the ML-DSA research profile. */
  async getTlsSignatureAlgorithms() {
    return this.request<TlsSignatureAlgorithms>("/api/tls/signature-algorithms");
  }

  // ── Admin actions (tls:admin) ──────────────────────────────────────────

  /** Render, validate and reload the policy. */
  async applyTlsPolicy(reload = true) {
    return this.request<Record<string, unknown>>("/api/tls/policy/apply", {
      method: "POST",
      body: JSON.stringify({ reload }),
    });
  }

  /** Control the NGINX data plane. */
  async tlsService(action: "start" | "stop" | "reload") {
    return this.request<Record<string, unknown>>(`/api/tls/service/${action}`, {
      method: "POST",
    });
  }

  /**
   * Run enforcement probes. Omit `probeType` for the whole standard suite.
   *
   * A negative probe PASSES when the handshake is refused — that asymmetry is
   * the point, and `enforcement_proven` is the only field that justifies
   * showing enforcement in the UI.
   */
  async runTlsProbe(probeType?: string, includeMtls = false) {
    return this.request<TlsProbeSuite>("/api/tls/probe", {
      method: "POST",
      body: JSON.stringify({ probe_type: probeType ?? null, include_mtls: includeMtls }),
    });
  }

  /** The mandatory fail-closed proof: X25519-only AND prime256v1-only refused. */
  async testHybridDowngrade() {
    return this.request<TlsDowngradeTest>("/api/tls/tests/hybrid-downgrade", {
      method: "POST",
    });
  }

  async testTls12Downgrade() {
    return this.request<TlsDowngradeTest>("/api/tls/tests/tls12-downgrade", {
      method: "POST",
    });
  }

  async testCipherDowngrade() {
    return this.request<TlsDowngradeTest>("/api/tls/tests/cipher-downgrade", {
      method: "POST",
    });
  }

  // ── API keys ───────────────────────────────────────────────────────────

  async listApiKeys() {
    return this.request<ApiKey[]>("/api/keys");
  }

  /**
   * Generate an API key. The raw key is returned ONCE and never again.
   *
   * `scopes` may only narrow the caller's own authority — the backend
   * intersects the request with the owner's role scopes, so a key can never
   * grant more than the user who created it holds. Omitted or empty means the
   * backend grants the caller's `:read` scopes only, per auth_api_keys.py.
   */
  async createApiKey(name: string, scopes: string[] = []) {
    return this.request<ApiKeyCreated>("/api/keys", {
      method: "POST",
      body: JSON.stringify({ name, scopes }),
    });
  }

  async revokeApiKey(id: number) {
    return this.request<{ status: string; key_id: number }>(`/api/keys/${id}`, {
      method: "DELETE",
    });
  }

  // ── TLS-scoped API keys ────────────────────────────────────────────────
  //
  // Thin wrappers over the same /api/keys routes, pinned to protocol=tls.
  // There is no separate TLS key store: a key is one row in api_keys, and
  // `protocol` records which portal issued it. Enforcement is always by
  // scope, never by protocol — a tls-labelled key holding only ssh:read
  // still cannot read TLS endpoints.

  /**
   * Create a TLS API key. The raw value comes back ONCE.
   *
   * `expiresInDays` omitted uses the backend's 90-day default. Passing
   * `neverExpires` requires system:admin and is rejected with 403 otherwise —
   * the UI offers it only to those who hold it, but the server is the check.
   */
  async createTlsApiKey(
    name: string,
    scopes: string[],
    opts: { expiresInDays?: number; neverExpires?: boolean } = {}
  ) {
    return this.request<ApiKeyCreated>("/api/keys", {
      method: "POST",
      body: JSON.stringify({
        name,
        scopes,
        protocol: "tls",
        expires_in_days: opts.expiresInDays ?? null,
        never_expires: opts.neverExpires ?? false,
      }),
    });
  }

  /** TLS keys only, masked. Includes revoked and expired so the page can
   *  show terminal states rather than silently dropping them. */
  async listTlsApiKeys() {
    return this.request<ApiKey[]>("/api/keys?protocol=tls&include_revoked=true");
  }

  async revokeTlsApiKey(id: number) {
    return this.request<{ status: string; key_id: number }>(`/api/keys/${id}`, {
      method: "DELETE",
    });
  }

  /** Which scopes the caller may actually grant. The page uses this to
   *  disable options rather than letting the user hit a 403. */
  async getGrantableScopes() {
    return this.request<GrantableScopes>("/api/keys/scopes");
  }

  connectLiveSocket(onMessage: (data: Record<string, unknown>) => void): WebSocket | null {
    if (typeof window === "undefined") return null;
    const wsBase = API_BASE.replace("http", "ws");
    const ws = new WebSocket(`${wsBase}/api/ws/live`);
    ws.onmessage = (event) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        // ignore malformed
      }
    };
    return ws;
  }
}

export const quansec = new QuansecClient();
