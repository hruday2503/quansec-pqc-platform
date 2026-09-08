import type {
  IPsecStats, IPsecTunnel, HandshakeEvent, Policy, PolicyCompare, AttackResult,
  TlsStatus, TlsStats, TlsReadiness, TlsSession, TlsEvent, TlsPolicy, TlsCertificate,
  TlsSignatureAlgorithms, TlsProbeSuite, TlsDowngradeTest, ApiKey, ApiKeyCreated, GrantableScopes,
} from "@/lib/api";
import { showcaseStore } from "./store";
import { showcaseLatency } from "./mode";

const SESSION_KEY = "quansec_showcase_session";

interface ShowcaseSession {
  id: number;
  email: string;
  role: string;
  portal: string | null;
}

function readSession(): ShowcaseSession | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as ShowcaseSession) : null;
  } catch {
    return null;
  }
}

function writeSession(session: ShowcaseSession) {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    /* storage disabled — session just won't survive a reload */
  }
}

function clearSession() {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(SESSION_KEY);
  } catch {
    /* nothing to clear */
  }
}

const SHOWCASE_SCOPES = [
  "ipsec:read", "ipsec:admin", "ssh:read", "ssh:admin",
  "tls:read", "tls:probe", "tls:admin", "system:admin",
];

/**
 * Serves every QuansecClient method from the in-memory showcase store instead
 * of the network. Method signatures mirror QuansecClient exactly so this can
 * be swapped in for it at the export site in lib/api.ts.
 */
export class MockQuansecClient {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }
  getToken(): string | null {
    return this.token;
  }
  loadToken(): string | null {
    return this.token;
  }
  clearToken() {
    this.token = null;
    clearSession();
  }

  async restore(): Promise<boolean> {
    await showcaseLatency(60, 180);
    const session = readSession();
    if (!session) return false;
    this.token = "showcase-token";
    return true;
  }

  async refresh(): Promise<boolean> {
    return this.restore();
  }

  async login(email: string, _password: string, portal?: string) {
    await showcaseLatency();
    const session: ShowcaseSession = { id: 1, email, role: "admin", portal: portal ?? null };
    writeSession(session);
    this.token = "showcase-token";
    return { access_token: this.token, csrf_token: "showcase-csrf" };
  }

  async logout() {
    await showcaseLatency(60, 150);
    this.clearToken();
  }

  async revokeAll() {
    await showcaseLatency();
    this.clearToken();
    return { revoked: 1, detail: "All sessions revoked." };
  }

  async sessions() {
    await showcaseLatency();
    return [{ current: true, created_at: new Date().toISOString() }];
  }

  async me() {
    await showcaseLatency(60, 180);
    const session = readSession() ?? { id: 1, email: "admin@quansec.io", role: "admin", portal: null };
    return {
      id: session.id,
      email: session.email,
      role: session.role,
      portal: session.portal,
      scopes: SHOWCASE_SCOPES,
      scope_descriptions: showcaseStore.getGrantableScopes().descriptions,
      auth_method: "password",
    };
  }

  // ── IPsec ────────────────────────────────────────────────────────────
  async getStats(): Promise<IPsecStats> {
    await showcaseLatency();
    return showcaseStore.getIpsecStats();
  }
  async getTunnels(): Promise<IPsecTunnel[]> {
    await showcaseLatency();
    return showcaseStore.getIpsecTunnels();
  }
  async getHandshakes(_limit = 20): Promise<HandshakeEvent[]> {
    await showcaseLatency();
    return [];
  }
  async getPolicies(): Promise<Policy[]> {
    await showcaseLatency();
    return showcaseStore.getIpsecPolicies();
  }
  async getCompare(): Promise<PolicyCompare> {
    await showcaseLatency();
    return showcaseStore.getIpsecCompare();
  }
  async applyPolicy(policyName: string, _tunnelName = "pqc-tunnel") {
    await showcaseLatency(200, 500);
    return showcaseStore.applyIpsecPolicy(policyName);
  }
  async runAttack(name: string): Promise<AttackResult> {
    await showcaseLatency(300, 900);
    return showcaseStore.runIpsecAttack(name);
  }
  async getAttackResults() {
    await showcaseLatency();
    return [];
  }

  // ── TLS ──────────────────────────────────────────────────────────────
  async getTlsStatus(): Promise<TlsStatus> {
    await showcaseLatency();
    return showcaseStore.getTlsStatus();
  }
  async getTlsStats(): Promise<TlsStats> {
    await showcaseLatency();
    return showcaseStore.getTlsStats();
  }
  async getTlsReadiness(): Promise<TlsReadiness> {
    await showcaseLatency();
    return showcaseStore.getTlsReadiness();
  }
  async getTlsSessions(limit = 50): Promise<TlsSession[]> {
    await showcaseLatency();
    return showcaseStore.getTlsSessions(limit);
  }
  async getTlsSession(id: number): Promise<TlsSession> {
    await showcaseLatency();
    const session = showcaseStore.getTlsSession(id);
    if (!session) throw new Error("404: session not found");
    return session;
  }
  async getTlsEvents(limit = 50): Promise<TlsEvent[]> {
    await showcaseLatency();
    return showcaseStore.getTlsEvents(limit);
  }
  async getTlsPolicy(): Promise<TlsPolicy> {
    await showcaseLatency();
    return showcaseStore.getTlsPolicy();
  }
  async getTlsCertificate(): Promise<TlsCertificate> {
    await showcaseLatency();
    return showcaseStore.getTlsCertificate();
  }
  async getTlsSignatureAlgorithms(): Promise<TlsSignatureAlgorithms> {
    await showcaseLatency();
    return showcaseStore.getTlsSignatureAlgorithms();
  }
  async applyTlsPolicy(_reload = true) {
    await showcaseLatency(200, 500);
    return showcaseStore.applyTlsPolicy();
  }
  async tlsService(action: "start" | "stop" | "reload") {
    await showcaseLatency(200, 500);
    return showcaseStore.tlsService(action);
  }
  async runTlsProbe(_probeType?: string, _includeMtls = false): Promise<TlsProbeSuite> {
    await showcaseLatency(400, 1100);
    return showcaseStore.runTlsProbe();
  }
  async testHybridDowngrade(): Promise<TlsDowngradeTest> {
    await showcaseLatency(400, 1100);
    return showcaseStore.testTlsDowngrade("hybrid");
  }
  async testTls12Downgrade(): Promise<TlsDowngradeTest> {
    await showcaseLatency(400, 1100);
    return showcaseStore.testTlsDowngrade("tls12");
  }
  async testCipherDowngrade(): Promise<TlsDowngradeTest> {
    await showcaseLatency(400, 1100);
    return showcaseStore.testTlsDowngrade("cipher");
  }

  // ── API keys ─────────────────────────────────────────────────────────
  async listApiKeys(): Promise<ApiKey[]> {
    await showcaseLatency();
    return showcaseStore.listApiKeys();
  }
  async createApiKey(name: string, scopes: string[] = []): Promise<ApiKeyCreated> {
    await showcaseLatency(200, 500);
    return showcaseStore.createApiKey(name, scopes, null, null, false);
  }
  async revokeApiKey(id: number) {
    await showcaseLatency();
    return showcaseStore.revokeApiKey(id);
  }

  async createTlsApiKey(
    name: string,
    scopes: string[],
    opts: { expiresInDays?: number; neverExpires?: boolean } = {}
  ): Promise<ApiKeyCreated> {
    await showcaseLatency(200, 500);
    return showcaseStore.createApiKey(name, scopes, "tls", opts.expiresInDays ?? null, opts.neverExpires ?? false);
  }
  async listTlsApiKeys(): Promise<ApiKey[]> {
    await showcaseLatency();
    return showcaseStore.listApiKeys("tls", true);
  }
  async revokeTlsApiKey(id: number) {
    await showcaseLatency();
    return showcaseStore.revokeApiKey(id);
  }
  async getGrantableScopes(): Promise<GrantableScopes> {
    await showcaseLatency();
    return showcaseStore.getGrantableScopes();
  }

  connectLiveSocket(onMessage: (data: Record<string, unknown>) => void) {
    if (typeof window === "undefined") return null;
    // No real socket in showcase mode — a lightweight timer stands in for it
    // so the "LIVE" indicator and periodic refresh still work.
    const timers: ReturnType<typeof setTimeout>[] = [];
    timers.push(setTimeout(() => onMessage({ type: "connected" }), 300));
    const interval = setInterval(() => {
      onMessage({ kind: "lifecycle", event: "tunnel_traffic", occurred_at: new Date().toISOString() });
    }, 6000);
    return {
      close: () => {
        timers.forEach(clearTimeout);
        clearInterval(interval);
      },
      onclose: null as (() => void) | null,
      onerror: null as (() => void) | null,
    } as unknown as WebSocket;
  }
}
