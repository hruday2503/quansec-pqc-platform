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

export interface ApiKey {
  id: number;
  name: string;
  key_prefix: string;
  scopes: string[];
  last_used: string | null;
  created_at: string;
  revoked: boolean;
}

export interface ApiKeyCreated extends ApiKey {
  api_key: string;
  warning: string;
}

class QuansecClient {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
    if (typeof window !== "undefined") {
      localStorage.setItem("quansec_token", token);
    }
  }

  loadToken(): string | null {
    if (typeof window !== "undefined") {
      this.token = localStorage.getItem("quansec_token");
    }
    return this.token;
  }

  clearToken() {
    this.token = null;
    if (typeof window !== "undefined") {
      localStorage.removeItem("quansec_token");
    }
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`${res.status}: ${body}`);
    }
    return res.json();
  }

  async login(email: string, password: string, portal?: string) {
    const url = portal
      ? `${API_BASE}/api/auth/login-scoped?portal=${encodeURIComponent(portal)}`
      : `${API_BASE}/api/auth/login`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`,
    });
    if (!res.ok) throw new Error("Login failed");
    const data = await res.json();
    this.setToken(data.access_token);
    return data;
  }

  async me() {
    return this.request<{ id: number; email: string; role: string }>("/api/auth/me");
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

  async createApiKey(name: string, scopes: string[] = ["read"]) {
    return this.request<ApiKeyCreated>("/api/keys", {
      method: "POST",
      body: JSON.stringify({ name, scopes }),
    });
  }

  async listApiKeys() {
    return this.request<ApiKey[]>("/api/keys");
  }

  async revokeApiKey(id: number) {
    return this.request<{ status: string }>(`/api/keys/${id}`, { method: "DELETE" });
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
