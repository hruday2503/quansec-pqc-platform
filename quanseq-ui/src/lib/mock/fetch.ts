import { SHOWCASE_MODE, showcaseLatency } from "./mode";
import { showcaseStore } from "./store";

const REAL_API_BASE = process.env.NEXT_PUBLIC_QUANSEQ_API || "http://localhost:8000";

function parseBody(init?: RequestInit): Record<string, unknown> {
  if (!init?.body) return {};
  try {
    return JSON.parse(String(init.body));
  } catch {
    return {};
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Routes a raw API path (as used by the SSH pages and other direct-fetch
 * call sites) to the showcase store. Every value returned here comes from
 * the same store the typed QUANSEQ client reads, so a count shown on one
 * page always matches the same count shown on another.
 */
function routeShowcase(path: string, init?: RequestInit): Response {
  const [pathname, search] = path.split("?");
  const query = new URLSearchParams(search ?? "");
  const method = (init?.method ?? "GET").toUpperCase();

  // ── SSH ──────────────────────────────────────────────────────────────
  if (pathname === "/api/ssh/stats" && method === "GET") return json(showcaseStore.getSshStats());
  if (pathname === "/api/ssh/connections" && method === "GET") return json(showcaseStore.getSshConnections());
  const sshAttack = pathname.match(/^\/api\/ssh\/attacks\/(.+)$/);
  if (sshAttack && method === "POST") return json(showcaseStore.runSshAttack(sshAttack[1]));
  if (pathname === "/api/ssh/policies" && method === "GET") return json(showcaseStore.getSshPolicies());
  if (pathname === "/api/ssh/policies/compare" && method === "GET") return json(showcaseStore.getSshCompare());
  if (pathname === "/api/ssh/policies/apply" && method === "POST") {
    const body = parseBody(init);
    return json(showcaseStore.applySshPolicy(String(body.policy_name ?? "")));
  }
  if (pathname === "/api/ssh/ca/info" && method === "GET") return json(showcaseStore.getCaInfo());
  if (pathname === "/api/ssh/ca/issued" && method === "GET") return json(showcaseStore.getCaIssued());
  if (pathname === "/api/ssh/ca/issue" && method === "POST") {
    const body = parseBody(init);
    return json(
      showcaseStore.issueCaCert(
        String(body.public_key ?? ""),
        String(body.identity ?? ""),
        String(body.principals ?? ""),
        Number(body.valid_hours ?? 8)
      )
    );
  }
  if (pathname === "/api/ssh/zt/events" && method === "GET") return json(showcaseStore.getZtEvents());
  if (pathname === "/api/ssh/zt/status" && method === "GET") return json(showcaseStore.getZtStatus());
  if (pathname === "/api/ssh/zt/policy" && method === "GET") return json(showcaseStore.getZtPolicy());

  // ── Shared API keys ──────────────────────────────────────────────────
  if (pathname === "/api/keys" && method === "GET") {
    const protocol = query.get("protocol") ?? undefined;
    const includeRevoked = query.get("include_revoked") === "true";
    return json(showcaseStore.listApiKeys(protocol, includeRevoked || !protocol));
  }
  if (pathname === "/api/keys" && method === "POST") {
    const body = parseBody(init);
    return json(
      showcaseStore.createApiKey(
        String(body.name ?? ""),
        Array.isArray(body.scopes) ? (body.scopes as string[]) : [],
        (body.protocol as string | undefined) ?? null,
        (body.expires_in_days as number | undefined) ?? null,
        Boolean(body.never_expires)
      )
    );
  }
  const keyDelete = pathname.match(/^\/api\/keys\/(\d+)$/);
  if (keyDelete && method === "DELETE") return json(showcaseStore.revokeApiKey(Number(keyDelete[1])));
  if (pathname === "/api/keys/scopes" && method === "GET") return json(showcaseStore.getGrantableScopes());

  // ── Alerts ───────────────────────────────────────────────────────────
  if (pathname === "/api/alerts" && method === "GET") return json(showcaseStore.getAlerts());
  const ack = pathname.match(/^\/api\/alerts\/(\d+)\/ack$/);
  if (ack && method === "POST") return json(showcaseStore.ackAlert(Number(ack[1])));

  // ── Scoring ──────────────────────────────────────────────────────────
  if (pathname === "/api/scoring/overall" && method === "GET") return json(showcaseStore.getOverallScore());
  const scoring = pathname.match(/^\/api\/scoring\/(ipsec|ssh|tls)$/);
  if (scoring && method === "GET") return json(showcaseStore.getScore(scoring[1] as "ipsec" | "ssh" | "tls"));

  // ── Fail mode ────────────────────────────────────────────────────────
  if (pathname === "/api/failmode" && method === "GET") return json(showcaseStore.getFailmode());
  if (pathname === "/api/failmode/set" && method === "POST") {
    const body = parseBody(init);
    return json(showcaseStore.setFailmode(body.protocol as "ipsec" | "ssh", String(body.mode ?? "")));
  }

  return json({ detail: `No showcase route for ${method} ${pathname}` }, 404);
}

/**
 * Drop-in replacement for `fetch(\`${API_BASE}${path}\`, init)`. In showcase
 * mode it never touches the network; otherwise it behaves exactly like the
 * call it replaces.
 */
export async function mockFetch(path: string, init?: RequestInit): Promise<Response> {
  if (!SHOWCASE_MODE) {
    return fetch(`${REAL_API_BASE}${path}`, init);
  }
  await showcaseLatency();
  return routeShowcase(path, init);
}
