/**
 * auth-fetch — authenticated fetch for pages that call the API directly.
 *
 * Replaces the per-page `authHeaders()` helpers that each read the access token
 * from `localStorage`. The token now lives in memory on the `quansec` client
 * singleton, so there is one place that holds it and one place that refreshes
 * it.
 *
 * `authedFetch` retries once after a silent refresh when a call comes back 401.
 * Access tokens last 15 minutes, so without that a user sitting on a dashboard
 * would be bounced to the login page mid-session; with it, the expiry is
 * invisible.
 *
 *     const res = await authedFetch("/api/ssh/stats");
 *
 * Pass a path, not a full URL — the API base is applied here.
 */

import { quansec } from "./api";

export const API_BASE =
  process.env.NEXT_PUBLIC_QUANSEC_API || "http://localhost:8000";

/**
 * Authorization header for the current in-memory access token.
 *
 * Returns an empty object when there is no token — the request then gets a 401,
 * which is the correct outcome and is handled by `authedFetch`.
 */
export function authHeaders(): Record<string, string> {
  const token = quansec.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Fetch an API path with the access token attached, refreshing once on 401.
 *
 * `credentials: "include"` is required so the HttpOnly refresh cookie reaches
 * /api/auth when a refresh becomes necessary.
 */
export async function authedFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const send = () =>
    fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: "include",
      headers: { ...authHeaders(), ...options.headers },
    });

  const res = await send();
  if (res.status !== 401) return res;

  // Expired or absent access token — try the refresh cookie once.
  const refreshed = await quansec.refresh();
  return refreshed ? send() : res;
}

/**
 * `authedFetch` plus JSON parsing, throwing on a non-2xx response.
 *
 * Most callers want this; use `authedFetch` when the status code itself
 * matters.
 */
export async function authedJson<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await authedFetch(path, options);
  if (!res.ok) {
    throw new Error(`${res.status}: ${await res.text()}`);
  }
  return res.json() as Promise<T>;
}
