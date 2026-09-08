# QUANSEQ UI

Operator portals for the QUANSEQ post-quantum cryptography platform.

Next.js 16 (App Router) · React 19 · TypeScript · Tailwind CSS 4 · Recharts

> Backend documentation lives in [`../docs/`](../docs/). Start with the
> [root README](../README.md) for the whole system.

---

## Quick start

```bash
npm install
echo "NEXT_PUBLIC_QUANSEQ_API=http://localhost:8000" > .env.local
npm run dev
```

<http://localhost:3000>

The backend must be running — see [`../docs/SETUP.md`](../docs/SETUP.md). Without
it every page renders but shows no data, and login fails.

| Script | Does |
|---|---|
| `npm run dev` | Development server with hot reload |
| `npm run build` | Production build |
| `npm run start` | Serve the production build |
| `npm run lint` | ESLint |

---

## Configuration

| Variable | Required | Notes |
|---|---|---|
| `NEXT_PUBLIC_QUANSEQ_API` | yes | Backend base URL. Falls back to `http://localhost:8000` |

**Inlined at build time.** Changing it after `npm run build` requires a rebuild —
`npm run start` keeps using the old value otherwise.

The WebSocket URL is derived from it by swapping the scheme (`http` → `ws`), so
one variable configures both transports.

**CORS:** the backend allows only `http://localhost:3000` and
`https://localhost:443`. Serving from another origin means updating
`allow_origins` in `quanseq/main.py`.

---

## Routes

| Route | Purpose |
|---|---|
| `/` | Landing — protocol picker (IPsec live, SSH live, TLS marked *soon*) |
| `/ipsec/login` | IPsec portal login (portal-scoped) |
| `/ssh/login` | SSH portal login (portal-scoped) |
| `/portal/*` | IPsec portal — auth-guarded |
| `/ssh-portal/*` | SSH portal — auth-guarded |

### IPsec portal (`/portal`)

| Page | Backend endpoints |
|---|---|
| Overview | `/api/ipsec/stats`, `/api/ipsec/tunnels`, `/api/ws/live` |
| Tunnels | `/api/ipsec/tunnels`, `/api/ipsec/handshakes` |
| Policy | `/api/ipsec/policies`, `/policies/compare`, `/policies/apply` |
| Attack Lab | `/api/ipsec/attacks/*` |
| Readiness | `/api/scoring/ipsec`, `/api/scoring/overall` |
| Alerts | `/api/alerts`, `/api/alerts/{id}/ack` |
| Integrations | `/api/siem/events`, `/api/failmode` |
| API Keys | `/api/keys` |
| Integration | static docs |

### SSH portal (`/ssh-portal`)

| Page | Backend endpoints |
|---|---|
| Overview | `/api/ssh/stats`, `/api/ssh/connections` |
| Sessions | `/api/ssh/connections`, `/api/ssh/handshakes` |
| Policy | `/api/ssh/policies`, `/policies/compare`, `/policies/apply` |
| Zero Trust | `/api/ssh/zt/events`, `/zt/status`, `/zt/policy` |
| Issue Cert | `/api/ssh/ca/issue`, `/ca/info`, `/ca/issued` |
| Readiness | `/api/scoring/ssh` |
| Alerts | `/api/alerts` |
| Integrations | `/api/siem/events`, `/api/failmode` |
| API Keys | `/api/keys` |

Full endpoint reference: [`../docs/API.md`](../docs/API.md).

---

## Structure

```
src/
├── app/
│   ├── layout.tsx              <AuthProvider> wraps the whole tree
│   ├── page.tsx                landing
│   ├── ipsec/login/            ssh/login/
│   ├── portal/
│   │   ├── layout.tsx          auth guard + IPsec sidebar
│   │   └── …/page.tsx
│   └── ssh-portal/
│       ├── layout.tsx          auth guard + SSH sidebar
│       └── …/page.tsx
├── lib/
│   ├── api.ts                  QuanseqClient — typed methods + token handling
│   ├── auth-context.tsx        {user, loading, login, logout}
│   └── use-live-stats.ts       polling + WebSocket hook
└── components/
    ├── sidebar.tsx             IPsec nav
    └── ui-primitives.tsx       shared presentational components
```

### The auth guard lives in the layout

Each portal's `layout.tsx` checks `useAuth()`, renders `AUTHENTICATING…` while
loading, and redirects to that module's login when there is no user. Every page
beneath inherits it — **a new page cannot forget to check authentication.**

```tsx
const { user, loading } = useAuth();
useEffect(() => { if (!loading && !user) router.replace("/ssh/login"); }, [loading, user, router]);
if (loading) return <Authenticating />;
if (!user) return null;
```

This is the main reason the App Router was chosen: the portals are entirely
behind authentication, so SSR and SEO are irrelevant — nested layouts are what
matter.

### One client, one token

`QuanseqClient` (`lib/api.ts`) holds the JWT in memory and mirrors it to
`localStorage` so a refresh survives. Every call goes through one private
`request<T>()` that attaches `Authorization: Bearer` and throws on non-2xx.

Adding an endpoint means adding a typed method:

```ts
async getSshStats() {
  return this.request<SshStats>("/api/ssh/stats");
}
```

Response interfaces mirror the backend's Pydantic models, so a server-side field
rename becomes a TypeScript compile error rather than a runtime `undefined`.

### Portal-scoped login

```ts
quanseq.login(email, password, "ssh")
// → POST /api/auth/login-scoped?portal=ssh
```

The backend rejects a user whose `users.portal` is neither `ssh` nor `main`;
admins bypass. This is **UI segregation, not a security boundary** — a valid
token reaches every endpoint regardless of portal. See
[`../docs/SECURITY.md`](../docs/SECURITY.md#23-portal-scoping).

### Live data

`useLiveStats(intervalMs = 5000)` combines two mechanisms:

- **REST polling every 5 s** — guarantees eventual correctness even if the socket
  drops. Fetch errors are swallowed deliberately, so the UI keeps showing the
  last good data instead of flashing an error on a transient blip.
- **WebSocket** — carries *notifications only*. On a `kind: "lifecycle"` message
  the hook refetches immediately, so an IKE rekey appears without waiting for the
  next tick.

The socket never carries authoritative state, so a dropped connection is a
latency problem, not a correctness problem.

```tsx
const { stats, tunnels, connected, lastEvent } = useLiveStats();
```

`connected` drives the live badge; it goes grey when Redis is down or the reverse
proxy is missing WebSocket `Upgrade` headers.

---

## Styling

Layout and spacing use Tailwind utility classes. Colour uses CSS custom
properties applied via inline `style`, so the palette is themeable from
`globals.css` alone:

| Variable | Used for |
|---|---|
| `--pqc-cyan` | IPsec module accent, active nav |
| `--lattice-violet` | SSH module accent, admin role badge |
| `--bg-void` / `--bg-panel` / `--bg-panel-raised` | Surfaces |
| `--text-primary` / `--secondary` / `--tertiary` | Text hierarchy |
| `--border-hairline` / `--border-hairline-bright` | Dividers |

Icons are `lucide-react` (tree-shakeable SVG components). Charts are `recharts`.

There is **no state management library** — server state lives in `useLiveStats`,
auth state in one React context. That is the whole client state model.

---

## Adding a protocol portal

1. Copy `app/ssh-portal/` to `app/<protocol>-portal/`.
2. Update the `NAV` array in its `layout.tsx` and the redirect target.
3. Add a login page at `app/<protocol>/login/`.
4. Add typed client methods in `lib/api.ts`.
5. Add a card to `app/page.tsx` — the TLS card already exists, marked `SOON`.

The layout, auth guard, sidebar pattern and UI primitives are reused unchanged.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Stuck on `AUTHENTICATING…` | `/api/auth/me` failing | Check the backend; clear `localStorage.quanseq_token` |
| CORS errors in the console | Origin not in `allow_origins` | Update `quanseq/main.py`, or serve on `localhost:3000` |
| Live badge grey | WebSocket failed | Redis down, or the proxy lacks `Upgrade` headers |
| Data never refreshes | Polling erroring silently — by design | Open the browser network tab |
| Calls go to the wrong host | `NEXT_PUBLIC_QUANSEQ_API` is build-time | `npm run build` again |
| Login returns 403 | Portal scoping rejected the account | Set `users.portal` to `main` or the right portal |

More: [`../docs/OPERATIONS.md`](../docs/OPERATIONS.md#frontend).

---

*See also:* [root README](../README.md) · [Architecture](../docs/ARCHITECTURE.md) · [API](../docs/API.md) · [Security](../docs/SECURITY.md)
