# Backend addition required: API Keys endpoint

The portal's "API Keys" page calls `/api/keys` endpoints which don't exist
in your QUANSEQ backend yet. Add them with these steps on VM A:

## Step 1 — Copy the file

```bash
cd ~/Downloads/quanseq_phase1/quanseq
cp /path/to/quanseq-ui/backend-additions/api_keys.py protocols/auth_api_keys.py
```

(Rename to `protocols/auth_api_keys.py` to avoid colliding with the
existing `protocols/auth_router.py`.)

## Step 2 — Wire into main.py

```bash
python3 - << 'EOF'
with open("main.py") as f:
    c = f.read()
if "auth_api_keys" not in c:
    c = c.replace(
        "from protocols.auth_router import router as auth_router",
        "from protocols.auth_router import router as auth_router\nfrom protocols.auth_api_keys import router as api_keys_router"
    )
    c = c.replace(
        "app.include_router(auth_router)",
        "app.include_router(auth_router)\napp.include_router(api_keys_router)"
    )
    with open("main.py", "w") as f:
        f.write(c)
    print("Patched main.py - API keys router added")
else:
    print("Already patched")
EOF
```

## Step 3 — Restart

```bash
pkill -f uvicorn; sleep 2
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
```

## Step 4 — Test

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login -d "username=admin@quanseq.io&password=Admin@1234" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8000/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Integration"}' | python3 -m json.tool
```

You should see a response with `api_key: qsk_live_...` — that confirms
the endpoint works and the portal's Keys page will function.

## Note on key validation (future work)

Currently generated API keys are stored (hashed) but the auth dependency
(`require_user`) only validates JWT tokens, not these long-lived API keys.
For a customer's server to actually authenticate WITH an `qsk_live_...` key
(not just a JWT), `core/auth.py`'s `get_current_user` needs to also check
the `api_keys` table when the bearer token doesn't decode as a JWT. This
is the next engineering step before customers can use generated keys for
real integration — currently the Keys page demonstrates the UX and
generates/stores valid-format keys, but JWT is still what authenticates
API calls today.
