"""
apply_auth_patches.py — wires the new auth system into existing files.

Run from the project root:
    cd ~/Downloads/quanseq_phase1/quanseq
    python3 apply_auth_patches.py

This:
  1. Mounts the auth router in main.py
  2. Adds login-required protection to all IPsec endpoints
"""

import os
import sys

def patch_main():
    path = "main.py"
    with open(path) as f:
        c = f.read()

    changed = False

    # Import auth router
    if "auth_router" not in c:
        c = c.replace(
            "from protocols.ipsec.router import router as ipsec_router",
            "from protocols.ipsec.router import router as ipsec_router\nfrom protocols.auth_router import router as auth_router",
        )
        changed = True

    # Mount auth router (before ipsec so /api/auth is registered first)
    if "app.include_router(auth_router)" not in c:
        c = c.replace(
            "app.include_router(ipsec_router)",
            "app.include_router(auth_router)\napp.include_router(ipsec_router)",
        )
        changed = True

    if changed:
        with open(path, "w") as f:
            f.write(c)
        print("Patched main.py — auth router mounted")
    else:
        print("main.py already patched")


def patch_ipsec_router():
    path = "protocols/ipsec/router.py"
    with open(path) as f:
        c = f.read()

    changed = False

    # Add auth import
    if "from core.auth import" not in c:
        c = c.replace(
            "from core.database import get_db",
            "from core.database import get_db\nfrom core.auth import require_user",
        )
        changed = True

    # Protect the router: add dependency to the APIRouter itself
    if "dependencies=[Depends(require_user)]" not in c:
        c = c.replace(
            'router = APIRouter(prefix="/api/ipsec", tags=["IPsec"])',
            'router = APIRouter(\n    prefix="/api/ipsec",\n    tags=["IPsec"],\n    dependencies=[Depends(require_user)],\n)',
        )
        changed = True

    if changed:
        with open(path, "w") as f:
            f.write(c)
        print("Patched protocols/ipsec/router.py — all endpoints now require login")
    else:
        print("ipsec/router.py already patched")


if __name__ == "__main__":
    if not os.path.exists("main.py"):
        print("ERROR: run this from the project root (where main.py is)")
        sys.exit(1)
    patch_main()
    patch_ipsec_router()
    print("\nDone. Now run: python3 seed_admin.py")
    print("Then restart: uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
