import os
import sys

def patch_main():
    with open("main.py") as f:
        c = f.read()
    changed = False
    if "event_listen_loop" not in c:
        c = c.replace(
            "from protocols.ipsec.collector import collect_loop as ipsec_collect_loop",
            "from protocols.ipsec.collector import collect_loop as ipsec_collect_loop\nfrom protocols.ipsec.events import event_listen_loop as ipsec_event_loop",
        )
        changed = True
    if "ipsec-events" not in c:
        c = c.replace(
            '    _background_tasks.append(ipsec_task)\n    logger.info("IPsec collector started")',
            '    _background_tasks.append(ipsec_task)\n    logger.info("IPsec collector started")\n\n    ipsec_ev_task = asyncio.create_task(ipsec_event_loop(), name="ipsec-events")\n    _background_tasks.append(ipsec_ev_task)\n    logger.info("IPsec lifecycle event listener started")',
        )
        changed = True
    if changed:
        with open("main.py", "w") as f:
            f.write(c)
        print("Patched main.py - lifecycle event listener wired in")
    else:
        print("main.py already patched")

def patch_stats():
    with open("protocols/ipsec/router.py") as f:
        c = f.read()
    if "'ESTABLISHED','INSTALLED'" not in c:
        c = c.replace(
            "COUNT(*) FILTER (WHERE state = 'ESTABLISHED')    AS established,",
            "COUNT(*) FILTER (WHERE state IN ('ESTABLISHED','INSTALLED')) AS established,",
        )
        with open("protocols/ipsec/router.py", "w") as f:
            f.write(c)
        print("Patched stats query - INSTALLED now counts as established")
    else:
        print("stats query already patched")

def add_handshake_endpoint():
    with open("protocols/ipsec/router.py") as f:
        c = f.read()
    if "/handshakes" in c:
        print("handshake endpoint already present")
        return
    endpoint = '''

@router.get("/handshakes")
async def handshake_stages(
    tunnel_name: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    conn: asyncpg.Connection = Depends(get_db),
):
    where = ""
    args = []
    if tunnel_name:
        where = "WHERE tunnel_name = $1"
        args.append(tunnel_name)
        args.append(limit)
        limit_idx = "$2"
    else:
        args.append(limit)
        limit_idx = "$1"
    rows = await conn.fetch(
        f"""
        SELECT tunnel_name, event_type, detail, occurred_at
        FROM ipsec_events
        {where}
        ORDER BY occurred_at DESC
        LIMIT {limit_idx}
        """,
        *args,
    )
    stage_order = {
        "IKE_SA_INIT": 1, "IKE_AUTH": 2, "ESTABLISHED": 3,
        "CHILD_UP": 4, "IKE_REKEY": 5, "CHILD_REKEY": 5,
        "CHILD_DOWN": 6, "DOWN": 7,
    }
    result = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("detail"), str):
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
        d["stage_order"] = stage_order.get(d["event_type"], 99)
        result.append(d)
    return result
'''
    c = c.rstrip() + "\n" + endpoint
    with open("protocols/ipsec/router.py", "w") as f:
        f.write(c)
    print("Added /api/ipsec/handshakes endpoint")

if __name__ == "__main__":
    if not os.path.exists("main.py"):
        print("ERROR: run from project root (where main.py is)")
        sys.exit(1)
    patch_main()
    patch_stats()
    add_handshake_endpoint()
    print("")
    print("Done. Restart: uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
