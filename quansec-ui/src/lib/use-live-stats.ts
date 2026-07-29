"use client";

import { useEffect, useRef, useState } from "react";
import { quansec, IPsecStats, IPsecTunnel } from "@/lib/api";

export function useLiveStats(intervalMs = 5000) {
  const [stats, setStats] = useState<IPsecStats | null>(null);
  const [tunnels, setTunnels] = useState<IPsecTunnel[]>([]);
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    let mounted = true;

    const fetchAll = async () => {
      try {
        const [s, t] = await Promise.all([quansec.getStats(), quansec.getTunnels()]);
        if (mounted) {
          setStats(s);
          setTunnels(t);
        }
      } catch {
        // swallow — UI shows stale data until next tick
      }
    };

    fetchAll();
    const poll = setInterval(fetchAll, intervalMs);

    const ws = quansec.connectLiveSocket((data) => {
      if (data.type === "connected") {
        setConnected(true);
        return;
      }
      if (data.kind === "lifecycle") {
        setLastEvent(data);
        fetchAll();
      }
    });

    if (ws) {
      ws.onclose = () => setConnected(false);
      ws.onerror = () => setConnected(false);
    }

    return () => {
      mounted = false;
      clearInterval(poll);
      ws?.close();
    };
  }, [intervalMs]);

  return { stats, tunnels, connected, lastEvent };
}
