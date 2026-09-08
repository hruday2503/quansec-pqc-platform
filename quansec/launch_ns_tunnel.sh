#!/bin/bash
# launch_ns_tunnel.sh — run two charon daemons in separate netns with isolated
# pidfiles and world-readable VICI sockets, then load + initiate the PQC tunnel.
#
# Run with: sudo bash launch_ns_tunnel.sh

set -e

echo "=== Cleanup ==="
pkill -9 charon 2>/dev/null || true
sleep 2
rm -f /var/run/charon.pid /var/run/ns-left/charon.* /var/run/ns-right/charon.*

echo "=== Launch left daemon (ns-left) ==="
# unshare BOTH net (already have via netns) and mount, bind a private pidfile,
# and chmod the socket from inside the same mount namespace so it's reachable.
ip netns exec ns-left unshare --mount bash -c '
  touch /var/run/ns-left/charon.pid
  mount --bind /var/run/ns-left/charon.pid /var/run/charon.pid
  STRONGSWAN_CONF=/etc/ns-left/strongswan.conf /usr/libexec/ipsec/charon &
  CHPID=$!
  # wait for socket then make it accessible
  for i in $(seq 1 10); do
    [ -S /var/run/ns-left/charon.vici ] && break
    sleep 0.5
  done
  chmod 777 /var/run/ns-left/charon.vici 2>/dev/null || true
  # load + initiate from inside this same mount namespace
  sleep 1
  swanctl --load-all -f /etc/ns-left/swanctl/swanctl.conf -u unix:///var/run/ns-left/charon.vici 2>&1 | grep -iv "plugin"
  wait $CHPID
' > /tmp/charon-left.log 2>&1 &
sleep 5

echo "=== Launch right daemon (ns-right) ==="
ip netns exec ns-right unshare --mount bash -c '
  touch /var/run/ns-right/charon.pid
  mount --bind /var/run/ns-right/charon.pid /var/run/charon.pid
  STRONGSWAN_CONF=/etc/ns-right/strongswan.conf /usr/libexec/ipsec/charon &
  CHPID=$!
  for i in $(seq 1 10); do
    [ -S /var/run/ns-right/charon.vici ] && break
    sleep 0.5
  done
  chmod 777 /var/run/ns-right/charon.vici 2>/dev/null || true
  sleep 1
  swanctl --load-all -f /etc/ns-right/swanctl/swanctl.conf -u unix:///var/run/ns-right/charon.vici 2>&1 | grep -iv "plugin"
  wait $CHPID
' > /tmp/charon-right.log 2>&1 &
sleep 5

echo "=== Daemon status ==="
echo "ns-left charons: $(ip netns pids ns-left | wc -l)"
echo "ns-right charons: $(ip netns pids ns-right | wc -l)"

echo "=== Left load result ==="
grep -i "loaded connection\|successfully\|error\|failed" /tmp/charon-left.log | grep -iv plugin | tail -3

echo "=== Right load result ==="
grep -i "loaded connection\|successfully\|error\|failed" /tmp/charon-right.log | grep -iv plugin | tail -3

echo ""
echo "Done. The left side has start_action=trap, so the tunnel comes up on first traffic."
echo "Trigger it with:  sudo ip netns exec ns-left ping -c 5 10.10.0.2"
