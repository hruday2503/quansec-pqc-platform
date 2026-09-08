#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo groupadd --system --force quanseq-control
sudo install -d -o root -g root -m 0755 /opt/quanseq/backend
sudo install -o root -g root -m 0755 \
  "$repo_root/quanseq/host_policy_agent.py" \
  /opt/quanseq/backend/host_policy_agent.py
sudo install -o root -g root -m 0644 \
  "$repo_root/deploy/quanseq-policy-agent.service" \
  /etc/systemd/system/quanseq-policy-agent.service
sudo install -o root -g root -m 0644 \
  "$repo_root/deploy/quanseq-pqc-sshd.service" \
  /etc/systemd/system/quanseq-pqc-sshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now quanseq-policy-agent.service

echo "Host controller installed. It will report targets unavailable until"
echo "StrongSwan swanctl and /opt/openssh-pqc are installed and configured."
