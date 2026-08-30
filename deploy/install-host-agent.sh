#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo groupadd --system --force quansec-control
sudo install -d -o root -g root -m 0755 /opt/quansec/backend
sudo install -o root -g root -m 0755 \
  "$repo_root/quansec/host_policy_agent.py" \
  /opt/quansec/backend/host_policy_agent.py
sudo install -o root -g root -m 0644 \
  "$repo_root/deploy/quansec-policy-agent.service" \
  /etc/systemd/system/quansec-policy-agent.service
sudo install -o root -g root -m 0644 \
  "$repo_root/deploy/quansec-pqc-sshd.service" \
  /etc/systemd/system/quansec-pqc-sshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now quansec-policy-agent.service

echo "Host controller installed. It will report targets unavailable until"
echo "StrongSwan swanctl and /opt/openssh-pqc are installed and configured."
