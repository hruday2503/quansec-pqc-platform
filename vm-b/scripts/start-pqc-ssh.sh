#!/bin/bash
sudo /opt/openssh-pqc/sbin/sshd -f /opt/openssh-pqc/etc/sshd_config
echo "PQC SSH (mlkem768x25519) listening on port 2222"
sudo ss -tlnp | grep 2222
