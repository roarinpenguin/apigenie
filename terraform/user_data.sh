#!/bin/bash
set -euo pipefail
exec > /var/log/user-data.log 2>&1

echo "=== ApiGenie bootstrap: $(date) ==="

# ---------------------------------------------------------------------------
# System update
# ---------------------------------------------------------------------------
dnf update -y

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
dnf install -y docker git
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user

# ---------------------------------------------------------------------------
# Docker Compose v2 (plugin)
# ---------------------------------------------------------------------------
COMPOSE_VERSION="v2.27.1"
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# ---------------------------------------------------------------------------
# Convenience: make docker compose available as ec2-user without sudo
# ---------------------------------------------------------------------------
mkdir -p /home/ec2-user/.docker/cli-plugins
ln -sf /usr/local/lib/docker/cli-plugins/docker-compose \
       /home/ec2-user/.docker/cli-plugins/docker-compose

# ---------------------------------------------------------------------------
# SSM Agent — ensure it's enabled and running after any dnf updates
# ---------------------------------------------------------------------------
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent

echo "=== Bootstrap complete: $(date) ==="
echo "Next steps:"
echo "  1. SSH in: ssh -i ~/.ssh/roarinkey.pem ec2-user@<elastic-ip>"
echo "  2. Clone your repo"
echo "  3. Run ./scripts/bootstrap.sh"
echo "  4. docker compose up -d"
