# ─────────────────────────────────────────────────────────────────────────────
# ApiGenie v4.0 POC environment — Terraform variables
# ─────────────────────────────────────────────────────────────────────────────
#
# This directory exists in parallel to ../terraform/ which manages the
# production EC2 (apigenie.roarinpenguin.com). The POC has its own state file
# (./terraform.tfstate) so terraform apply here can NEVER touch prod.
#
# Every AWS resource gets the prefix "apigenie-poc-" via project_name, so no
# naming collision with the prod stack in the same AWS account.
#
# After validation of v4.0 by the 5-tester group, run:
#     terraform -chdir=terraform-poc destroy
# to fully tear this environment down. Do NOT git-commit terraform.tfstate
# (it's gitignored) — but you may keep this terraform.tfvars committed since
# it contains no secrets.
# ─────────────────────────────────────────────────────────────────────────────

# Same region as prod — keeps cost predictable and avoids cross-region traffic
# for testers who already hit apigenie.roarinpenguin.com from EU.
region = "eu-central-1"

# Resource-name prefix. This MUST differ from "apigenie" (the prod prefix)
# otherwise SG/IAM/key-pair names will collide.
project_name = "apigenie-poc"

# t3.large = the documented minimum. 5 testers will sit well within this.
instance_type = "t3.large"

# Reuse the existing public key (same material) but register it under a
# different AWS key-pair name so it doesn't collide with prod's "apigenie-key".
ssh_public_key_path = "~/.ssh/roarinkey.pub"
key_name            = "apigenie-poc-key"

# SSH allowlist — your /32. Zscaler-aware; this is your real home IP, not the
# Zscaler egress. Add more entries here if other admins need shell access.
ssh_allowed_cidrs = ["87.121.148.232/32"]

# Domain you intend to serve. Used by the outputs to print the recommended
# DNS A record. After terraform apply, create:
#     apigenie-poc.roarinpenguin.com.  IN  A  <elastic_ip>
# then choose "letsencrypt" mode in ./scripts/bootstrap.sh on the box.
domain = "apigenie-poc.roarinpenguin.com"
