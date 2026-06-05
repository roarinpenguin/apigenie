# ApiGenie on AWS — Zero to Hero

> Bring a fresh AWS account from "I have credentials" to "https://apigenie.example.com/admin is signed-in and serving a Let's Encrypt cert" in about 25 minutes. End-state: an EC2 instance running the full apigenie stack (FastAPI + nginx + Kafka + Pub/Sub emulator + RBAC) behind a public Elastic IP, with auto-renewing TLS.

---

## What you will build

```
    ┌──────────────────────────────────────────────────────────────────┐
    │  AWS account (one region, default VPC)                           │
    │                                                                  │
    │   ┌────────────────────────────────────────────────────────────┐ │
    │   │  EC2 t3.large  ──  Amazon Linux 2023                       │ │
    │   │                                                            │ │
    │   │   Docker stack (docker compose):                           │ │
    │   │     • apigenie  — FastAPI + RBAC + Pillow avatars          │ │
    │   │     • nginx     — TLS, HTTP/2, /admin, /portal, /listener  │ │
    │   │     • certbot   — Let's Encrypt issue + renew (HTTP-01)    │ │
    │   │     • kafka     — PLAINTEXT, SASL_PLAINTEXT, SASL_SSL      │ │
    │   │     • zookeeper                                            │ │
    │   │     • pubsub-emulator                                      │ │
    │   │                                                            │ │
    │   │   Persistent volume: /data  (RBAC SQLite + JSON + avatars) │ │
    │   └────────────────────────────────────────────────────────────┘ │
    │              │                                                   │
    │      Elastic IP  ──  DNS A: apigenie.example.com                 │
    │              │                                                   │
    │     Security Group:  22 (SSH, your IP) | 80, 443                 │
    │                       8443 (gRPC TLS) | 9092/9093/9094 (Kafka)   │
    └──────────────────────────────────────────────────────────────────┘
```

---

## 0. Prerequisites — your laptop

You need these on the machine that will run `terraform apply`:

| Tool | Version | Notes |
|------|---------|-------|
| **Terraform** | ≥ 1.5 | `brew install terraform` / `apt install terraform` |
| **AWS CLI v2** | latest | `aws configure` with an admin-ish IAM user/role |
| **OpenSSH key pair** | ed25519 or RSA | Public key path is fed into Terraform; private key lives only on your laptop |
| **A DNS zone you control** | — | Cloudflare / Route 53 / Gandi — anything that lets you create an A record |

Sanity-check your AWS credentials:

```bash
aws sts get-caller-identity
# {"UserId":"AIDA…","Account":"123456789012","Arn":"arn:aws:iam::…:user/you"}
```

If you don't already have an SSH keypair you intend to dedicate to this instance, make one:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/apigenie -C "apigenie@aws"
# Press Enter twice for an empty passphrase or pick one — your choice.
```

This produces `~/.ssh/apigenie` (private) and `~/.ssh/apigenie.pub` (public). You will give the public path to Terraform.

---

## 1. Provision the EC2 instance with Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
```

Set at least these values:

```hcl
region              = "eu-central-1"
domain              = "apigenie.example.com"        # your domain
ssh_public_key_path = "~/.ssh/apigenie.pub"
ssh_allowed_cidrs   = ["1.2.3.4/32"]                # `curl -4s https://api.ipify.org`
```

Then:

```bash
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

When it finishes (~3 minutes), Terraform prints the outputs:

```
elastic_ip       = "18.156.x.y"
instance_id      = "i-0a1b2c3d4e5f6"
ssm_command      = "aws ssm start-session --target i-0a1b… --region eu-central-1"
dns_hint         = "Create an A record:  apigenie.example.com.  →  18.156.x.y"
first_login_hint = (a multi-line cheat sheet — read it!)
```

> **Cost reminder.** A `t3.large` in eu-central-1 is ~$0.10/hr ≈ **$70/month** if you leave it running 24/7. Plus a few cents for the Elastic IP if it's ever unattached. `terraform destroy` returns you to zero.

---

## 2. Create the DNS A record

Use whatever your registrar gives you:

```
A   apigenie.example.com.   →   18.156.x.y    (TTL 300)
```

Wait until DNS propagates (usually < 2 minutes for a fresh record). Verify:

```bash
dig +short apigenie.example.com
# 18.156.x.y
```

**Do not move to step 3 until `dig` returns the EIP.** Let's Encrypt's HTTP-01 challenge will hit your EIP via the DNS name — if DNS doesn't resolve, certificate issuance will fail and you have to retry.

---

## 3. Get a shell on the instance

Two options. Pick **A** if you want simplicity. Pick **B** if you want to close port 22 entirely after first-time setup.

### Option A — SSH

```bash
ssh -i ~/.ssh/apigenie ec2-user@$(terraform -chdir=terraform output -raw elastic_ip)
```

### Option B — SSM Session Manager (no SSH, no port 22)

```bash
aws ssm start-session \
  --target $(terraform -chdir=terraform output -raw instance_id) \
  --region $(terraform -chdir=terraform output -raw region 2>/dev/null || echo eu-central-1)
```

If SSM complains about plugin missing, install it once:

```bash
# macOS
brew install --cask session-manager-plugin
# Linux
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o /tmp/sm.deb && sudo dpkg -i /tmp/sm.deb
```

Once SSM works, you can shrink `ssh_allowed_cidrs` to `["127.0.0.1/32"]` and `terraform apply` again — port 22 is now effectively closed.

---

## 4. Bootstrap the apigenie stack on the instance

Inside the SSH/SSM shell:

```bash
# 1. Clone the repo
git clone <your-repo-url> apigenie
cd apigenie

# 2. Run the interactive bootstrap
./scripts/bootstrap.sh
```

`bootstrap.sh` will ask:

| Prompt | Answer |
|--------|--------|
| **Domain** | `apigenie.example.com` (must match the DNS A record) |
| **Admin username** | `admin` (default) — accept it |
| **Admin password** | Choose a strong one. **Save it** — you'll need it in step 6. |
| **TLS mode** | Pick **`letsencrypt`** (the default) |
| **Let's Encrypt email** | A real address — used only for expiry warnings from Let's Encrypt |

The script writes `.env`, generates a temporary self-signed cert as a placeholder, and writes the right `COMPOSE_PROFILES=letsencrypt` line so the certbot sidecar is enabled.

---

## 5. Start the stack and watch certbot get a real cert

```bash
docker compose up -d --build
# This is the first build — it pulls/compiles Python, Pillow, Kafka, the works.
# Allow ~2-3 minutes on a t3.large.
```

In a second terminal (still on the EC2), watch the certbot sidecar issue your cert:

```bash
docker logs -f apigenie-certbot
```

You should see something like:

```
[INFO] No existing certificate for apigenie.example.com — issuing new one via HTTP-01…
[INFO] Successfully received certificate.
[INFO] Reloading nginx…
```

If certbot fails:

| Error | Cause | Fix |
|-------|-------|-----|
| `Connection refused`, port 80 unreachable | DNS not propagated yet, or SG missing port 80 | `dig +short` should return EIP; check SG inbound 80/tcp open `0.0.0.0/0` |
| `Account creation failed` | Bad email | Re-run `./scripts/bootstrap.sh` and supply a valid one |
| `unauthorized: Incorrect TXT record` | You picked DNS-01 by mistake | apigenie uses HTTP-01; re-run bootstrap |

While certbot finishes its first issuance the site is reachable on the self-signed cert (you'll get a browser warning). Once certbot succeeds, nginx is reloaded and the real cert takes over.

Renewal is fully automatic — certbot runs every 12 hours and renews any cert that's within 30 days of expiry. Watch with `docker logs -f apigenie-certbot`.

---

## 6. First sign-in as the administrator

Open `https://apigenie.example.com/admin` in a browser.

- Sign in with the username (`admin`) and password you set in step 4.
- The dashboard loads. No browser warning means certbot succeeded.

> If you ever lose the admin password: SSH into the instance, edit `.env` to set `ADMIN_PASSWORD=` to a new value, then `docker compose up -d` to restart only the apigenie container. The built-in admin password is not stored in the database.

---

## 7. Validate the multi-user RBAC stack (the lab)

Now that the platform is live, drive it through the labs:

1. `docs/USER_GUIDE.md` § 0 — 10 user-side exercises that build up Alice & Bob with identifiers, private detection rules, avatars, and a Log Push profile.
2. `docs/ADMIN_GUIDE.md` § 0 — 8 admin-side exercises that confirm entitlements, "Viewing as", isolation, and recovery flows.

When you finish, run the regression suite to be doubly sure:

```bash
docker exec apigenie pip install --quiet pytest pytest-asyncio
docker exec apigenie python -m pytest tests/ -v
# Expect: 66 passed
```

---

## 8. Operate the instance

### Tail logs

```bash
docker compose logs -f apigenie         # API + RBAC + detections
docker compose logs -f apigenie-nginx    # TLS, HTTP/2, proxy
docker compose logs -f apigenie-certbot  # cert issue/renew
```

### Restart just the API

```bash
docker compose restart apigenie
```

### Pull a fresh build (e.g. after a code change)

```bash
git pull
docker compose up -d --build apigenie
# pytest, if you want — see step 7
```

### Back up the RBAC + state volume

```bash
docker exec apigenie tar -C / -czf - data > apigenie-backup-$(date +%F).tgz
```

To restore on a fresh instance:

```bash
docker compose down
docker volume rm apigenie_data    # exact name from `docker volume ls`
docker compose up -d --no-start
docker exec -i apigenie tar -C / -xzf - < apigenie-backup-2026-06-05.tgz
docker compose up -d
```

### Inspect the RBAC database directly

```bash
docker exec apigenie sqlite3 /data/accounts.db ".tables"
docker exec apigenie sqlite3 /data/accounts.db \
  "select id, username, is_admin, confirmed, disabled, avatar_path from users;"
```

---

## 9. Tear it all down

When you're done with the demo:

```bash
cd terraform
terraform destroy
```

Destroys the EC2 instance, the EIP, the security group, the IAM role, and the SSH key-pair resource. Removes you from any further AWS spend. The DNS A record stays in your registrar — delete it manually.

---

## Troubleshooting cheat-sheet

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `terraform apply` fails: `KeyPairName already exists` | An older key-pair with the same name lingers in AWS | `aws ec2 delete-key-pair --key-name apigenie-key` then retry |
| `terraform apply` fails: file `~/.ssh/apigenie.pub` not found | Wrong path in `ssh_public_key_path` | Fix the path or regenerate the key |
| EC2 instance reachable on SSH but `https://` hangs | nginx not up yet — first `docker compose up` is still building | `docker compose ps`; wait until all show `Up`/`Healthy` |
| Browser warns about self-signed cert after step 5 | Certbot hasn't issued yet (still running) | `docker logs apigenie-certbot` — wait for the "Successfully received" line |
| Browser still warns after certbot reports success | Old cached cert in your browser | Hard-reload (Cmd-Shift-R / Ctrl-F5); or try Incognito |
| Avatar upload returns 422 | The browser dropped multipart due to a proxy/extension | Try a different browser; check nginx logs for the request body size |
| `docker exec apigenie pytest` says `No module named pytest` | dev deps not in the runtime image | `docker exec apigenie pip install pytest pytest-asyncio` |
| Kafka clients can't reach the EC2 | SG missing 9092/9093/9094 inbound | Terraform's SG already opens these; double-check via the console |
| Let's Encrypt rate-limit hit | You re-ran bootstrap too many times | Use `--staging` mode by editing `docker-compose.yaml`'s certbot env until you stabilise, then switch back |

---

## Where everything lives in the repo

| Path | Purpose |
|------|---------|
| `terraform/main.tf` | All AWS resources (EC2, EIP, SG, IAM, key pair) |
| `terraform/variables.tf` | Inputs — region, instance type, SSH key path, allowed CIDRs |
| `terraform/outputs.tf` | EIP, SSM/SSH commands, DNS hint, first-login cheat sheet |
| `terraform/user_data.sh` | Installs Docker + compose plugin on first boot |
| `terraform/terraform.tfvars.example` | Template you copy to `terraform.tfvars` |
| `scripts/bootstrap.sh` | Interactive setup on the EC2 instance — `.env`, certs, admin creds |
| `docker-compose.yaml` | All services (apigenie, nginx, certbot, kafka, zookeeper, pubsub) |
| `Dockerfile` | apigenie's image (Python 3.13 + FastAPI + Pillow + Docker CLI) |
| `nginx/nginx.conf.template` | TLS termination + routing for `/admin`, `/portal`, every source path |
| `docs/USER_GUIDE.md` | User-facing reference + RBAC lab (Section 0) |
| `docs/ADMIN_GUIDE.md` | Admin reference + admin RBAC lab (Section 0) |
| `tests/` | Pytest harness — 66 tests covering the full RBAC surface |
