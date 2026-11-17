# OpenSSH CA & Public ACME Encryption Guide — `mgtls`

## Part 1: OpenSSH Certificate Authorities (`mgtls ssh`)

### 1.1 Why Replace `authorized_keys` and TOFU `known_hosts` with OpenSSH CAs?

Traditional SSH key management suffers from two operational bottlenecks:
1. **Sprawling `~/.ssh/authorized_keys`**: Adding or rotating an engineer's SSH key requires touching every server in the fleet, and keys never expire automatically.
2. **Trust-On-First-Use (TOFU) Prompts**: Connecting to a new or rebuilt host triggers `The authenticity of host '...' can't be established`, training operators to blindly accept fingerprints or failing automated pipelines.

With `mgtls ssh`:
- **SSH User CA**: Servers trust a single `mgtls_user_ca.pub` (`TrustedUserCAKeys`). Engineers receive short-lived signed certificates (`id_ed25519-cert.pub`) scoped to specific OS principals (e.g., `ubuntu`, `deploy`) that automatically expire after `--hours`.
- **SSH Host CA**: Clients trust a single `@cert-authority` line in `known_hosts`. Every server presents a signed host certificate (`ssh_host_ed25519_key-cert.pub`), eliminating TOFU prompts across the entire domain/subnet.

---

### 1.2 Step 1: Create Dedicated OpenSSH User and Host CAs

Always maintain separate CA keys for users and hosts:

```bash
# Create an Ed25519 User CA
mgtls ssh ca-create \
  --name prod-user-ca \
  --type user \
  --algo ed25519

# Create an Ed25519 Host CA
mgtls ssh ca-create \
  --name prod-host-ca \
  --type host \
  --algo ed25519
```

Artifacts created in `.mgtls/ssh/ca/`:
- `prod-user-ca` (`0600`) & `prod-user-ca.pub` (`0644`)
- `prod-host-ca` (`0600`) & `prod-host-ca.pub` (`0644`)

---

### 1.3 Step 2: Sign SSH User Certificates (`mgtls ssh sign-user`)

You can either pass an existing public key (`--pubkey ~/.ssh/id_ed25519.pub`) or omit `--pubkey` to let `mgtls` generate a fresh private/public keypair (`0600`/`0644`) alongside the signed `-cert.pub`:

```bash
# Issue a 24-hour user certificate for principals "ubuntu" and "deploy"
mgtls ssh sign-user \
  --name alice-prod \
  --ca prod-user-ca \
  --key-id "alice@example.com" \
  --principals "ubuntu,deploy" \
  --hours 24
```

Optional security restrictions (Critical Options):
- `--force-command "/usr/local/bin/backup-runner"`: Restricts the certificate to executing a single command.
- `--source-address "10.0.0.0/8,192.168.1.0/24"`: Restricts the source IPv4/IPv6 CIDR blocks allowed to authenticate with this certificate.

---

### 1.4 Step 3: Sign SSH Host Certificates (`mgtls ssh sign-host`)

Sign a server's SSH host key (or generate a new host keypair + certificate bundle) bound to its FQDNs and IP addresses:

```bash
mgtls ssh sign-host \
  --name node01-host \
  --ca prod-host-ca \
  --key-id "node01.internal" \
  --principals "node01.internal,node01,10.10.0.21" \
  --hours 8760
```

---

### 1.5 Step 4: Inspect Signed OpenSSH Certificates (`mgtls ssh inspect`)

Verify certificate type (`user` vs `host`), serial number, principals, validity window, CA key fingerprint, critical options, and extensions without invoking `ssh-keygen -L`:

```bash
mgtls ssh inspect --cert .mgtls/ssh/certs/alice-prod-cert.pub
mgtls ssh inspect --cert .mgtls/ssh/certs/node01-host-cert.pub --json
```

---

### 1.6 Step 5: Generate Server & Client Configuration Bundles (`mgtls ssh config`)

Generate drop-in configuration files for both target OpenSSH servers and client workstations:

```bash
mgtls ssh config \
  --user-ca prod-user-ca \
  --host-ca prod-host-ca \
  --hosts "*.internal,10.10.0.*" \
  --account ubuntu=alice \
  --account deploy=alice,ci \
  --out ./ssh-fleet-config
```

Each `--account ACCOUNT=PRINCIPAL[,PRINCIPAL...]` says which certificate principals may log in as that local account. mgtls writes one file per account, so a certificate for `ci` can log in as `deploy` but not as `ubuntu` or `root`. The shorthand `--principals "alice,bob"` is the same as `--account alice=alice --account bob=bob`: each principal may log in only as the account with its own name. You cannot combine the two forms. Rerunning the command deletes the files of accounts you dropped.

Generated files in `./ssh-fleet-config/`:

1. **`sshd_config.d/mgtls-ca.conf`** (Copy to `/etc/ssh/sshd_config.d/mgtls-ca.conf` on servers):
   ```sshconfig
   TrustedUserCAKeys /etc/ssh/mgtls_user_ca.pub
   HostKey /etc/ssh/ssh_host_ed25519_key
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   AuthorizedPrincipalsFile <out>/auth_principals/%u
   ```
   sshd expands `%u` to the account being logged into. If you copy the files somewhere else, such as `/etc/ssh/auth_principals/`, edit this line to match.
2. **`auth_principals/<account>`**, one file per account (copy the directory to `/etc/ssh/auth_principals/`). For the command above:
   ```text
   auth_principals/ubuntu:  alice
   auth_principals/deploy:  alice
                            ci
   ```
   sshd refuses certificate logins to any account without a file.
3. **`known_hosts`** (Append to client `~/.ssh/known_hosts` or `/etc/ssh/ssh_known_hosts`):
   ```text
   @cert-authority *.internal,10.10.0.* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... prod-host-ca
   ```
4. **`ssh_config.d/mgtls.conf`** (Include in client `~/.ssh/config`):
   ```sshconfig
   Host *.internal 10.10.0.*
       IdentityFile ~/.mgtls/ssh/certs/alice-prod
       CertificateFile ~/.mgtls/ssh/certs/alice-prod-cert.pub
       UserKnownHostsFile ~/.mgtls/ssh/config/known_hosts
   ```

---

## Part 2: Free Public Encryption via ACME v2 (`mgtls acme`)

`mgtls acme` implements a pure Go RFC 8555 ACME v2 client supporting five public Certificate Authorities out of the box, plus custom RFC 8555 ACME servers (Smallstep `step-ca`, Pebble, Boulder) and a built-in offline mock server.

### 2.1 List Supported Free Public ACME Providers

```bash
mgtls acme providers
```

| Provider Flag (`--provider`) | Authority | Free Tier Details |
| :--- | :--- | :--- |
| `letsencrypt` | Let's Encrypt (Production) | Free 90-day DV certificates; supports HTTP-01, TLS-ALPN-01, DNS-01 (incl. wildcards). |
| `letsencrypt-staging` | Let's Encrypt (Staging) | High rate limits for testing deployment automation before switching to `letsencrypt`. |
| `zerossl` | ZeroSSL | Free 90-day DV certificates via ACME with External Account Binding (`--eab-kid`, `--eab-hmac-key`). |
| `buypass` | Buypass Go SSL | Free **180-day** DV certificates (no EAB required). |
| `google` | Google Trust Services | Free 90-day DV certificates (multi-cloud/public roots) using Google Cloud Public CA EAB credentials. |
| `custom` | Custom RFC 8555 Directory | Any internal or external ACME server via `--directory-url https://ca.internal/acme/acme/directory`. |

---

### 2.2 Challenge Workflows

#### Workflow A: Standalone HTTP-01 Challenge (`--challenge http-01`)
When port `80` is reachable from the internet and no web server is currently bound to `:80`, `mgtls` spins up an ephemeral HTTP-01 listener automatically:

```bash
sudo mgtls acme obtain \
  --name edge-gateway \
  --provider letsencrypt \
  --email ops@example.com \
  --domains "edge.example.com,api.example.com" \
  --challenge http-01 \
  --http-addr ":80"
```

#### Workflow B: Webroot HTTP-01 Challenge (`--webroot`)
When NGINX or Apache is already running on port `80`, point `--webroot` to the server's document root so `mgtls` writes and cleans up `/.well-known/acme-challenge/<token>` without stopping your web server:

```bash
mgtls acme obtain \
  --name edge-gateway \
  --provider buypass \
  --email ops@example.com \
  --domains "edge.example.com" \
  --challenge http-01 \
  --webroot /var/www/html
```

#### Workflow C: Standalone TLS-ALPN-01 Challenge (`--challenge tls-alpn-01`)
When port `80` is blocked by ISP or firewall policy and only port `443` is open, `mgtls` negotiates the RFC 8737 `acme-tls/1` ALPN protocol and presents a temporary certificate carrying the critical `1.3.6.1.5.5.7.1.31` (`id-pe-acmeIdentifier`) extension:

```bash
sudo mgtls acme obtain \
  --name alpn-gateway \
  --provider letsencrypt \
  --email ops@example.com \
  --domains "alpn.example.com" \
  --challenge tls-alpn-01 \
  --tls-addr ":443"
```

#### Workflow D: DNS-01 Challenge & Wildcard Certificates (`--challenge dns-01`)
For wildcard certificates (`*.example.com`) or internal hosts behind private networks that cannot receive inbound port 80/443 connections from public CAs, use `dns-01` with a DNS hook script:

```bash
mgtls acme obtain \
  --name wildcard-corp \
  --provider letsencrypt \
  --email ops@example.com \
  --domains "example.com,*.example.com" \
  --challenge dns-01 \
  --dns-cmd "/usr/local/bin/publish-dns-txt.sh"
```

Your `--dns-cmd` script receives the following environment variables automatically:
- `MGTLS_ACME_DOMAIN`: Target domain being validated (e.g., `example.com`)
- `MGTLS_ACME_TXT_NAME`: Full TXT record name (`_acme-challenge.example.com`)
- `MGTLS_ACME_TXT_VALUE`: Base64URL-encoded SHA-256 digest of the ACME key authorization
- `MGTLS_ACME_TOKEN`: Raw ACME challenge token

---

### 2.3 Using External Account Binding (ZeroSSL & Google Trust Services)

To issue certificates from ZeroSSL or Google Trust Services, pass `--eab-kid` and `--eab-hmac-key` (base64url-encoded HMAC key):

```bash
mgtls acme obtain \
  --name google-prod \
  --provider google \
  --email ops@example.com \
  --domains "app.example.com" \
  --challenge http-01 \
  --eab-kid "ead1234567890abcdef" \
  --eab-hmac-key "dGhpcyBpcyBhIHRlc3QgaG1hYyBrZXkgZm9yIGVhYg"
```

---

### 2.4 Offline End-to-End ACME Testing (`--mock`)

Test your entire ACME issuance pipeline offline in CI/CD or air-gapped environments using the built-in RFC 8555 compliant mock ACME server (`pkg/acme/mockserver`):

```bash
mgtls acme obtain \
  --name ci-acme-test \
  --provider custom \
  --email dev@example.local \
  --domains "app.example.local,api.example.local" \
  --challenge http-01 \
  --mock
```
