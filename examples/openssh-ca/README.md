# OpenSSH User CA & Host CA Fleet Authentication Example with `mgtls`

This example demonstrates how to eliminate static `authorized_keys` sprawl and TOFU (`Trust On First Use`) host key prompts across an infrastructure fleet using **OpenSSH Certificate Authorities** managed by `mgtls`:

1. **OpenSSH User CA (`corp-ssh-user-ca`)**: Signs short-lived developer and automation SSH user certificates (`alice-ssh`, principals `alice,admin,sre`) trusted by `sshd` via `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`.
2. **OpenSSH Host CA (`corp-ssh-host-ca`)**: Signs server host keys (`bastion-host-ssh`, principals `bastion.corp.internal,10.0.0.10,localhost`) trusted by SSH clients via `@cert-authority` in `known_hosts`.

## Files in This Example

| File | Description |
| :--- | :--- |
| [`setup_openssh_ca.sh`](file:///home/bill/src/sysadmin/mgtls/examples/openssh-ca/setup_openssh_ca.sh) | End-to-end script that creates the OpenSSH User CA and Host CA, signs user and host certificates, inspects the resulting `-cert.pub` artifacts, and generates `sshd_config`, `ssh_config`, `authorized_principals`, and `@cert-authority` `known_hosts` bundles. |

## Quickstart

### 1. Run the OpenSSH CA Provisioning Script

```bash
./setup_openssh_ca.sh
```

### 2. Inspect a Signed OpenSSH Certificate

```bash
mgtls --store-dir .mgtls-openssh ssh inspect \
  --cert .mgtls-openssh/ssh/certs/alice-ssh/alice-ssh-cert.pub
```

### 3. Deploy to OpenSSH Server (`sshd`)

```bash
sudo cp generated-openssh-config/sshd_config.d/mgtls-ca.conf /etc/ssh/sshd_config.d/mgtls-ca.conf
sudo cp generated-openssh-config/authorized_principals /etc/ssh/authorized_principals
sudo systemctl reload sshd
```

### 4. Connect from OpenSSH Client Using Signed User Certificate

```bash
ssh -F generated-openssh-config/ssh_config.d/mgtls.conf \
  -i .mgtls-openssh/ssh/certs/alice-ssh/id_ed25519 \
  alice@bastion.corp.internal
```
