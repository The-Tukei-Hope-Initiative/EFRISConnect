# Security and credential handling

This document describes exactly how EFRISConnect handles sensitive data:
Manager API access tokens, EFRIS passwords, EFRIS private keys, and key
passphrases. It reflects the behaviour of the code in this repository
(`backend/vault.js`, `backend/server.js`). If you find a discrepancy, please
open an issue.

## What is sensitive

- **Manager API access token** - grants access to your Manager.io business.
- **EFRIS password** - your URA EFRIS portal password.
- **EFRIS private key (PEM)** and its **passphrase** - used to decrypt the EFRIS
  session key so submissions can be signed.

## Where it runs

EFRISConnect is a relay you host yourself. The **browser UI never holds the
EFRIS private key or the Manager token**: it refers to a saved business by an
id, and the server decrypts the secret into memory only for the moment it makes
a call to Manager or EFRIS.

## Transmission

- Browser <-> your relay: over HTTP on `localhost` for a local install, or HTTPS
  when you enable the local certificate (recommended) or put the relay behind
  TLS. Because you host the relay, credentials are not sent to any third party.
- Relay <-> Manager.io and Relay <-> URA EFRIS: HTTPS to the endpoints you
  configure. EFRIS payloads are additionally AES-encrypted and signed per URA's
  interface specification.

## Storage (encryption at rest)

Secrets are stored server-side in `backend/data/credentials_vault.json`,
encrypted with **AES-256-GCM** (a random 12-byte IV per value, an authentication
tag, versioned `v1:` prefix). Non-secret metadata (TIN, device number, Manager
endpoint, flags) is stored in clear so the UI can list businesses without
decrypting anything.

The encryption key (the "master key") is resolved in this order:
1. `VAULT_MASTER_KEY` environment variable (base64 of 32 bytes). **Required for
   any shared or cloud deployment.**
2. Fallback for a single self-hosted taxpayer: a per-install random key generated
   once and stored at `backend/data/.vault_master` with `0600` permissions
   (owner-only). This is fine for one person on their own machine; it is **not**
   appropriate for a shared/multi-user server - set `VAULT_MASTER_KEY` there.

Both `credentials_vault.json` and `.vault_master` are git-ignored and are written
with `0600` permissions.

## Logging

The relay redacts secrets from its logs: EFRIS passwords, key passphrases,
access tokens, and private-key material are stripped from error messages and
diagnostic output before anything is written. Logs record operational events
(which EFRIS interface was called, return codes) - not credential values.

## Backup

Nothing is backed up automatically by the application. Note that **Manager.io's
own backup does NOT cover EFRISConnect** - it backs up your Manager accounting
data only. EFRISConnect is a separate app, so its `backend/data/` (the vault,
the local master key, and logs) must be backed up separately by you.

Treat `backend/data/` as highly sensitive and encrypt those backups. If you set
`VAULT_MASTER_KEY` via environment, keep it out of your code backups (it is the
key to the vault); store it in a secrets manager, not alongside the vault file.

### Generating a VAULT_MASTER_KEY
It must be base64 of exactly 32 random bytes. Generate one with either:
```
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
openssl rand -base64 32
```
Set the output as the `VAULT_MASTER_KEY` environment variable (see the env-var
instructions in docs/self-hosting.md).

## Access

Only the relay process reads the vault, and only to decrypt a secret into memory
for a single outbound call. Server API endpoints that accept credentials are
protected by the relay's own API key when configured. There is no endpoint that
returns stored secrets to the browser.

## Deletion

Removing a business from the app deletes its entry from
`credentials_vault.json`. To remove everything, stop the relay and delete
`backend/data/credentials_vault.json` (and `.vault_master` if you want to discard
the local master key). Deletion is immediate and permanent.

## Local HTTPS certificate

To serve `https://localhost:5443` for the Manager button, the app uses a
**self-signed certificate for localhost/LAN only**. This certificate is unrelated
to any EFRIS or Manager credential and secures only local TLS.

- On Windows, `setup-https.ps1` generates the cert and a PFX. The PFX password is
  a **random per-install value** (not a shared constant); the password file is
  restricted to the current user. The private key's real protection is file-system
  permissions on `backend/data/`.
- On macOS/Linux you provide a cert/key pair (see docs/self-hosting.md); protect
  the key file with `0600`.
- The generated cert, key, PFX, and password file live in `backend/data/` and are
  git-ignored - they are never committed or published.

Because this only protects a local self-signed certificate, an attacker who can
read these files already has local file-system access; the certificate password
is therefore not a meaningful additional secret. No public CA key material is
involved.

## Testing vs production

Keep **Sandbox mode ON** while evaluating the software. Do not enter production
EFRIS credentials until you have verified the install against URA's sandbox with
test data. Production submissions are live and legally binding.

## Security design notes and limitations

Being transparent about the trade-offs of a self-hostable, largely single-tenant
tool:

- **Manager TLS verification is ON by default.** Calls to Manager verify the
  server certificate (prevents MITM). It is skipped only if you explicitly set
  `MANAGER_INSECURE_TLS=1` for a self-signed Manager - never silently.
- **Request bodies are capped** (5 MB) to limit oversized-payload abuse.
- **CORS is open (`*`)** because the extension is loaded cross-origin from
  Manager, whose origin varies (a random localhost port on Desktop, or a cloud
  domain). Authentication is by header token / operator API key, not cookies, so
  classic CSRF does not apply. Sensitive relay endpoints require the operator
  API key (`INTERNAL_API_KEY`).
- **Credentials should be sent in headers/body, not query strings.** Some GET
  diagnostics accept `ep`/`tk` as query params for convenience; on a shared
  server prefer headers and disable query-string access logging.
- **Sessions and decrypted keys live only in memory** and are gone on restart.
  On a shared/multi-tenant host, isolate the process and set `VAULT_MASTER_KEY`.
- **The vault master key on disk** (`.vault_master`, `0600`) is unavoidable for a
  single self-hoster - the process must read it to decrypt. It protects against
  casual file copying, not against full compromise of that machine. Use
  `VAULT_MASTER_KEY` (kept outside the repo/backups) for anything shared.
- **Rate limiting is per-IP and in-memory** - adequate for a single-tenant
  self-host; put a proper gateway/WAF in front for a public multi-tenant deployment.
- **Logs record operational data** (customer name, TIN, amounts, references) but
  redact secrets. Treat log files as sensitive; rotate and protect them.
- **On-disk caches** (e.g. the goods catalog) are stored unencrypted and
  git-ignored; they contain product/pricing data, not credentials.
- **`deviceMAC`** sent to EFRIS is a fixed constant required by the interface,
  not a secret.

## Network exposure

The relay is designed to run **locally** (a desktop/server on the same machine or
LAN as the till), not to be published directly on the public internet. If you do
expose it, restrict access with a firewall / security-group rule to
localhost/trusted networks only, and put it behind proper TLS and a gateway.

## Deployment checklist (shared / multi-tenant / cloud)

For anything beyond a single self-hosted taxpayer:

- [ ] Set `VAULT_MASTER_KEY` (do not rely on the local `.vault_master` file).
- [ ] Set `INTERNAL_API_KEY` explicitly (do not use the random per-process key).
- [ ] Restrict network access to authorised IPs (firewall / security group).
- [ ] Disable query-string credential params in your reverse-proxy access logs.
- [ ] Run behind a WAF / gateway for real rate limiting (the built-in limiter is
      in-memory and per-IP).
- [ ] Rotate logs regularly and encrypt them at rest.
- [ ] Use a proper CA-issued TLS certificate (not self-signed); keep
      `MANAGER_INSECURE_TLS` unset.

## Reporting a vulnerability

Please report security issues privately to **outreach@tukeihopeinitiative.org**
rather than opening a public issue, so we can address them before disclosure.
