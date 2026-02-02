# Key Management Architecture

Cordelia uses a two-tier key management strategy that balances security with ease of onboarding.

## Two-Tier Strategy

### Tier 1: Registered Users (Future -- Martin's Portal Work)

- User authenticates via OAuth/IDP through the secret keeper portal
- Portal generates encryption key, stores in vault
- Client retrieves key at session start via authenticated API call
- Key never touches disk
- Enables: key rotation, recovery, multi-device sync

### Tier 2: Local-Only Users (Current)

- Self-generated key stored in platform keychain or file
- No account, no portal dependency
- Can upgrade to Tier 1 later (re-encrypt with vault-managed key)

## Key Retrieval Priority Chain

`getEncryptionKey()` in `hooks/lib.mjs` tries these sources in order:

```
1. Vault API       -- CORDELIA_VAULT_URL + CORDELIA_API_TOKEN set
2. Environment     -- CORDELIA_ENCRYPTION_KEY (CI, Docker, advanced users)
3. Platform keychain -- macOS Keychain / Linux GNOME Keyring
4. File fallback   -- ~/.cordelia/key (chmod 0600)
```

First match wins. The function never throws -- it returns `null` if no key is found.

### Source Details

**1. Vault API** (Tier 1, future)

```javascript
// If CORDELIA_VAULT_URL is set, call the vault
const res = await fetch(`${vaultUrl}/api/key`, {
  headers: { 'Authorization': `Bearer ${apiToken}` }
});
const { key } = await res.json();
```

**2. Environment variable**

```bash
export CORDELIA_ENCRYPTION_KEY="<64-char-hex>"
```

Used by CI pipelines, Docker containers, and advanced users who prefer explicit configuration.

**3. Platform keychain**

macOS:
```bash
# Store
security add-generic-password -a cordelia -s cordelia-encryption-key -w <key> -U
# Retrieve
security find-generic-password -a cordelia -s cordelia-encryption-key -w
```

Linux (GNOME Keyring):
```bash
# Store
echo -n <key> | secret-tool store --label='Cordelia Encryption Key' service cordelia type encryption-key
# Retrieve
secret-tool lookup service cordelia type encryption-key
```

**4. File fallback**

```bash
# ~/.cordelia/key (chmod 0600)
cat ~/.cordelia/key
```

Used when no keychain is available (headless Linux, WSL, containers).

## Vault Integration Contract (for Martin)

The vault is the first source checked by `getEncryptionKey()`. When `CORDELIA_VAULT_URL` is set:

**Request:**
```
GET {CORDELIA_VAULT_URL}/api/key
Authorization: Bearer {CORDELIA_API_TOKEN}
```

**Response (200):**
```json
{
  "key": "<64-char-hex-encryption-key>"
}
```

**Error responses:**
- `401` -- invalid or expired token (fall through to local chain)
- `403` -- user not authorized for this key
- `5xx` -- vault unavailable (fall through to local chain)

On any non-200 response, `getEncryptionKey()` logs a warning and falls through to the next source. The vault is never a hard dependency.

## Upgrade Path: Local to Registered

1. User creates account on the portal
2. Portal generates a new encryption key in the vault
3. User runs a migration command that:
   - Reads current local key (from keychain/file)
   - Re-encrypts all L2 items with the new vault key
   - Removes local key from keychain/file
4. Subsequent sessions retrieve key from vault

## Install Script Key Storage

The installer (`install.sh`) stores keys in this priority:

1. macOS: `security add-generic-password` (Keychain)
2. Linux: `secret-tool store` (GNOME Keyring)
3. Fallback: `~/.cordelia/key` with `chmod 0600`

The installer **never** writes the encryption key to shell profiles (`.zshrc`, `.bashrc`). Old installs that did this are cleaned up automatically.

## Threat Model

### What Tier 2 (local) protects against

- Casual disk access (encrypted at rest in SQLite)
- Other local users on shared machines (keychain ACL, file permissions)
- Accidental exposure in git commits (key not in any tracked file)

### What Tier 2 does NOT protect against

- Root/admin access on the machine
- Key extraction from a compromised user session
- Key loss (no recovery without backup)

### What Tier 1 (vault) adds

- Key never touches local disk (memory only, per-session retrieval)
- Key rotation without re-encryption downtime (vault handles versioning)
- Recovery via authenticated portal access
- Multi-device: same key retrieved on any machine
- Audit trail: vault logs every key access

## Key Rotation

**Tier 1 (vault):** Supported. The vault manages key versions. Old items can be decrypted with previous key versions during a rolling migration.

**Tier 2 (local):** Not supported. The key is static. To rotate, the user would need to:
1. Decrypt all items with the old key
2. Re-encrypt with a new key
3. Replace the key in keychain/file

This is deliberately not automated for local-only users to avoid complexity and data loss risk.
