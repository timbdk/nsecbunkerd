# Signer Service Configuration

The signer daemon is configured primarily through environment variables.

> [!WARNING]
> **Legacy `nsecbunker.json` Key Deprecation**:
> Legacy key configuration in `nsecbunker.json` (`admin.key`, `keys.admin`, or `admin.npubs`) is deprecated and rejected at boot with a fatal exit. All daemon identities and encryption keys must be configured via environment variables.

## Required Environment Variables

| Variable | Type | Description |
| :--- | :--- | :--- |
| `SIGNER_KEK` | Hex (64 chars / 256 bits) | Vault Key Encryption Key (KEK) root. Memory-only, used for AES-256-GCM encryption of stored vault keys. Never used for signing. |
| `SIGNER_DAEMON_KEY` | Hex (5,120 chars) | Daemon ML-DSA-44 secret key. Serves as the consolidated service signing identity for both the daemon NDK and admin interfaces, and signs platform endorsements. |
| `SIGNER_DAEMON_ECDH_KEY` | Hex (64 chars) | Classical secp256k1 secret key used for daemon NIP-44/ECDH encryption operations. |
| `VERITY_PLATFORM_ID` | Hex (64 chars) | Platform root key identifier (SHA-256 hash). Required for verifying platform chain endorsements. |

## Optional Environment Variables

| Variable | Type | Description |
| :--- | :--- | :--- |
| `SIGNER_UID` | Hex (64 chars) | Identity guard (`H(daemon signing public key)`). When present, startup fails if derived UID does not match. |
| `ADMIN_UIDS` | Comma-separated hex | Allowed UIDs for administrative RPC commands (e.g. `create_account`, `rename_account`). |
| `RELAYS` | Comma-separated URLs | Nostr relay endpoints to connect to for NIP-46 client requests and endorsements. |
| `DATABASE_URL` | String URI | SQLite database location (default: `file:/app/config/nsecbunker.db`). |
| `PORT` | Number | Port for daemon HTTP / status listener (default: `3000`). |
| `AUDIT_LOG_PATH` | Path string | Filesystem path for audit log storage (default: `/app/logs/audit`). |
| `VERITY_SERIALIZATION_PREFIX` | Number | Numeric event serialization prefix (injected by environment). |
