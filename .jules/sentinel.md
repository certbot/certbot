## 2025-02-14 - Insecure Default File Permissions
**Vulnerability:** `certbot.util.unique_file` defaulted to `0o777` permissions, potentially allowing world-write access to created files if the caller didn't specify strict permissions.
**Learning:** Utility functions often default to permissive modes (relying on umask), but security-sensitive tools should default to secure modes (e.g., `0o600`).
**Prevention:** Audit default parameter values for file creation functions. Prefer restrictive defaults (`0o600` or `0o700`).
