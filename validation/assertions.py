"""Strategy-specific positive assertions run on patched files after a fix.

Each assertion is keyed on the remediation `strategy` declared in
config/compliance_rules.yaml. It returns (passed, message).

These assertions layer POSITIVE checks on top of what the targeted re-scan
already does (negative check: original detection pattern no longer matches).
Example: for replace_with_env_var we need to see that the literal secret is
gone AND that an env-var reference exists — otherwise the AI might have
"fixed" the rule by deleting the code entirely.

Strategies without a cheap positive check (parameterize_queries, sanitize_output,
safe_deserialization, upgrade_dependency, pin_versions, enable_branch_protection)
intentionally have no assertion. For those, the validator relies on targeted
re-scan + the repo's existing tests.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable, Optional

# (absolute patched file paths, repo root) -> (passed, message)
AssertionFn = Callable[[list[str], str], tuple[bool, str]]


def _read(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""


_ENV_REF = re.compile(
    r"os\.environ|os\.getenv|process\.env|System\.getenv|ENV\[|Deno\.env|std::env::var",
    re.IGNORECASE,
)
_HARDCODED_SECRET = re.compile(
    r"""(?ix)
    (api[_-]?key|apikey|secret|password|passwd|pwd|token)
    \s*[:=]\s*
    ['"][A-Za-z0-9+/=_\-]{16,}['"]
    """
)
_AWS_KEY = re.compile(
    r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"][^'\"]+"
)
_GHP_TOKEN = re.compile(r"ghp_[A-Za-z0-9]{36}")
_SK_TOKEN = re.compile(r"sk-[A-Za-z0-9]{32,}")

_FROM_LATEST = re.compile(
    r"^\s*FROM\s+[^\s@#]+:latest\b", re.MULTILINE | re.IGNORECASE
)
_FROM_UNTAGGED = re.compile(
    r"^\s*FROM\s+[^\s:@#]+(\s|$)", re.MULTILINE | re.IGNORECASE
)
_USER_NON_ROOT = re.compile(
    r"^\s*USER\s+(?!(?:root|0)\s*$)\S+", re.MULTILINE | re.IGNORECASE
)
_ENV_SECRET = re.compile(
    r"^\s*(ENV|ARG)\s+(PASSWORD|SECRET|TOKEN|API_KEY)",
    re.MULTILINE | re.IGNORECASE,
)
_COPY_SECRET_FILE = re.compile(
    r"^\s*COPY\b[^\n]*\.(env|key|pem|crt)\b", re.MULTILINE | re.IGNORECASE
)

_OPEN_CIDR = re.compile(r"0\.0\.0\.0/0")
_ENCRYPTED_FALSE = re.compile(
    r"(?i)(encrypted\s*=\s*false|encryption_disabled\s*=\s*true)"
)
_PUBLIC_ACL = re.compile(
    r'(?i)(acl\s*=\s*["\'](public-read|public-read-write)["\']'
    r'|block_public_acls\s*=\s*false)'
)
_INSECURE_TLS = re.compile(
    r"(?i)(ssl_verify\s*=\s*false"
    r"|verify\s*=\s*false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
    r"|InsecureSkipVerify:\s*true)"
)

_WRITE_ALL = re.compile(r"permissions:\s*write-all")
_UNPINNED_ACTION = re.compile(r"uses:\s+[^@\s]+@(main|master|latest)\b")
_ECHO_SECRET = re.compile(
    r"echo\s+[^\n]*\$\{?[^}\n]*(SECRET|TOKEN|PASSWORD)", re.IGNORECASE
)


def _assert_env_var_replacement(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        content = _read(f)
        if (
            _HARDCODED_SECRET.search(content)
            or _AWS_KEY.search(content)
            or _GHP_TOKEN.search(content)
            or _SK_TOKEN.search(content)
        ):
            return False, f"{f}: hardcoded secret pattern still present"
        if not _ENV_REF.search(content):
            return False, f"{f}: no environment variable reference after remediation"
    return True, "secret externalized to env/vault reference"


def _assert_non_root_user(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if not _USER_NON_ROOT.search(_read(f)):
            return False, f"{f}: missing non-root USER directive"
    return True, "non-root USER directive present"


def _assert_pinned_base_image(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        content = _read(f)
        if _FROM_LATEST.search(content):
            return False, f"{f}: :latest tag still present"
        if _FROM_UNTAGGED.search(content):
            return False, f"{f}: FROM directive without explicit tag"
    return True, "base images pinned"


def _assert_build_secrets(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        content = _read(f)
        if _ENV_SECRET.search(content):
            return False, f"{f}: ENV/ARG still declares secret"
        if _COPY_SECRET_FILE.search(content):
            return False, f"{f}: still copies secret file into image"
    return True, "no build-time secrets exposed"


def _assert_restrict_cidr(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _OPEN_CIDR.search(_read(f)):
            return False, f"{f}: 0.0.0.0/0 CIDR still present"
    return True, "no open CIDR blocks"


def _assert_enable_encryption(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _ENCRYPTED_FALSE.search(_read(f)):
            return False, f"{f}: encryption still disabled"
    return True, "encryption enabled"


def _assert_make_private(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _PUBLIC_ACL.search(_read(f)):
            return False, f"{f}: public ACL still present"
    return True, "bucket not public"


def _assert_tls_verify(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _INSECURE_TLS.search(_read(f)):
            return False, f"{f}: insecure TLS setting still present"
    return True, "TLS verification enabled"


def _assert_restrict_permissions(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _WRITE_ALL.search(_read(f)):
            return False, f"{f}: permissions: write-all still present"
    return True, "workflow permissions restricted"


def _assert_pin_action_sha(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _UNPINNED_ACTION.search(_read(f)):
            return False, f"{f}: action still pinned to a branch (main/master/latest)"
    return True, "actions pinned to SHA or stable tag"


def _assert_mask_secrets(files: list[str], repo_root: str) -> tuple[bool, str]:
    for f in files:
        if _ECHO_SECRET.search(_read(f)):
            return False, f"{f}: echo of secret variable still present"
    return True, "no secret echo statements"


def _assert_security_policy(files: list[str], repo_root: str) -> tuple[bool, str]:
    for candidate in ("SECURITY.md", ".github/SECURITY.md"):
        if os.path.exists(os.path.join(repo_root, candidate)):
            return True, f"{candidate} present"
    return False, "SECURITY.md not created"


def _assert_codeowners(files: list[str], repo_root: str) -> tuple[bool, str]:
    for candidate in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        if os.path.exists(os.path.join(repo_root, candidate)):
            return True, f"{candidate} present"
    return False, "CODEOWNERS not created"


def _assert_lockfile(files: list[str], repo_root: str) -> tuple[bool, str]:
    for candidate in (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "go.sum",
        "Cargo.lock",
    ):
        if os.path.exists(os.path.join(repo_root, candidate)):
            return True, f"{candidate} present"
    return False, "no lockfile present after remediation"


ASSERTIONS: dict[str, AssertionFn] = {
    "replace_with_env_var": _assert_env_var_replacement,
    "externalize_to_vault": _assert_env_var_replacement,
    "add_non_root_user": _assert_non_root_user,
    "pin_base_image": _assert_pinned_base_image,
    "use_build_secrets": _assert_build_secrets,
    "restrict_cidr": _assert_restrict_cidr,
    "enable_encryption": _assert_enable_encryption,
    "make_private": _assert_make_private,
    "enable_tls_verify": _assert_tls_verify,
    "restrict_permissions": _assert_restrict_permissions,
    "pin_action_sha": _assert_pin_action_sha,
    "mask_secrets": _assert_mask_secrets,
    "generate_security_policy": _assert_security_policy,
    "generate_codeowners": _assert_codeowners,
    "generate_lockfile": _assert_lockfile,
}


def get_assertion(strategy: str) -> Optional[AssertionFn]:
    """Return the assertion for a strategy, or None if no positive check applies."""
    return ASSERTIONS.get(strategy)
