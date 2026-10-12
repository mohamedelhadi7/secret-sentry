"""Regex and entropy-based secret detectors.

Each regex detector is a (name, category, compiled_pattern, redact_groups)
tuple. `redact_groups` lists which regex groups hold the actual secret
material, so the reporter can show a short, safe preview (first/last 4
chars) instead of the full key.

Regex rules are deliberately specific to real-world secret formats (AWS,
GitHub, Slack, Google, Stripe, Twilio, private-key blocks, JWTs) because a
format-specific prefix (e.g. `AKIA`, `ghp_`, `sk_live_`) is a much stronger
signal than a bare "looks random" heuristic, and it lets us say exactly
what kind of credential was found.

The entropy detector is the fallback for secrets with no recognizable
format: a generic `name = "<random-looking string>"` assignment where the
variable name suggests a credential and the value's Shannon entropy is
high enough that it's unlikely to be an English word, a placeholder, or a
short code.
"""
import math
import re

# ---------------------------------------------------------------------------
# Format-specific regex detectors
# ---------------------------------------------------------------------------
# Each pattern captures the secret itself in group 1 (or the named group
# 'secret') so it can be redacted in reports.

REGEX_RULES = [
    ("aws_access_key_id", "aws",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret_access_key", "aws",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("github_token", "github",
     re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("github_fine_grained_pat", "github",
     re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("slack_token", "slack",
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b")),
    ("slack_webhook", "slack",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)")),
    ("google_api_key", "google",
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("stripe_live_key", "stripe",
     re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b")),
    ("stripe_test_key", "stripe",
     re.compile(r"\b(sk_test_[A-Za-z0-9]{20,})\b")),
    ("twilio_api_key", "twilio",
     re.compile(r"\b(SK[a-f0-9]{32})\b")),
    ("jwt", "jwt",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("private_key_block", "private_key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("generic_assignment", "generic",
     re.compile(
         r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
         r"client[_-]?secret|private[_-]?token|password|passwd|pwd)\b"
         r"\s*[:=]\s*['\"]([A-Za-z0-9/_+.=-]{16,})['\"]")),
]

# Placeholder / example values that should never be flagged even if they
# match a rule, because they aren't real secrets.
PLACEHOLDER_HINTS = (
    "example", "xxxx", "xxxxxxxx", "changeme", "change_me", "your_api_key",
    "your-api-key", "yourkey", "placeholder", "redacted", "0000000000",
    "1111111111", "sample", "dummy", "fakekey", "test_key_1234",
    "insert_key_here", "<your", "***", "...", "foobar", "notarealsecret",
)


def is_placeholder(value):
    low = value.lower()
    if low in PLACEHOLDER_HINTS:
        return True
    return any(hint in low for hint in PLACEHOLDER_HINTS)


def find_regex_secrets(line):
    """Return a list of (rule_name, category, matched_secret) for `line`."""
    findings = []
    for name, category, pattern in REGEX_RULES:
        for m in pattern.finditer(line):
            secret = m.group(1) if m.groups() else m.group(0)
            if is_placeholder(secret):
                continue
            findings.append((name, category, secret))
    return findings


# ---------------------------------------------------------------------------
# Entropy-based generic detector (fallback for unrecognized formats)
# ---------------------------------------------------------------------------

SECRET_NAME_HINTS = (
    "key", "token", "secret", "password", "passwd", "pwd", "credential",
    "apikey", "auth",
)

# A generic `name = "value"` assignment, used only for the entropy check
# (separate from generic_assignment above, which is stricter about length).
ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")

B64_CHARSET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def looks_like_prose_or_code(value):
    """Cheap filters for things that are high-entropy but not secrets:
    sentences (spaces), file paths, URLs without credentials, UUIDs that
    are clearly just identifiers (handled by caller), version strings."""
    if " " in value:
        return True
    if value.count(".") >= 3 and all(p.isdigit() or p == "" for p in value.split(".")):
        return True  # version string / IP-looking
    return False


def find_entropy_secrets(line, min_entropy=3.5, min_length=16):
    """Flag `name = "value"` assignments where `name` hints at a credential
    and `value` has high enough entropy to not be a placeholder/word."""
    findings = []
    for m in ASSIGNMENT_RE.finditer(line):
        var_name, value = m.group(1), m.group(2)
        if not any(h in var_name.lower() for h in SECRET_NAME_HINTS):
            continue
        if len(value) < min_length:
            continue
        if is_placeholder(value):
            continue
        if looks_like_prose_or_code(value):
            continue
        if not all(c in B64_CHARSET for c in value):
            continue
        ent = shannon_entropy(value)
        if ent >= min_entropy:
            findings.append(("high_entropy_assignment", "generic", value, ent))
    return findings
