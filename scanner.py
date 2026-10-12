"""secret-sentry: static secret scanner for source code and git history.

Looks for hardcoded credentials - API keys, tokens, private keys,
passwords - using two layers of detection:
  1. Format-specific regexes for real-world secret shapes (AWS, GitHub,
     Slack, Google, Stripe, Twilio, private-key blocks, JWTs).
  2. A generic entropy-based fallback for `name = "value"` assignments
     where the name hints at a credential and the value's Shannon entropy
     is too high to be an ordinary word or placeholder.

Two scan modes:
  - Working tree: every tracked-looking text file under a path.
  - Git history (`--history`): every added line in `git log -p`, so a
    secret that was committed and later removed is still caught.

This is a detector, not an exploitation tool: it never uses a secret it
finds, only reports where it is and tells you to rotate it.

Usage:
    python scanner.py <path>              # scan working tree
    python scanner.py <path> --history    # also scan git history
Exit code: 0 = nothing found, 1 = findings.
"""
import subprocess
import sys
from pathlib import Path

from detectors import find_regex_secrets, find_entropy_secrets

SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv",
                   "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
SKIP_FILE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip",
                       ".gz", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                       ".so", ".pyc", ".lock"}
# Files that legitimately hold example/placeholder secrets.
ALLOWLIST_NAMES = {".env.example", ".env.sample", ".env.template"}

MAX_FILE_BYTES = 2_000_000  # skip anything bigger - not source code


def redact(secret):
    if len(secret) <= 8:
        return secret[:2] + "..." + secret[-2:]
    return secret[:4] + "..." + secret[-4:]


def scan_line(line):
    """Return a list of (rule_name, category, redacted_secret, extra) for
    one line of text. The entropy fallback is skipped for any value a
    format-specific regex already caught on the same line, so a single
    AWS/GitHub/etc. secret is reported once, under its real category,
    rather than once there and once again as a generic high-entropy hit."""
    findings = []
    already_caught = set()
    for name, category, secret in find_regex_secrets(line):
        findings.append((name, category, redact(secret), None))
        already_caught.add(secret)
    for name, category, value, entropy in find_entropy_secrets(line):
        if value in already_caught:
            continue
        findings.append((name, category, redact(value), round(entropy, 2)))
    return findings


def iter_text_files(root):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_FILE_SUFFIXES:
            continue
        if p.name in ALLOWLIST_NAMES:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def scan_working_tree(root):
    """Scan every text file under `root`. Returns a list of
    (filename, lineno, rule, category, redacted, extra)."""
    results = []
    for path in iter_text_files(root):
        try:
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule, category, redacted, extra in scan_line(line):
                results.append((str(path), lineno, rule, category, redacted, extra))
    return results


def scan_git_history(root):
    """Scan every added line (`+...`) across the full git log -p for
    `root`'s repo. Returns the same tuple shape as scan_working_tree,
    with filename set to 'commit <sha>:<path>'."""
    try:
        out = subprocess.run(
            ["git", "log", "-p", "--all", "--no-color", "--unified=0"],
            cwd=root, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    results = []
    current_file = "<unknown>"
    current_sha = "<unknown>"
    for raw_line in out.stdout.splitlines():
        if raw_line.startswith("commit "):
            current_sha = raw_line.split()[1][:10]
            continue
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue
        if not raw_line.startswith("+"):
            continue
        content = raw_line[1:]
        for rule, category, redacted, extra in scan_line(content):
            results.append(
                (f"{current_sha}:{current_file}", None, rule, category,
                 redacted, extra))
    return results


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = argv[1]
    history = "--history" in argv[2:]

    findings = scan_working_tree(target)
    if history:
        findings += scan_git_history(target)

    if not findings:
        print("No secrets found.")
        return 0

    by_category = {}
    for filename, lineno, rule, category, redacted, extra in findings:
        by_category.setdefault(category, []).append(
            (filename, lineno, rule, redacted, extra))

    for category, items in sorted(by_category.items()):
        print("== %s (%d) ==" % (category, len(items)))
        for filename, lineno, rule, redacted, extra in items:
            where = f"{filename}:{lineno}" if lineno else filename
            tail = f" (entropy {extra})" if extra else ""
            print(f"  {where} - {rule}: {redacted}{tail}")

    total = len(findings)
    print(f"\n{total} finding(s) across {len(by_category)} categor"
          f"{'y' if len(by_category) == 1 else 'ies'}.")
    print("Rotate any real credential found here immediately; do not "
          "just delete the line - it is still in git history unless you "
          "also rewrite history.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
