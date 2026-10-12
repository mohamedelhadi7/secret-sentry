"""Builds the TEXT CONTENT of a deliberately-vulnerable sample file from
samples/fragments.py, entirely in memory. Nothing here is written to a
file that gets committed to git - tests and the demo write the result to
a temp path, scan it, and let it get cleaned up.

The assembled secrets are fake (made up, not real credentials) but
real-shaped, which is exactly what a secret scanner needs to be tested
against - and exactly why the complete strings are kept out of git
history, see fragments.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fragments import decode

TEMPLATE = '''"""Deliberately contains fake-but-well-formed secrets, assembled at
run time from samples/fragments.py - see that file for why. None of
these are real credentials.
"""

AWS_ACCESS_KEY_ID = "{aws_access_key_id}"
AWS_SECRET_ACCESS_KEY = "{aws_secret_access_key}"

GITHUB_TOKEN = "{github_token}"

SLACK_BOT_TOKEN = "{slack_bot_token}"

GOOGLE_API_KEY = "{google_api_key}"

STRIPE_SECRET_KEY = "{stripe_live_key}"

JWT_TOKEN = "{jwt}"

PRIVATE_KEY = """{private_key_block}"""


def connect_to_db(password="{generic_password}"):
    """password= looks like a real credential by name + high entropy."""
    return password


def legit_config():
    db_host = "localhost"
    db_port = 5432
    return db_host, db_port
'''

FIELDS = ["aws_access_key_id", "aws_secret_access_key", "github_token",
          "slack_bot_token", "google_api_key", "stripe_live_key", "jwt",
          "private_key_block", "generic_password"]


def build_source():
    """Return the full Python source text, with fake-but-real-shaped
    secrets filled in, as a plain string (never written to a tracked
    file)."""
    return TEMPLATE.format(**{name: decode(name) for name in FIELDS})


def write_to(path):
    """Write the assembled source to `path` (meant to be a temp file,
    not anything tracked in git) and return the path."""
    Path(path).write_text(build_source())
    return path


if __name__ == "__main__":
    # Demo entry point: write the vulnerable file to /tmp and scan it,
    # so `python samples/build_vulnerable.py` is a one-shot, repo-safe
    # way to see the scanner catch every category.
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile(
            mode="w", suffix="_vulnerable_demo.py", delete=False) as fh:
        fh.write(build_source())
        tmp_path = fh.name
    print(f"Wrote a demo vulnerable file to {tmp_path}\n")
    root = Path(__file__).resolve().parent.parent
    subprocess.run([sys.executable, str(root / "scanner.py"), tmp_path])
