"""The fixed version: every credential is read from the environment
instead of being hardcoded, so the scanner should report nothing here."""
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")


def connect_to_db(password=None):
    password = password or os.environ["DB_PASSWORD"]
    return password


def legit_config():
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = int(os.environ.get("DB_PORT", "5432"))
    return db_host, db_port


# Example/placeholder values that must NOT be flagged.
EXAMPLE_API_KEY = "your_api_key_here"
PLACEHOLDER_TOKEN = "changeme"
SAMPLE_PASSWORD = "sample"
