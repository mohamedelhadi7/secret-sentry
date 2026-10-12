"""Labeled corpus for eval/benchmark.py: one line (or short snippet) per
entry, labeled with the category the scanner should find, or "safe" if it
should find nothing. Written by hand, independent of samples/, so this
is a clean benchmark rather than a re-run of the unit tests.

The "safe" entries are literal - none of them are secret-shaped, so there
is nothing for GitHub's own push protection (or this scanner) to flag.
The "vulnerable" entries are built from hex-encoded fragments and
assembled into real-shaped-but-fake secrets only here, at import time -
see samples/fragments.py for why a complete secret-shaped string should
never sit as literal plaintext in this repo's git history. All of them
are made up; none are real credentials.
"""


def _hex(s):
    return bytes.fromhex(s).decode()


# name -> (line_template, hex-encoded secret substring to fill in)
_VULN_HEX = {
    "aws_key_id_var": ('AWS_KEY = "{}"',
                        "414b4941515a524d334e54583742564c4b505743"),
    "aws_key_id_inline": ('boto3.client("s3", aws_access_key_id="{}")',
                           "414b4941573647325848503443395a544d445245"),
    "aws_secret_assignment": ('aws_secret_access_key = "{}"',
                               "6d52386b4c704e3276547a3451785762466859396a4373416533446735556f315a69374b74566e52"),
    "github_pat_classic": ('TOKEN = "{}"',
                            "6768705f39664b326d5a7152377856624e34634c705438775973416531446f4a6833477835556b30"),
    "github_oauth": ('os.environ["X"] = "{}"',
                      "67686f5f346d4b39704c785a32764e6352377154625738735965416f31446a354867335566526b4e78"),
    "github_fine_grained": ('GH_PAT = "{}"',
                             "6769746875625f7061745f313141414242434344445f70513272543878566e4d34634c7a4b376257735965416f31446a35486733556636526b4e785a7642"),
    "slack_bot_token": ('SLACK_TOKEN = "{}"',
                         "786f78622d3938373635343332313039382d313132323333343435353636372d70513272543878566e4d34634c7a4b376257735965416f"),
    "slack_webhook_url": ('WEBHOOK = "{}"',
                           "68747470733a2f2f686f6f6b732e736c61636b2e636f6d2f73657276696365732f5430414231434432452f42334647344849354a2f70513272543878566e4d34634c7a4b376257735965"),
    "google_maps_key": ('MAPS_KEY = "{}"',
                         "41497a61537942396b4c70543278566e4d3463527a4b376257735965416f31446a354853794239"),
    "stripe_live_secret": ('STRIPE_KEY = "{}"',
                            "736b5f6c6976655f34654b39704c785a32764e6352377154625738735965416f31446a354867335566526b4e785a7642"),
    "stripe_test_secret": ('STRIPE_KEY = "{}"',
                            "736b5f746573745f34654b39704c785a32764e6352377154625738735965416f31446a354867335566526b4e785a7642"),
    "jwt_hardcoded": ('AUTH = "{}"',
                       "65794a68624763694f694a49557a49314e694a392e65794a3163325679496a6f69595752746157346966512e346d4b39704c785a32764e6352377154625738735965416f31446a354867335566"),
    "generic_api_key_var": ('api_key = "{}"',
                             "34654b39704c785a32764e6352377154625738735965416f31446a354867335566"),
    "generic_password_var": ('password = "{}"',
                              "547230756234646f7239784b704c7a566e4d715a65"),
    "generic_client_secret": ('client_secret = "{}"',
                               "6d52386b4c704e3276547a3451785762466859396a4373416533446735556f"),
    "generic_auth_token_var": ('auth_token = "{}"',
                                "376257735965416f31446a35486733556636526b4e785a764234654b39704c785a"),
}


def _vuln_line(name):
    template, hexsecret = _VULN_HEX[name]
    return template.format(_hex(hexsecret))


CORPUS = [
    # ---------------- aws: vulnerable ----------------
    ("aws_key_id_var", "aws", _vuln_line("aws_key_id_var")),
    ("aws_key_id_inline", "aws", _vuln_line("aws_key_id_inline")),
    ("aws_secret_assignment", "aws", _vuln_line("aws_secret_assignment")),
    # ---------------- aws: safe ----------------
    ("aws_region_only", "safe", 'AWS_REGION = "eu-west-1"'),
    ("aws_bucket_name", "safe", 'BUCKET_NAME = "my-company-uploads-prod"'),

    # ---------------- github: vulnerable ----------------
    ("github_pat_classic", "github", _vuln_line("github_pat_classic")),
    ("github_oauth", "github", _vuln_line("github_oauth")),
    ("github_fine_grained", "github", _vuln_line("github_fine_grained")),
    # ---------------- github: safe ----------------
    ("github_repo_url", "safe", 'REPO = "https://github.com/octocat/hello-world"'),
    ("github_username", "safe", 'GITHUB_USER = "octocat"'),

    # ---------------- slack: vulnerable ----------------
    ("slack_bot_token", "slack", _vuln_line("slack_bot_token")),
    ("slack_webhook_url", "slack", _vuln_line("slack_webhook_url")),
    # ---------------- slack: safe ----------------
    ("slack_channel_name", "safe", 'CHANNEL = "#general"'),

    # ---------------- google: vulnerable ----------------
    ("google_maps_key", "google", _vuln_line("google_maps_key")),
    # ---------------- google: safe ----------------
    ("google_analytics_id", "safe", 'GA_ID = "UA-12345678-1"'),

    # ---------------- stripe: vulnerable ----------------
    ("stripe_live_secret", "stripe", _vuln_line("stripe_live_secret")),
    ("stripe_test_secret", "stripe", _vuln_line("stripe_test_secret")),
    # ---------------- stripe: safe ----------------
    ("stripe_publishable_looks_like_id", "safe", 'PLAN_ID = "price_1H6qT2zRpN8mVk"'),

    # ---------------- jwt: vulnerable ----------------
    ("jwt_hardcoded", "jwt", _vuln_line("jwt_hardcoded")),
    # ---------------- jwt: safe ----------------
    ("jwt_like_but_short", "safe", 'VALUE = "eyJ.abc.def"'),

    # ---------------- private_key: vulnerable ----------------
    ("rsa_private_key_header", "private_key", _hex("2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d")),
    ("openssh_private_key_header", "private_key", _hex("2d2d2d2d2d424547494e204f50454e5353482050524956415445204b45592d2d2d2d2d")),
    # ---------------- private_key: safe ----------------
    ("public_key_header", "safe", "-----BEGIN PUBLIC KEY-----"),
    ("certificate_header", "safe", "-----BEGIN CERTIFICATE-----"),

    # ---------------- generic: vulnerable ----------------
    ("generic_api_key_var", "generic", _vuln_line("generic_api_key_var")),
    ("generic_password_var", "generic", _vuln_line("generic_password_var")),
    ("generic_client_secret", "generic", _vuln_line("generic_client_secret")),
    ("generic_auth_token_var", "generic", _vuln_line("generic_auth_token_var")),
    # ---------------- generic: safe ----------------
    ("generic_password_placeholder", "safe", 'password = "changeme"'),
    ("generic_short_password", "safe", 'password = "abc123"'),
    ("generic_api_key_env_lookup", "safe", 'api_key = os.environ["API_KEY"]'),
    ("generic_key_as_dict_key", "safe", 'config = {"api_key_name": "primary"}'),

    # ---------------- plain safe code, no credentials at all ----------------
    ("plain_sum", "safe", "def f(a, b):\n    return a + b"),
    ("plain_url", "safe", 'ENDPOINT = "https://api.example.com/v1/users"'),
    ("plain_comment", "safe", "# TODO: wire up the real client once staging is ready"),
    ("plain_version_string", "safe", 'VERSION = "3.11.2"'),
    ("plain_uuid", "safe", 'REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"'),
    ("plain_sentence_value", "safe", 'ERROR_MSG = "the request could not be completed"'),
    ("plain_file_path", "safe", 'LOG_PATH = "/var/log/app/server.log"'),
]
