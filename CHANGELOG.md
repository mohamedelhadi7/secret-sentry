v1 (initial release): format-specific regex detectors for AWS, GitHub,
Slack, Google, Stripe, Twilio, JWT and PEM private-key secrets, plus a
Shannon-entropy fallback for generic `name = "value"` credential
assignments. Working-tree and git-history scan modes. 39-example,
8-category benchmark: 100% recall/precision (self-authored corpus - see
README for the honesty caveat). GitHub Actions CI runs the tests, the
benchmark, and the scanner against its own source on every push.
