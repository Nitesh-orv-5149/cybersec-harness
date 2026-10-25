# Secrets fixtures

- `gitleaks-8.24.3.report.json`: real `gitleaks dir . --redact --report-format json` output (Gitleaks 8.24.3) for a throwaway
  project whose fake credentials were assembled at runtime. Every `Secret`/`Match` is `REDACTED`; no credential-shaped
  string is committed, so the repository itself does not trip secret scanning. Tests that need real matches build
  the fake values from string fragments in a temporary directory.
