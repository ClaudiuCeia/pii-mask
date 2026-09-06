# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ClaudiuCeia/pii-mask/security/advisories/new). Do not include sensitive details in a public issue.

Include the affected package version, runtime, impact, and the smallest reproducible example you can provide. You can expect acknowledgment through the advisory and follow-up questions when more information is needed.

## Supported Versions

Security fixes target the latest published version. Upgrade before reporting an issue that is already resolved on the default branch or in a newer release.

## Security Boundary

`pii-mask` uses pattern matching to reduce accidental PII exposure. It is not a compliance product, an exhaustive classifier, or a replacement for controls such as allowlists, path-based redaction, access restrictions, and data-retention policies.

The detector can produce false negatives and false positives. Applications remain responsible for testing their own data formats and protecting unknown or domain-specific identifiers.

The optional LRU cache retains original input strings as keys and transformed strings as values until each entry is evicted or its `PiiMasker` instance becomes unreachable. Disable it with `cacheSize: 0` when retaining sensitive strings in memory is not acceptable.
