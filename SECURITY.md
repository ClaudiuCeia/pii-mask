# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/ClaudiuCeia/pii-mask/security/advisories/new). Do not include sensitive details in a public issue.

Include the affected package version, runtime, impact, and the smallest reproducible example you can provide. You can expect acknowledgment through the advisory and follow-up questions when more information is needed.

## Supported Versions

Security fixes target the latest published version. Upgrade before reporting an issue that is already resolved on the default branch or in a newer release.

## Security Boundary

`pii-mask` uses pattern matching to reduce accidental PII exposure. It is not a compliance product, an exhaustive classifier, or a replacement for controls such as allowlists, path-based redaction, access restrictions, and data-retention policies.

The detector can produce false negatives and false positives. Applications remain responsible for testing their own data formats and protecting unknown or domain-specific identifiers.

The LRU cache is disabled by default. Setting `cacheSize` to a positive entry limit retains original input strings as keys and transformed strings as values until eviction or until the `PiiMasker` methods are no longer reachable. The current parser dependency independently retains up to eight complete detector input strings per loaded parser module instance in an entry-count cache; `cacheSize` controls only `pii-mask`'s LRU.
