# Contributing

Issues and focused pull requests are welcome. Security reports belong in [GitHub private vulnerability reporting](https://github.com/ClaudiuCeia/pii-mask/security/advisories/new), not the public issue tracker.

## Requirements

- Bun 1.3 or newer
- Node.js 24 or newer for npm package smoke tests
- Deno 2.9 or newer for JSR checks

## Setup

```sh
bun install --frozen-lockfile
```

## Validation

Run the fast local checks while developing:

```sh
bun run check
```

Before opening a pull request, also validate the published package shapes and supported runtimes:

```sh
bun run package:check
bun run package:smoke
bun run jsr:smoke
deno publish --dry-run --allow-dirty
```

CI runs the quality suite once, exercises the installed package across the supported Bun and Node.js versions, and checks the JSR package across the supported Deno versions.

## Benchmarks

The benchmark suite uses Mitata and writes a machine-readable report. Regression checks compare median time with a 15% relative threshold and a 1 microsecond absolute floor.

```sh
# Inspect current performance
bun run bench

# Save the current build as a local baseline
bun run bench:save

# Compare a candidate build with that baseline
bun run bench:check
```

Benchmarks use generated data only. When changing detector or traversal performance, include enough context to reproduce material differences and avoid presenting a single machine's result as universal.

Baseline and candidate reports must use the same Bun version, operating system, and architecture. Save a new baseline after changing environments.

## Pull Requests

Keep changes scoped, add tests for behavior changes, and update documentation when public behavior or compatibility changes. Do not edit package versions or publish artifacts as part of a routine pull request.
