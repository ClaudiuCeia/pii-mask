# @claudiu-ceia/pii-mask

Deterministic PII masking and redaction for TypeScript applications and logs on Bun, Deno, and Node.js.

[![CI](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@claudiu-ceia/pii-mask.svg)](https://www.npmjs.com/package/@claudiu-ceia/pii-mask)
[![jsr](https://jsr.io/badges/@claudiu-ceia/pii-mask.svg)](https://jsr.io/@claudiu-ceia/pii-mask)
[![license](https://img.shields.io/npm/l/@claudiu-ceia/pii-mask?style=flat-square&label=license)](LICENSE)

`pii-mask` uses [`@claudiu-ceia/ts-duckling`](https://github.com/ClaudiuCeia/ts-duckling) directly for local, grammar-based PII detection. It adds masking and redaction policies, immutable structured-value traversal, and opt-in plugins for Pino and Winston. There are no network calls and no logger monkeypatching.

## Install

### Bun

```sh
bun add @claudiu-ceia/pii-mask
```

### Deno

```sh
deno add jsr:@claudiu-ceia/pii-mask@^0.2.0
```

Deno 2.9's default dependency-age policy may defer a release published within the last 24 hours.
Current Deno versions can bypass it by adding `--min-dep-age=0` to the install command. On Deno
2.9.0, wait for the policy window or temporarily add `jsr:@claudiu-ceia/pii-mask`,
`jsr:@claudiu-ceia/ts-duckling`, and `jsr:@claudiu-ceia/combine` to
`minimumDependencyAge.exclude` in `deno.json`.

### Node.js

```sh
npm install @claudiu-ceia/pii-mask
```

Install the optional peer for the logger adapter you use:

```sh
bun add pino # or winston
npm install pino # or winston
deno add npm:pino@^10 # or npm:winston@^3.3
```

The package is ESM-only. It supports Bun 1.3+, Deno 2.9+, and Node.js 24+.

## Text

```ts
import { findPii, maskText, redactText } from "@claudiu-ceia/pii-mask";

maskText("Email jane@example.com");
// "Email ****************"

maskText("Card 4242 4242 4242 4242", {
  keepStart: 4,
  keepEnd: 4,
});
// "Card 4242***********4242"

redactText("Email jane@example.com from 192.168.0.1");
// "Email [REDACTED] from [REDACTED]"

redactText("Email jane@example.com", {
  replacement: ({ kind }) => `[REDACTED:${kind}]`,
});
// "Email [REDACTED:email]"

findPii("Email jane@example.com");
// [{ kind: "email", start: 6, end: 22, text: "jane@example.com", ... }]
```

Use `kinds` to transform only selected PII kinds:

```ts
maskText("jane@example.com from 192.168.0.1", {
  kinds: ["email"],
});
// "**************** from 192.168.0.1"
```

The supported kinds come from `ts-duckling`'s `PIIParsers`: `email`, `phone`, `ip`, `ssn`, `credit_card`, `uuid`, `api_key`, `iban`, `mac_address`, `jwt`, `crypto_address`, and `bic`.

## Structured Values

`maskValue` and `redactValue` recursively protect strings in arrays, plain objects, and errors. They return a copy and do not mutate the input.

```ts
import { maskValue, redactValue } from "@claudiu-ceia/pii-mask";

const safe = maskValue({
  message: "Contact jane@example.com",
  context: { ip: "192.168.0.1" },
});

// {
//   message: "Contact ****************",
//   context: { ip: "***********" },
// }

redactValue(new Error("Request from 192.168.0.1"));
// Error: Request from [REDACTED]
```

Dates, buffers, maps, sets, and other class instances are retained as-is. Cycles in transformed values are preserved.

For repeated use, create one configured protector:

```ts
import { createPiiMasker } from "@claudiu-ceia/pii-mask";

const protector = createPiiMasker({
  mode: "redact",
  replacement: ({ kind }) => `<${kind}>`,
});

protector.text("Email jane@example.com");
protector.value({ email: "jane@example.com" });
```

## Pino

The Pino plugin returns a normal `hooks.logMethod` configuration. It protects arguments before Pino serializes them.
Pino applications running under Deno also need `--allow-sys=hostname`, which Pino uses for its default bindings.

```ts
import pino from "pino";
import { pinoPiiMasking } from "@claudiu-ceia/pii-mask/pino";

const logger = pino(
  pinoPiiMasking({
    mode: "redact",
    replacement: "[PII]",
  }),
);

logger.info({ email: "jane@example.com" }, "User from 192.168.0.1");
```

If you already use a `logMethod` hook, compose its behavior explicitly; Pino accepts one hook at that position.

## Winston

The Winston plugin is a regular format. Put it before finalizing formats such as `json()` and `simple()`.

```ts
import winston from "winston";
import { winstonPiiMasking } from "@claudiu-ceia/pii-mask/winston";

const logger = winston.createLogger({
  format: winston.format.combine(winstonPiiMasking({ mode: "redact" }), winston.format.json()),
  transports: [new winston.transports.Console()],
});
```

## API

- `findPii(input)` returns the detected `PIIEntity[]` spans.
- `maskText(input, options?)` repeats a mask token across detected spans.
- `redactText(input, options?)` replaces each detected span once.
- `maskValue(input, options?)` immutably masks nested string values.
- `redactValue(input, options?)` immutably redacts nested string values.
- `createPiiMasker(options?)` creates reusable `text` and `value` operations.
- `pinoPiiMasking(options?)` is exported from `@claudiu-ceia/pii-mask/pino`.
- `winstonPiiMasking(options?)` is exported from `@claudiu-ceia/pii-mask/winston`.

## Performance

`createPiiMasker` (and therefore both logger plugins) keeps a bounded LRU cache of transformed strings — 1,024 entries by default. Logging traffic repeats routes, messages, and metadata constantly, so cached strings cost almost nothing. Tune or disable it with `cacheSize`:

```ts
createPiiMasker({ cacheSize: 4096 }); // larger cache
createPiiMasker({ cacheSize: 0 }); // disabled, every string is re-scanned
```

Measured overhead of the Pino hook over plain Pino (Bun 1.3, median of 13 samples):

| Scenario                                     |   Plain | Protected |           Added |
| -------------------------------------------- | ------: | --------: | --------------: |
| Small log object                             | ~0.8 µs |   ~1.4 µs |         ~0.6 µs |
| Realistic HTTP log (repeated strings)        | ~1.3 µs |   ~3.5 µs |           ~2 µs |
| Realistic HTTP log (unique PII per call)     |   ~1 µs |    ~21 µs |          ~20 µs |
| 700 KB batch payload, 10k unique PII strings | ~180 µs |   ~320 ms | detection-bound |

Grammar-based detection costs scale with the number of unique PII-like strings. Very large one-off payloads are the worst case; prefer logging such payloads selectively or scoping `kinds` to what you actually need to hide.

Pull requests run the full benchmark suite — including all logger scenarios — against the base commit and fail on regressions over 15%.

## Security Notes

PII detection is grammar-based. It can produce false positives and false negatives, especially for ambiguous numeric identifiers and domain-specific secrets. Test it against representative data and use logger-native key redaction alongside this package when fields are known to be sensitive.

Only string values are inspected. Object keys and arbitrary class instances are not transformed. Avoid logging raw secrets that no configured parser can recognize.

## Development

Bun owns the development toolchain:

```sh
bun install
bun run check
bun run build
bun run package:check
```

`bun run check` runs Oxfmt, Oxlint, TypeScript, the Bun test suite, and Knip.
Deno is required locally only to validate the JSR package with
`deno publish --dry-run --allow-dirty`. Releases are published exclusively by pushing a matching
version tag, which preserves trusted-publishing provenance for both registries.

`bun run package:check` validates the package metadata, installs the packed artifact with both
Bun and npm, checks isolated optional-peer configurations and lower bounds, typechecks consumers,
and runs it with Bun and Node.

Install the optional pre-commit hook with `bun run hooks:install`.

### Benchmarks

Run the benchmark suite locally:

```sh
bun run bench
```

Save a local baseline, make a change, then compare against it:

```sh
bun run bench:save
bun run bench:check
```

`bench:check` gates non-reference scenarios on minimum time per operation. It fails when a result
regresses by more than 15% and by more than the 1 µs absolute noise floor. Pass a different
percentage threshold directly to the comparator when needed:

```sh
bun run bench:compare -- .benchmarks/baseline.json .benchmarks/current.json 10
```

Pull requests run the same suite against the base and candidate commits on one GitHub runner. The `BENCHMARK_THRESHOLD_PERCENT` value in `.github/workflows/ci.yml` controls the CI budget.

## License

MIT © [Claudiu Ceia](https://github.com/ClaudiuCeia)
