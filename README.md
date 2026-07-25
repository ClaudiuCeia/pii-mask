# @claudiu-ceia/pii-mask

Deterministic PII masking and redaction for TypeScript applications and logs.

[![CI](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@claudiu-ceia/pii-mask.svg)](https://www.npmjs.com/package/@claudiu-ceia/pii-mask)
[![license](https://img.shields.io/npm/l/@claudiu-ceia/pii-mask.svg)](LICENSE)

`pii-mask` uses [`@claudiu-ceia/ts-duckling`](https://github.com/ClaudiuCeia/ts-duckling) directly for local, grammar-based PII detection. It adds masking and redaction policies, immutable structured-value traversal, and opt-in plugins for Pino and Winston. There are no network calls and no logger monkeypatching.

## Install

```sh
bun add @claudiu-ceia/pii-mask
```

Install the optional peer for the logger adapter you use:

```sh
bun add pino
# or
bun add winston
```

The package is ESM-only. It supports Bun 1.3+ and Node.js 20+.

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

Measured overhead of the Pino hook over plain Pino (Bun 1.3, median of 21 samples):

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

```sh
bun install
bun run check
bun run package:check
```

The project uses Bun, TypeScript 7, Oxfmt, Oxlint, Knip, Publint, and Bun's test runner.

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

`bench:check` fails when any median time per operation regresses by more than 15%. Pass a different threshold directly to the comparator when needed:

```sh
bun run bench:compare -- .benchmarks/baseline.json .benchmarks/current.json 10
```

Pull requests run the same suite against the base and candidate commits on one GitHub runner. The `BENCHMARK_THRESHOLD_PERCENT` value in `.github/workflows/performance.yml` controls the CI budget.

## License

MIT © [Claudiu Ceia](https://github.com/ClaudiuCeia)
