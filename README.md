# @claudiu-ceia/pii-mask

Detect and redact common PII formats in TypeScript backend logs before they leave your process.

[![CI](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/ClaudiuCeia/pii-mask/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@claudiu-ceia/pii-mask.svg)](https://www.npmjs.com/package/@claudiu-ceia/pii-mask)
[![JSR](https://jsr.io/badges/@claudiu-ceia/pii-mask.svg)](https://jsr.io/@claudiu-ceia/pii-mask)
[![license](https://img.shields.io/npm/l/@claudiu-ceia/pii-mask.svg)](./LICENSE)

`pii-mask` detects 12 common PII formats inside messages and nested values, then returns a redacted or masked copy without mutating the input. Detection runs synchronously in your process, makes no network calls, and integrates with Pino and Winston without patching either logger.

## Quick Start

```sh
bun add @claudiu-ceia/pii-mask pino
```

```ts
import pino from "pino";
import { pinoPiiMasking } from "@claudiu-ceia/pii-mask/pino";

const logger = pino(
  pinoPiiMasking({
    mode: "redact",
    replacement: "[PII]",
  }),
);

logger.info(
  {
    user: { email: "person@example.com" },
    card: "4111 1111 1111 1111",
  },
  "Request from 192.168.1.20",
);

// user.email -> "[PII]"
// card       -> "[PII]"
// message    -> "Request from [PII]"
```

The same matcher can protect values before they reach any logger or storage boundary:

```ts
import { redactValue } from "@claudiu-ceia/pii-mask";

const event = {
  message: "Contact person@example.com",
  client: { ip: "192.168.1.20" },
};

const safeEvent = redactValue(event, { replacement: "[PII]" });

console.log(safeEvent);
// {
//   message: "Contact [PII]",
//   client: { ip: "[PII]" },
// }

console.log(event.client.ip);
// "192.168.1.20"; the input was not mutated
```

## Why pii-mask

- Protects free-form messages and nested structured values, not only known object paths.
- Provides redaction and character masking through one detector set.
- Preserves cycles and clones supported arrays, plain objects, and `Error` values.
- Includes a standard Pino hook and a Winston format.
- Uses configurable PII kinds and an optional bounded LRU cache.
- Supports Bun 1.3+, Deno 2.9+, and Node.js 24+ from one ESM package.

## Detected PII

| Kind                   | Examples                        |
| ---------------------- | ------------------------------- |
| Identity               | Email, phone, SSN               |
| Network and device     | IPv4, IPv6, MAC address, UUID   |
| Payment and banking    | Credit card, IBAN, BIC          |
| Credentials and tokens | JWT, API key                    |
| Blockchain             | Common cryptocurrency addresses |

The corresponding API kinds are `email`, `phone`, `ip`, `ssn`, `credit_card`, `uuid`, `api_key`, `iban`, `mac_address`, `jwt`, `crypto_address`, and `bic`.

Detection is pattern-based and best-effort. See [Security](#security) before using it at a sensitive boundary.

## Installation

```sh
# Bun
bun add @claudiu-ceia/pii-mask

# npm
npm install @claudiu-ceia/pii-mask

# Deno and JSR-aware tooling
deno add jsr:@claudiu-ceia/pii-mask@^0.2.0
```

Install `pino` or `winston` as an optional peer when using its adapter. The Pino adapter requires Pino 10 because it protects the final serialized entry with `hooks.streamWrite`. Pino applications running under Deno also need `--allow-sys=hostname`, which Pino uses for its default bindings.

Deno 2.9's default dependency-age policy may defer a release published within the last 24 hours. Current Deno versions can bypass it with `--min-dep-age=0`. On Deno 2.9.0, wait for the policy window or temporarily exclude this package and its JSR dependencies from `minimumDependencyAge`.

The package is ESM-only. The npm artifact includes JavaScript and type declarations; JSR consumers use the TypeScript source.

## Pino

The Pino adapter returns a standard `hooks.streamWrite` configuration. It transforms the complete serialized entry after base and child bindings, serializers, mixins, and message prefixes have been applied.

```ts
import pino from "pino";
import { pinoPiiMasking } from "@claudiu-ceia/pii-mask/pino";

const logger = pino({
  level: "info",
  redact: ["req.headers.authorization", "user.internalId"],
  ...pinoPiiMasking({ mode: "redact" }),
});
```

Use Pino's path-based `redact` option alongside `pii-mask` for fields you always consider sensitive, even when their value does not match a supported PII format. If you already use a `streamWrite` hook, compose the behaviors explicitly because Pino accepts one hook at that position. Invalid JSON from a preceding hook fails closed with the non-retryable `PinoOutputError` code `PII_MASK_INVALID_PINO_OUTPUT`. Pino diagnostics-channel subscribers and metadata-aware destinations observe data before `streamWrite` performs the transformation, so they must be treated as unprotected sinks.

## Winston

The Winston adapter is a regular format. Put it before finalizing formats such as `json()` and `simple()`.

```ts
import winston from "winston";
import { winstonPiiMasking } from "@claudiu-ceia/pii-mask/winston";

const logger = winston.createLogger({
  format: winston.format.combine(winstonPiiMasking({ mode: "redact" }), winston.format.json()),
  transports: [new winston.transports.Console()],
});
```

## Core API

```ts
import {
  createPiiMasker,
  findPii,
  maskText,
  maskValue,
  redactText,
  redactValue,
} from "@claudiu-ceia/pii-mask";

findPii("Email person@example.com");
// [{ kind: "email", text: "person@example.com", start: 6, end: 24, ... }]

redactText("Email person@example.com");
// "Email [REDACTED]"

maskText("Card 4111 1111 1111 1111", { keepStart: 4, keepEnd: 4 });
// "Card 4111***********1111"

maskValue({ email: "person@example.com" });
redactValue({ ip: "192.168.1.20" });

const protector = createPiiMasker({
  mode: "redact",
  replacement: ({ kind }) => `[${kind}]`,
  kinds: ["email", "ip", "jwt"],
  cacheSize: 2_048,
});

protector.text("Email person@example.com");
protector.value({ ip: "192.168.1.20" });
```

`maskValue` and `redactValue` recursively transform string values in arrays, plain objects, errors, and the own enumerable data properties of class instances and callable objects. They preserve cycles and return a copy without mutating the input. Boxed strings become protected primitive strings. Other objects and callables become null-prototype records, so inherited methods, accessors, non-enumerable state, and custom `toJSON` methods are not retained or invoked. Transformed errors use the base `Error` prototype and protect own data properties for their name, message, stack, cause, and enumerable metadata without invoking inherited accessors.

Their `ProtectedValue<T>` return type widens transformed string literals and preserves unaugmented tuple item structure. Object types, including structurally typed errors, expose optional readonly non-callable data with recursively readonly nested arrays because TypeScript cannot prove runtime prototypes or guarantee that accessors, methods, and subclass state are copied. Augmented tuples and other arrays retain their element type without promising custom or array-subclass members.

The cache is disabled by default and local to each protector. Set `cacheSize` to a positive entry limit to enable it. Every LRU entry retains the original input string as its key and the transformed string as its value until eviction or until the protector's methods are no longer reachable. The current parser dependency independently retains up to eight complete detector input strings per loaded parser module instance in an entry-count cache; `cacheSize` controls only `pii-mask`'s LRU.

## Performance

The benchmark suite uses [Mitata](https://github.com/evanwashere/mitata) and covers direct detection, string transformation, nested values from small to large, and Pino hook overhead. CI compares median time for the candidate and base builds, then fails protected benchmark regressions above 15% with a 1 microsecond absolute floor.

```sh
bun run bench
```

Detection cost scales with unique input strings and payload size. Very large one-off payloads are the worst case, so log them selectively. Run the suite in your deployment environment when performance is part of the decision.

## Security

Pattern matching reduces accidental PII exposure. It does not prove that data is safe or that a system complies with a privacy standard.

- False negatives and false positives are possible.
- Object keys are not inspected or transformed.
- Unknown and domain-specific identifiers require separate rules.
- Non-string scalar values are not transformed.
- An explicitly enabled cache retains original and transformed strings in memory.
- Logger output can still expose data through serializers, transports, or values added after the adapter runs.

Combine value detection with allowlists, known-path redaction, access controls, retention limits, and tests built from your own data formats. Report vulnerabilities privately through [GitHub security advisories](https://github.com/ClaudiuCeia/pii-mask/security/advisories/new); see the [security policy](https://github.com/ClaudiuCeia/pii-mask/blob/main/SECURITY.md) for details.

## Development

See the [contribution guide](https://github.com/ClaudiuCeia/pii-mask/blob/main/CONTRIBUTING.md) for setup, validation, and benchmark workflows.

## License

[MIT](./LICENSE) © [Claudiu Ceia](https://github.com/ClaudiuCeia)
