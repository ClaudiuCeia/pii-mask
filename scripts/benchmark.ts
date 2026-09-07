import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { bench, do_not_optimize, run } from "mitata";
import {
  BENCHMARK_REPORT_VERSION,
  BENCHMARK_RUNNER,
  type BenchmarkReport,
  type BenchmarkResult,
} from "./benchmark-report.js";

type BenchmarkApi = Readonly<{
  findPii(input: string): readonly unknown[];
  maskText(input: string, options?: Record<string, unknown>): string;
  maskValue<T>(input: T, options?: Record<string, unknown>): T;
  redactValue<T>(input: T, options?: Record<string, unknown>): T;
}>;

type CliOptions = Readonly<{
  modulePath: string;
  jsonPath?: string;
}>;

const parseCli = (args: readonly string[]): CliOptions => {
  let modulePath = "dist/index.js";
  let jsonPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument !== "--module" && argument !== "--json") {
      throw new Error(`Unknown argument: ${argument}`);
    }

    const value = args[index + 1];
    if (value === undefined) throw new Error(`${argument} requires a path`);
    if (argument === "--module") modulePath = value;
    else jsonPath = value;
    index += 1;
  }

  return jsonPath === undefined ? { modulePath } : { modulePath, jsonPath };
};

type PinoHookModule = Readonly<{
  pinoPiiMasking(options?: Record<string, unknown>): {
    hooks: { streamWrite(line: string): string };
  };
}>;

type PinoLike = Readonly<{
  info(payload: object, message?: string): void;
}>;

const cli = parseCli(Bun.argv.slice(2));
const modulePath = resolve(cli.modulePath);
const moduleUrl = pathToFileURL(modulePath).href;
const api = (await import(moduleUrl)) as BenchmarkApi;
const pinoModuleUrl = pathToFileURL(resolve(dirname(modulePath), "pino.js")).href;
const { pinoPiiMasking } = (await import(pinoModuleUrl)) as PinoHookModule;
const pino = (await import("pino")).default as (
  options: Record<string, unknown>,
  destination: { write(chunk: string): void },
) => PinoLike;

const cleanText =
  "The quick brown fox jumps over the lazy dog while a quiet service handles the request.";
const denseText =
  "User jane@example.com called +14155552671 from 192.168.0.1 with card 4242 4242 4242 4242 and SSN 123-45-6789.";
const logPayload = {
  message: "Login for jane@example.com from 192.168.0.1",
  request: {
    headers: {
      authorization: "Bearer safe-placeholder",
      forwardedFor: "192.168.0.1",
    },
    users: [
      { email: "jane@example.com", phone: "+14155552671" },
      { email: "john@example.net", phone: "+442071838750" },
    ],
  },
  status: 200,
};
const requestError = new Error("Request for jane@example.com failed from 192.168.0.1", {
  cause: new Error("Card 4242 4242 4242 4242 was rejected"),
});

const sinkWriter = { write: (_chunk: string) => {} };
const loggerOptions = { base: null, timestamp: false, level: "info" };
const plainLogger = pino(loggerOptions, sinkWriter);
const protectedLogger = pino({ ...loggerOptions, ...pinoPiiMasking() }, sinkWriter);

const smallPayload = { reqId: "req_9f2c7a", durationMs: 13, status: 200 };
const mediumPayload = {
  method: "POST",
  url: "/api/users/verify",
  statusCode: 200,
  responseTimeMs: 42.7,
  remoteAddress: "192.168.0.1",
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
  user: { email: "jane@example.com", phone: "+14155552671" },
  requestId: "req_9f2c7a",
  region: "us-east-1",
};
// This batch fixture serializes to roughly 270 KB.
const largePayload = {
  batchId: "batch_2026_07_25_001",
  imported: 2000,
  users: Array.from({ length: 2000 }, (_, index) => ({
    id: `usr_${index.toString().padStart(6, "0")}`,
    email: `user${index}@example.com`,
    phone: `+1415555${(index % 10000).toString().padStart(4, "0")}`,
    ip: `192.168.${Math.floor(index / 256) % 256}.${index % 256}`,
    name: `User Number ${index}`,
    active: index % 2 === 0,
  })),
};

// Unique: same shape as medium, but fresh PII per operation. The cache
// cannot help, so this isolates worst-case detection overhead.
let uniqueCounter = 0;
const uniquePayload = () => {
  uniqueCounter += 1;
  return {
    ...mediumPayload,
    remoteAddress: `192.168.0.${uniqueCounter % 256}`,
    user: { email: `user${uniqueCounter}@example.com`, phone: "+14155552671" },
  };
};

const register = (name: string, operation: () => unknown): void => {
  bench(name, () => {
    do_not_optimize(operation());
  });
};

register("findPii/dense-text", () => api.findPii(denseText));
register("maskText/clean-text", () => api.maskText(cleanText));
register("maskText/dense-text", () => api.maskText(denseText, { keepStart: 1, keepEnd: 2 }));
register("maskValue/log-payload", () => api.maskValue(logPayload));
register("redactValue/error", () => api.redactValue(requestError, { replacement: "[PII]" }));
register("log/small/plain", () => plainLogger.info(smallPayload, "request completed"));
register("log/small/protected", () => protectedLogger.info(smallPayload, "request completed"));
register("log/medium/plain", () => plainLogger.info(mediumPayload, "POST /api/users/verify"));
register("log/medium/protected", () =>
  protectedLogger.info(mediumPayload, "POST /api/users/verify"),
);
register("log/medium-unique/plain", () =>
  plainLogger.info(uniquePayload(), "POST /api/users/verify"),
);
register("log/medium-unique/protected", () =>
  protectedLogger.info(uniquePayload(), "POST /api/users/verify"),
);
register("log/large/plain", () => plainLogger.info(largePayload, "batch import finished"));
register("log/large/protected", () => protectedLogger.info(largePayload, "batch import finished"));

const benchmarkRun = await run({
  colors: cli.jsonPath === undefined,
  format: cli.jsonPath === undefined ? "mitata" : "quiet",
  throw: true,
});

const results: readonly BenchmarkResult[] = benchmarkRun.benchmarks.flatMap((trial) =>
  trial.runs.map((result) => {
    if (result.stats === undefined) {
      throw new Error(`Benchmark did not produce statistics: ${result.name}`);
    }

    const stats = result.stats;
    return {
      name: result.name,
      averageNanoseconds: stats.avg,
      medianNanoseconds: stats.p50,
      minimumNanoseconds: stats.min,
      p99Nanoseconds: stats.p99,
      operationsPerSecond: 1_000_000_000 / stats.p50,
      samples: stats.samples.length,
      iterations: stats.ticks,
    };
  }),
);

const report: BenchmarkReport = {
  version: BENCHMARK_REPORT_VERSION,
  runner: BENCHMARK_RUNNER,
  runtime: `Bun ${Bun.version}`,
  platform: process.platform,
  architecture: process.arch,
  generatedAt: new Date().toISOString(),
  results,
};

if (cli.jsonPath !== undefined) {
  const outputPath = resolve(cli.jsonPath);
  await mkdir(dirname(outputPath), { recursive: true });
  await Bun.write(outputPath, `${JSON.stringify(report, null, 2)}\n`);

  const formatter = new Intl.NumberFormat("en", { maximumFractionDigits: 2 });
  console.log(`\nPII mask benchmarks (${report.runtime})`);
  console.log("-");
  for (const result of results) {
    const microseconds = result.medianNanoseconds / 1_000;
    console.log(
      `${result.name.padEnd(28)} ${formatter.format(microseconds).padStart(10)} us/op  ${formatter.format(result.operationsPerSecond).padStart(12)} ops/s`,
    );
  }
}

const formatter = new Intl.NumberFormat("en", { maximumFractionDigits: 2 });
console.log("\nPino hook overhead");
console.log("-");
const byName = new Map(results.map((result) => [result.name, result]));
for (const result of results) {
  if (!result.name.endsWith("/protected")) continue;
  const plain = byName.get(result.name.replace("/protected", "/plain"));
  if (plain === undefined) continue;
  const overhead =
    ((result.medianNanoseconds - plain.medianNanoseconds) / plain.medianNanoseconds) * 100;
  const scenario = result.name.replace("/protected", "");
  console.log(
    `${scenario.padEnd(28)} ${formatter.format(overhead).padStart(10)}%  (${formatter.format(plain.medianNanoseconds / 1_000)} us -> ${formatter.format(result.medianNanoseconds / 1_000)} us)`,
  );
}
