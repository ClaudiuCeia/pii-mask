export const BENCHMARK_REPORT_VERSION = 4;
export const BENCHMARK_RUNNER = "mitata";
type PinoHookLifecycle = "logMethod" | "streamWrite";
type DefaultCacheMode = "disabled" | "enabled";

export type BenchmarkResult = Readonly<{
  name: string;
  averageNanoseconds: number;
  medianNanoseconds: number;
  minimumNanoseconds: number;
  p99Nanoseconds: number;
  operationsPerSecond: number;
  samples: number;
  iterations: number;
}>;

export type BenchmarkReport = Readonly<{
  version: typeof BENCHMARK_REPORT_VERSION;
  runner: typeof BENCHMARK_RUNNER;
  runtime: string;
  platform: string;
  architecture: string;
  pinoHookLifecycle: PinoHookLifecycle;
  defaultCacheMode: DefaultCacheMode;
  generatedAt: string;
  results: readonly BenchmarkResult[];
}>;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null;

const isPositiveNumber = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value > 0;

const isPositiveInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0;

const isIsoTimestamp = (value: unknown): value is string => {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
};

export const parseBenchmarkReport = (value: unknown, source: string): BenchmarkReport => {
  if (
    !isRecord(value) ||
    value.version !== BENCHMARK_REPORT_VERSION ||
    value.runner !== BENCHMARK_RUNNER
  ) {
    throw new Error(`Unsupported benchmark report: ${source}`);
  }

  if (
    typeof value.runtime !== "string" ||
    value.runtime.length === 0 ||
    typeof value.platform !== "string" ||
    value.platform.length === 0 ||
    typeof value.architecture !== "string" ||
    value.architecture.length === 0 ||
    (value.pinoHookLifecycle !== "logMethod" && value.pinoHookLifecycle !== "streamWrite") ||
    (value.defaultCacheMode !== "disabled" && value.defaultCacheMode !== "enabled") ||
    !isIsoTimestamp(value.generatedAt) ||
    !Array.isArray(value.results) ||
    value.results.length === 0
  ) {
    throw new Error(`Invalid benchmark report: ${source}`);
  }

  const names = new Set<string>();
  const results = value.results.map((result, index): BenchmarkResult => {
    if (
      !isRecord(result) ||
      typeof result.name !== "string" ||
      result.name.length === 0 ||
      !isPositiveNumber(result.averageNanoseconds) ||
      !isPositiveNumber(result.medianNanoseconds) ||
      !isPositiveNumber(result.minimumNanoseconds) ||
      !isPositiveNumber(result.p99Nanoseconds) ||
      !isPositiveNumber(result.operationsPerSecond) ||
      !isPositiveInteger(result.samples) ||
      !isPositiveInteger(result.iterations) ||
      result.minimumNanoseconds > result.medianNanoseconds ||
      result.medianNanoseconds > result.p99Nanoseconds ||
      names.has(result.name)
    ) {
      throw new Error(`Invalid benchmark result at index ${index}: ${source}`);
    }

    names.add(result.name);
    return {
      name: result.name,
      averageNanoseconds: result.averageNanoseconds,
      medianNanoseconds: result.medianNanoseconds,
      minimumNanoseconds: result.minimumNanoseconds,
      p99Nanoseconds: result.p99Nanoseconds,
      operationsPerSecond: result.operationsPerSecond,
      samples: result.samples,
      iterations: result.iterations,
    };
  });

  return {
    version: BENCHMARK_REPORT_VERSION,
    runner: BENCHMARK_RUNNER,
    runtime: value.runtime,
    platform: value.platform,
    architecture: value.architecture,
    pinoHookLifecycle: value.pinoHookLifecycle,
    defaultCacheMode: value.defaultCacheMode,
    generatedAt: value.generatedAt,
    results,
  };
};
