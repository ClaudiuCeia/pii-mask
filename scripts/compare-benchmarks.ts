import type { BenchmarkReport, BenchmarkResult } from "./benchmark.js";

interface Comparison {
  name: string;
  baseline: number;
  candidate: number;
  changePercent: number;
  regressed: boolean;
}

const [baselinePath, candidatePath, thresholdArgument] = Bun.argv.slice(2);
if (baselinePath === undefined || candidatePath === undefined) {
  throw new Error(
    "Usage: compare-benchmarks.ts <baseline.json> <candidate.json> [threshold-percent]",
  );
}

const thresholdPercent = Number(
  thresholdArgument ?? process.env.BENCHMARK_THRESHOLD_PERCENT ?? "15",
);
if (!Number.isFinite(thresholdPercent) || thresholdPercent < 0) {
  throw new RangeError("Benchmark threshold must be a non-negative number");
}

const readReport = async (path: string): Promise<BenchmarkReport> => {
  const report = (await Bun.file(path).json()) as BenchmarkReport;
  if (report.version !== 1 || !Array.isArray(report.results)) {
    throw new Error(`Unsupported benchmark report: ${path}`);
  }
  return report;
};

const baseline = await readReport(baselinePath);
const candidate = await readReport(candidatePath);
const baselineByName = new Map<string, BenchmarkResult>(
  baseline.results.map((result) => [result.name, result]),
);

// Reference scenarios (plain Pino, no hook) only feed overhead ratios — they
// measure third-party code and are skipped by the regression gate.
const isReference = (name: string): boolean => name.endsWith("/plain");

// Sub-microsecond medians are dominated by noise; require a minimum absolute
// slowdown before a relative regression counts.
const ABSOLUTE_FLOOR_NANOSECONDS = 1_000;

const comparisons: Comparison[] = candidate.results
  .filter((result) => !isReference(result.name))
  .map((result) => {
    const previous = baselineByName.get(result.name);
    if (previous === undefined) {
      throw new Error(`Benchmark is missing from baseline: ${result.name}`);
    }

    // Gate on minimum time: for CPU-bound work, noise only adds time, so the
    // minimum is the most repeatable signal. Medians remain in the report.
    const baselineBest = previous.minimumNanoseconds;
    const candidateBest = result.minimumNanoseconds;
    const changePercent = ((candidateBest - baselineBest) / baselineBest) * 100;
    return {
      name: result.name,
      baseline: baselineBest,
      candidate: candidateBest,
      changePercent,
      regressed:
        changePercent > thresholdPercent &&
        candidateBest - baselineBest > ABSOLUTE_FLOOR_NANOSECONDS,
    };
  });

const gatedBaseline = baseline.results.filter((result) => !isReference(result.name));
if (comparisons.length !== gatedBaseline.length) {
  const candidateNames = new Set(candidate.results.map((result) => result.name));
  const missing = gatedBaseline
    .filter((result) => !candidateNames.has(result.name))
    .map((result) => result.name);
  throw new Error(`Benchmarks are missing from candidate: ${missing.join(", ")}`);
}

const formatTime = (nanoseconds: number): string => `${(nanoseconds / 1_000).toFixed(2)} us`;
const formatChange = (percent: number): string =>
  `${percent >= 0 ? "+" : ""}${percent.toFixed(2)}%`;

const rows = comparisons.map((comparison) =>
  [
    comparison.name,
    formatTime(comparison.baseline),
    formatTime(comparison.candidate),
    formatChange(comparison.changePercent),
    comparison.regressed ? "FAIL" : "PASS",
  ].join(" | "),
);

const summary = [
  `Performance regression threshold: ${thresholdPercent}% on minimum time/op (1 us absolute floor; */plain reference scenarios excluded)`,
  "",
  "Benchmark | Baseline (min) | Candidate (min) | Change | Status",
  "--- | ---: | ---: | ---: | :---:",
  ...rows,
].join("\n");

console.log(`\n${summary}\n`);

const stepSummary = process.env.GITHUB_STEP_SUMMARY;
if (stepSummary !== undefined) {
  await Bun.write(stepSummary, `## Benchmark results\n\n${summary}\n`);
}

const regressions = comparisons.filter((comparison) => comparison.regressed);
if (regressions.length > 0) {
  console.error(
    `Performance budget exceeded by: ${regressions.map(({ name }) => name).join(", ")}`,
  );
  process.exit(1);
}
