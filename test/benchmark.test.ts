import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BENCHMARK_REPORT_VERSION,
  BENCHMARK_RUNNER,
  type BenchmarkReport,
  type BenchmarkResult,
} from "../scripts/benchmark-report.js";

const resultFixture = (name: string, medianNanoseconds: number): BenchmarkResult => ({
  name,
  averageNanoseconds: medianNanoseconds,
  medianNanoseconds,
  minimumNanoseconds: medianNanoseconds * 0.9,
  p99Nanoseconds: medianNanoseconds * 1.1,
  operationsPerSecond: 1_000_000_000 / medianNanoseconds,
  samples: 20,
  iterations: 20,
});

const report = (results: readonly BenchmarkResult[]): BenchmarkReport => ({
  version: BENCHMARK_REPORT_VERSION,
  runner: BENCHMARK_RUNNER,
  runtime: "Bun 1.4.2",
  platform: "darwin",
  architecture: "arm64",
  generatedAt: "2026-09-06T00:00:00.000Z",
  results,
});

type ComparatorResult = Readonly<{
  exitCode: number;
  stdout: readonly string[];
  error: string | undefined;
}>;

const runComparator = async (baseline: unknown, candidate: unknown): Promise<ComparatorResult> => {
  const directory = await mkdtemp(join(tmpdir(), "pii-mask-benchmark-test-"));
  const baselinePath = join(directory, "baseline.json");
  const candidatePath = join(directory, "candidate.json");

  try {
    await Promise.all([
      writeFile(baselinePath, JSON.stringify(baseline)),
      writeFile(candidatePath, JSON.stringify(candidate)),
    ]);
    const child = Bun.spawn(
      [process.execPath, "run", "scripts/compare-benchmarks.ts", baselinePath, candidatePath],
      { stdout: "pipe", stderr: "pipe" },
    );
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    const normalizedError = stderr
      .replaceAll(baselinePath, "<baseline>")
      .replaceAll(candidatePath, "<candidate>")
      .split("\n")
      .find(
        (line) => line.startsWith("error: ") || line.startsWith("Performance budget exceeded by: "),
      );
    return { exitCode, stdout: stdout.trim().split("\n"), error: normalizedError };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
};

const summary = (...rows: readonly string[]): readonly string[] => [
  "Performance regression threshold: 15% on median time/op (1 us absolute floor; */plain reference scenarios excluded)",
  "",
  "Benchmark | Baseline (median) | Candidate (median) | Change | Status",
  "--- | ---: | ---: | ---: | :---:",
  ...rows,
];

test("the benchmark comparator accepts a valid version 2 Mitata report", async () => {
  const result = await runComparator(
    report([resultFixture("maskText/protected", 10_000)]),
    report([resultFixture("maskText/protected", 10_500)]),
  );

  expect(result).toEqual({
    exitCode: 0,
    stdout: summary("maskText/protected | 10.00 us | 10.50 us | +5.00% | PASS"),
    error: undefined,
  });
});

test("the benchmark comparator rejects reports from another runner", async () => {
  const valid = report([resultFixture("maskText/protected", 10_000)]);
  const result = await runComparator({ ...valid, runner: "custom" }, valid);

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Unsupported benchmark report: <baseline>");
});

test("the benchmark comparator rejects reports from another schema version", async () => {
  const valid = report([resultFixture("maskText/protected", 10_000)]);
  const result = await runComparator({ ...valid, version: 1 }, valid);

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Unsupported benchmark report: <baseline>");
});

test("the benchmark comparator rejects incomplete report metadata", async () => {
  const valid = report([resultFixture("maskText/protected", 10_000)]);
  const { runtime: _runtime, ...incomplete } = valid;
  const result = await runComparator(incomplete, valid);

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Invalid benchmark report: <baseline>");
});

test("the benchmark comparator rejects an empty report", async () => {
  const result = await runComparator(
    report([]),
    report([resultFixture("maskText/protected", 10_000)]),
  );

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Invalid benchmark report: <baseline>");
});

test("the benchmark comparator rejects non-positive median values", async () => {
  const invalid = { ...resultFixture("maskText/protected", 10_000), medianNanoseconds: 0 };
  const result = await runComparator(
    report([invalid]),
    report([resultFixture("maskText/protected", 10_000)]),
  );

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Invalid benchmark result at index 0: <baseline>");
});

test("the benchmark comparator fails a regression above both limits", async () => {
  const result = await runComparator(
    report([resultFixture("maskText/protected", 10_000)]),
    report([resultFixture("maskText/protected", 12_000)]),
  );

  expect(result).toEqual({
    exitCode: 1,
    stdout: summary("maskText/protected | 10.00 us | 12.00 us | +20.00% | FAIL"),
    error: "Performance budget exceeded by: maskText/protected",
  });
});

test("the benchmark comparator ignores a regression below the absolute floor", async () => {
  const result = await runComparator(
    report([resultFixture("maskText/protected", 1_000)]),
    report([resultFixture("maskText/protected", 1_900)]),
  );

  expect(result).toEqual({
    exitCode: 0,
    stdout: summary("maskText/protected | 1.00 us | 1.90 us | +90.00% | PASS"),
    error: undefined,
  });
});

test("the benchmark comparator treats both limits as strict boundaries", async () => {
  const result = await runComparator(
    report([resultFixture("threshold/protected", 10_000), resultFixture("floor/protected", 4_000)]),
    report([resultFixture("threshold/protected", 11_500), resultFixture("floor/protected", 5_000)]),
  );

  expect(result).toEqual({
    exitCode: 0,
    stdout: summary(
      "threshold/protected | 10.00 us | 11.50 us | +15.00% | PASS",
      "floor/protected | 4.00 us | 5.00 us | +25.00% | PASS",
    ),
    error: undefined,
  });
});

test("the benchmark comparator rejects different benchmark environments", async () => {
  const baseline = report([resultFixture("maskText/protected", 10_000)]);
  const candidate = { ...baseline, runtime: "Bun 1.5.0" };
  const result = await runComparator(baseline, candidate);

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe(
    "error: Benchmark environments do not match: Bun 1.4.2 darwin/arm64 != Bun 1.5.0 darwin/arm64",
  );
});

test("the benchmark comparator rejects a candidate with a missing benchmark", async () => {
  const result = await runComparator(
    report([
      resultFixture("maskText/protected", 10_000),
      resultFixture("redactText/protected", 10_000),
    ]),
    report([resultFixture("maskText/protected", 10_000)]),
  );

  expect(result.exitCode).toBe(1);
  expect(result.stdout).toEqual([""]);
  expect(result.error).toBe("error: Benchmarks are missing from candidate: redactText/protected");
});
