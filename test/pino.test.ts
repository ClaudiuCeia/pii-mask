import { describe, expect, test } from "bun:test";
import pino from "pino";
import { pinoPiiMasking } from "../src/pino.js";

describe("pinoPiiMasking", () => {
  test("protects message arguments and structured fields", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact" }),
        base: null,
        timestamp: false,
      },
      { write: (line) => lines.push(line) },
    );

    logger.info({ email: "jane@example.com" }, "Request from 192.168.0.1");

    const entry = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(entry.email).toBe("[REDACTED]");
    expect(entry.msg).toBe("Request from [REDACTED]");
  });
});
