import assert from "node:assert/strict";
import pino from "pino";
import winston from "winston";
import { findPii, maskText, maskValue, redactText, redactValue } from "../src/index.ts";
import { pinoPiiMasking } from "../src/pino.ts";
import { winstonPiiMasking } from "../src/winston.ts";

const deno = (
  globalThis as typeof globalThis & {
    Deno: { test: (name: string, test: () => void | Promise<void>) => void };
  }
).Deno;

deno.test("masks and redacts text", () => {
  assert.equal(maskText("Email jane@example.com"), "Email ****************");
  assert.equal(redactText("IP 192.168.0.1"), "IP [REDACTED]");
});

deno.test("detects PII entities", () => {
  const kinds = findPii("Contact jane@example.com from 192.168.0.1").map(({ kind }) => kind);
  assert.ok(kinds.includes("email"));
  assert.ok(kinds.includes("ip"));
});

deno.test("protects structured data", () => {
  assert.equal(maskValue({ message: "Email jane@example.com" }).message, "Email ****************");
  assert.equal(redactValue({ message: "Email jane@example.com" }).message, "Email [REDACTED]");
});

deno.test("integrates with Pino", () => {
  const lines: string[] = [];
  const logger = pino(
    { ...pinoPiiMasking({ mode: "redact" }), base: null, timestamp: false },
    { write: (line) => lines.push(line) },
  );
  logger.info({ email: "jane@example.com" }, "Request from 192.168.0.1");
  assert.deepEqual(JSON.parse(lines[0] ?? "{}"), {
    level: 30,
    email: "[REDACTED]",
    msg: "Request from [REDACTED]",
  });
});

deno.test("integrates with Winston", () => {
  const entries: Record<PropertyKey, unknown>[] = [];
  const capture = winston.format((info) => {
    entries.push(info);
    return info;
  });
  const logger = winston.createLogger({
    format: winston.format.combine(winstonPiiMasking({ mode: "redact" }), capture()),
    transports: [new winston.transports.Console({ silent: true })],
  });
  logger.info("Email jane@example.com", { ip: "192.168.0.1" });
  assert.equal(entries[0]?.message, "Email [REDACTED]");
  assert.equal(entries[0]?.ip, "[REDACTED]");
});
