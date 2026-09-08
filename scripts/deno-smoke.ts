import assert from "node:assert/strict";
import pino from "pino";
import winston from "winston";
import {
  createPiiMasker,
  findPii,
  maskText,
  maskValue,
  redactText,
  redactValue,
} from "../src/index.ts";
import { pinoPiiMasking } from "../src/pino.ts";
import { winstonPiiMasking } from "../src/winston.ts";

const deno = (
  globalThis as typeof globalThis & {
    Deno: {
      inspect: (value: unknown) => string;
      test: (name: string, test: () => void | Promise<void>) => void;
    };
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
  const masked = maskValue({ message: "Email jane@example.com" });
  const redacted = redactValue({ message: "Email jane@example.com" });
  if (typeof masked === "string" || masked instanceof Error) {
    throw new Error("Expected a masked object projection");
  }
  if (typeof redacted === "string" || redacted instanceof Error) {
    throw new Error("Expected a redacted object projection");
  }
  assert.equal(masked.message, "Email ****************");
  assert.equal(redacted.message, "Email [REDACTED]");
});

deno.test("does not cache repeated strings by default", () => {
  let replacements = 0;
  const protector = createPiiMasker({
    mode: "redact",
    replacement: () => {
      replacements += 1;
      return "<pii>";
    },
  });

  assert.equal(protector.text("jane@example.com"), "<pii>");
  assert.equal(protector.text("jane@example.com"), "<pii>");
  assert.equal(replacements, 2);
});

deno.test("does not inherit Deno inspection hooks", () => {
  const inspectKey = Symbol.for("Deno.customInspect");
  const arrayDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, inspectKey);
  const errorDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, inspectKey);
  let arrayInspections = 0;
  let errorInspections = 0;
  const array = new Proxy(["jane@example.com"], {
    getOwnPropertyDescriptor: (target, key) => {
      Object.defineProperty(Array.prototype, inspectKey, {
        configurable: true,
        value: () => {
          arrayInspections += 1;
          return target[0];
        },
      });
      return Object.getOwnPropertyDescriptor(target, key);
    },
  });
  const target = new Error("jane@example.com");
  const error = new Proxy(target, {
    getOwnPropertyDescriptor: (value, key) => {
      Object.defineProperty(Error.prototype, inspectKey, {
        configurable: true,
        value: () => {
          errorInspections += 1;
          return value.message;
        },
      });
      return Object.getOwnPropertyDescriptor(value, key);
    },
  });

  try {
    const protectedArray = redactValue(array);
    const protectedError = redactValue(error);
    if (!Array.isArray(protectedArray)) throw new Error("Expected a protected array");
    if (typeof protectedError === "string") throw new Error("Expected a protected Error");
    deno.inspect(protectedArray);
    deno.inspect(protectedError);
    assert.equal(arrayInspections, 0);
    assert.equal(errorInspections, 0);
    assert.equal(protectedArray[0], "[REDACTED]");
    assert.equal(protectedError.message, "[REDACTED]");
  } finally {
    if (arrayDescriptor === undefined) Reflect.deleteProperty(Array.prototype, inspectKey);
    else Object.defineProperty(Array.prototype, inspectKey, arrayDescriptor);
    if (errorDescriptor === undefined) Reflect.deleteProperty(Error.prototype, inspectKey);
    else Object.defineProperty(Error.prototype, inspectKey, errorDescriptor);
  }
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
