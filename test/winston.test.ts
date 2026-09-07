import { describe, expect, test } from "bun:test";
import winston from "winston";
import { winstonPiiMasking } from "../src/winston.js";

describe("winstonPiiMasking", () => {
  test("protects message and metadata through Winston's format pipeline", () => {
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

    expect(entries[0]?.message).toBe("Email [REDACTED]");
    expect(entries[0]?.ip).toBe("[REDACTED]");
  });

  test("does not cache repeated entry strings by default", () => {
    let replacements = 0;
    const logger = winston.createLogger({
      format: winstonPiiMasking({
        mode: "redact",
        replacement: () => {
          replacements += 1;
          return "<pii>";
        },
      }),
      transports: [new winston.transports.Console({ silent: true })],
    });

    logger.info("Email jane@example.com");
    logger.info("Email jane@example.com");

    expect(replacements).toBe(2);
  });

  test("protects metadata stored in class instances", () => {
    class Account {
      email = "jane@example.com";

      toJSON = (): Readonly<{ email: string }> => ({ email: "serializer@example.com" });
    }

    const entries: string[] = [];
    const capture = winston.format((info) => {
      const message: unknown = info[Symbol.for("message")];
      if (typeof message === "string") entries.push(message);
      return info;
    });
    const logger = winston.createLogger({
      format: winston.format.combine(
        winstonPiiMasking({ mode: "redact" }),
        winston.format.json(),
        capture(),
      ),
      transports: [new winston.transports.Console({ silent: true })],
    });

    logger.info("Account", { account: new Account() });

    expect(JSON.parse(entries[0] ?? "{}")).toEqual({
      level: "info",
      message: "Account",
      account: { email: "[REDACTED]" },
    });
  });

  test("preserves entries with accessor-backed required fields", () => {
    const entries: Record<PropertyKey, unknown>[] = [];
    const accessors = winston.format((info) => {
      const { level, message } = info;
      Object.defineProperties(info, {
        level: { configurable: true, get: () => level },
        message: { configurable: true, get: () => message },
      });
      return info;
    });
    const capture = winston.format((info) => {
      entries.push(info);
      return info;
    });
    const logger = winston.createLogger({
      format: winston.format.combine(accessors(), winstonPiiMasking({ mode: "redact" }), capture()),
      transports: [new winston.transports.Console({ silent: true })],
    });

    logger.info("Email jane@example.com", { ip: "192.168.0.1" });

    expect(entries).toHaveLength(1);
    expect(entries[0]?.message).toBe("Email [REDACTED]");
    expect(entries[0]?.level).toBe("info");
    expect(entries[0]?.ip).toBe("[REDACTED]");
  });

  test("restores non-enumerable required fields before JSON formatting", () => {
    const entries: string[] = [];
    const hideMessage = winston.format((info) => {
      Object.defineProperty(info, "message", {
        configurable: true,
        value: info.message,
        writable: true,
      });
      return info;
    });
    const capture = winston.format((info) => {
      const message: unknown = info[Symbol.for("message")];
      if (typeof message === "string") entries.push(message);
      return info;
    });
    const logger = winston.createLogger({
      format: winston.format.combine(
        hideMessage(),
        winstonPiiMasking({ mode: "redact" }),
        winston.format.json(),
        capture(),
      ),
      transports: [new winston.transports.Console({ silent: true })],
    });

    logger.info("Email jane@example.com", { ip: "192.168.0.1" });

    expect(JSON.parse(entries[0] ?? "{}")).toEqual({
      ip: "[REDACTED]",
      level: "info",
      message: "Email [REDACTED]",
    });
  });
});
