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
});
