import { describe, expect, test } from "bun:test";
import pino from "pino";
import { PinoOutputError, pinoPiiMasking } from "../src/pino.js";

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

  test("protects base and child bindings including bindings added later", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact" }),
        base: { owner: "base@example.com" },
        timestamp: false,
      },
      { write: (line) => lines.push(line) },
    ).child({ client: "child@example.com" });

    logger.setBindings({ actor: "actor@example.com" });
    logger.info("Contact message@example.com");

    const entry = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(entry).toEqual({
      level: 30,
      owner: "[REDACTED]",
      client: "[REDACTED]",
      actor: "[REDACTED]",
      msg: "Contact [REDACTED]",
    });
  });

  test("protects values introduced by mixins and serializers", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact" }),
        base: null,
        timestamp: false,
        mixin: () => ({ requester: "mixin@example.com" }),
        msgPrefix: "prefix@example.com ",
        serializers: {
          account: () => ({ email: "serializer@example.com" }),
        },
      },
      { write: (line) => lines.push(line) },
    );

    logger.info({ account: "safe" }, "Processed");

    const entry = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(entry).toEqual({
      level: 30,
      requester: "[REDACTED]",
      account: { email: "[REDACTED]" },
      msg: "[REDACTED] Processed",
    });
  });

  test("keeps output valid JSON when a replacement needs escaping", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact", replacement: 'hidden "value"\nnext' }),
        base: null,
        timestamp: false,
      },
      { write: (line) => lines.push(line) },
    );

    logger.info("Contact user@example.com");

    expect(lines[0]).toBe('{"level":30,"msg":"Contact hidden \\"value\\"\\nnext"}\n');
    expect(JSON.parse(lines[0] ?? "{}")).toEqual({
      level: 30,
      msg: 'Contact hidden "value"\nnext',
    });
  });

  test("preserves CRLF output while masking the complete entry", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact" }),
        base: null,
        crlf: true,
        timestamp: false,
      },
      { write: (line) => lines.push(line) },
    );

    logger.info("Contact user@example.com");

    expect(lines[0]).toBe('{"level":30,"msg":"Contact [REDACTED]"}\r\n');
  });

  test("preserves integer tokens outside the safe number range", () => {
    const lines: string[] = [];
    const logger = pino(
      {
        ...pinoPiiMasking({ mode: "redact" }),
        base: null,
        timestamp: false,
      },
      { write: (line) => lines.push(line) },
    );

    logger.info({ id: 9_007_199_254_740_993n }, "Contact user@example.com");

    expect(lines[0]).toBe('{"level":30,"id":9007199254740993,"msg":"Contact [REDACTED]"}\n');
  });

  test("preserves keys, duplicate fields, and escaped string content", () => {
    const streamWrite = pinoPiiMasking({ mode: "redact" }).hooks?.streamWrite;
    if (streamWrite === undefined) throw new Error("Pino masking stream hook is missing");

    expect(
      streamWrite(
        '{"user@example.com":"safe","path":"C:\\\\user@example.com","message":"user\\u0040example.com said \\"hello\\"","duplicate":"first","duplicate":"second@example.com"}\n',
      ),
    ).toBe(
      '{"user@example.com":"safe","path":"C:\\\\[REDACTED]","message":"[REDACTED] said \\"hello\\"","duplicate":"first","duplicate":"[REDACTED]"}\n',
    );
  });

  test("preserves valid JSON grammar while protecting nested strings", () => {
    const streamWrite = pinoPiiMasking({ mode: "redact" }).hooks?.streamWrite;
    if (streamWrite === undefined) throw new Error("Pino masking stream hook is missing");

    expect(
      streamWrite(
        '{"empty":{},"values":[true,false,null,-0,1.25e+2,"user@example.com"],"escaped":"line\\nvalue"}\n',
      ),
    ).toBe(
      '{"empty":{},"values":[true,false,null,-0,1.25e+2,"[REDACTED]"],"escaped":"line\\nvalue"}\n',
    );
  });

  test("fails closed when the stream hook receives invalid JSON", () => {
    const streamWrite = pinoPiiMasking().hooks?.streamWrite;
    if (streamWrite === undefined) throw new Error("Pino masking stream hook is missing");

    const invalidEntries = [
      '{"message":"user@example.com}',
      '{"message":user@example.com}',
      '{"message":"user@example.com",}',
      '{"message":"user@example.com" "status":200}',
      '{"values":["user@example.com",]}',
      '{"value":01}',
      '{"value":1.}',
      '{"user\\x@example.com":"safe"}',
      '"user@example.com"',
    ];
    for (const entry of invalidEntries) {
      try {
        streamWrite(entry);
        throw new Error("Expected invalid Pino output to be rejected");
      } catch (error) {
        expect(error).toBeInstanceOf(PinoOutputError);
        expect(error).toEqual(
          expect.objectContaining({
            name: "PinoOutputError",
            message: "Pino produced invalid JSON output",
            code: "PII_MASK_INVALID_PINO_OUTPUT",
            retryable: false,
          }),
        );
      }
    }
  });
});
