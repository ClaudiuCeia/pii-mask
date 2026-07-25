import { describe, expect, test } from "bun:test";
import {
  createPiiMasker,
  findPii,
  maskText,
  maskValue,
  redactText,
  redactValue,
} from "../src/index.js";

describe("findPii", () => {
  test("uses ts-duckling's PII parser set", () => {
    const entities = findPii("Contact jane@example.com from 192.168.0.1");

    expect(entities.map(({ kind }) => kind)).toEqual(["email", "ip"]);
  });
});

describe("maskText", () => {
  test("masks all detected PII by default", () => {
    expect(maskText("Email jane@example.com or call +14155552671")).toBe(
      "Email **************** or call ************",
    );
  });

  test("can keep leading and trailing characters", () => {
    expect(
      maskText("Card 4242 4242 4242 4242", {
        keepStart: 4,
        keepEnd: 4,
      }),
    ).toBe("Card 4242***********4242");
  });

  test("can select entity kinds", () => {
    expect(
      maskText("Email jane@example.com from 192.168.0.1", {
        kinds: ["email"],
      }),
    ).toBe("Email **************** from 192.168.0.1");
  });

  test("supports custom mask tokens", () => {
    expect(maskText("SSN 123-45-6789", { mask: "#" })).toBe("SSN ###########");
  });

  test("rejects invalid masking options", () => {
    expect(() => maskText("jane@example.com", { mask: "" })).toThrow("mask must not be empty");
    expect(() => maskText("jane@example.com", { keepStart: -1 })).toThrow(
      "keepStart must be a non-negative safe integer",
    );
  });
});

describe("redactText", () => {
  test("replaces PII with one marker per entity", () => {
    expect(redactText("Email jane@example.com from 192.168.0.1")).toBe(
      "Email [REDACTED] from [REDACTED]",
    );
  });

  test("supports entity-aware replacements", () => {
    expect(
      redactText("Email jane@example.com from 192.168.0.1", {
        replacement: ({ kind }) => `[REDACTED:${kind}]`,
      }),
    ).toBe("Email [REDACTED:email] from [REDACTED:ip]");
  });
});

describe("structured values", () => {
  test("deeply masks arrays and plain objects without mutation", () => {
    const input = {
      message: "Email jane@example.com",
      nested: ["IP 192.168.0.1", 42, { safe: true }],
    };

    const result = maskValue(input);

    expect(result).toEqual({
      message: "Email ****************",
      nested: ["IP ***********", 42, { safe: true }],
    });
    expect(result).not.toBe(input);
    expect(result.nested).not.toBe(input.nested);
    expect(input.message).toBe("Email jane@example.com");
  });

  test("preserves cycles", () => {
    const input: { message: string; self?: unknown } = {
      message: "Email jane@example.com",
    };
    input.self = input;

    const result = redactValue(input);

    expect(result.message).toBe("Email [REDACTED]");
    expect(result.self).toBe(result);
  });

  test("protects Error messages, stacks, causes, and metadata", () => {
    const cause = new Error("User jane@example.com");
    const input = new Error("Request from 192.168.0.1", { cause });
    Object.assign(input, { account: "jane@example.com" });

    const result = redactValue(input);

    expect(result).toBeInstanceOf(Error);
    expect(result).not.toBe(input);
    expect(result.message).toBe("Request from [REDACTED]");
    expect(result.stack).not.toContain("192.168.0.1");
    expect((result.cause as Error).message).toBe("User [REDACTED]");
    expect((result as Error & { account: string }).account).toBe("[REDACTED]");
  });

  test("leaves non-plain values intact", () => {
    const date = new Date();
    expect(maskValue({ date }).date).toBe(date);
  });
});

describe("createPiiMasker", () => {
  test("creates reusable maskers", () => {
    const masker = createPiiMasker({ keepStart: 1, keepEnd: 4 });
    expect(masker.text("jane@example.com")).toBe("j***********.com");
  });

  test("creates reusable redactors", () => {
    const masker = createPiiMasker({ mode: "redact", replacement: "<pii>" });
    expect(masker.value(["jane@example.com"])).toEqual(["<pii>"]);
  });

  test("caches repeated strings with identical results", () => {
    const masker = createPiiMasker();
    const first = masker.text("Email jane@example.com");
    const second = masker.text("Email jane@example.com");
    expect(first).toBe("Email ****************");
    expect(second).toBe(first);
  });

  test("cache can be disabled", () => {
    const masker = createPiiMasker({ cacheSize: 0 });
    expect(masker.text("Email jane@example.com")).toBe("Email ****************");
  });

  test("rejects invalid cache sizes", () => {
    expect(() => createPiiMasker({ cacheSize: -1 })).toThrow(
      "cacheSize must be a non-negative safe integer",
    );
  });
});
