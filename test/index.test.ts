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

  test("normalizes unsupported built-ins without retaining serialization hooks", () => {
    const date = Object.assign(new Date("2026-09-07T00:00:00.000Z"), {
      email: "jane@example.com",
    });
    Object.defineProperty(date, "toJSON", {
      enumerable: true,
      value: () => "serializer@example.com",
    });

    const result = redactValue(date);

    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(result.email).toBe("[REDACTED]");
    expect(Reflect.ownKeys(result)).toEqual(["email"]);
    expect(JSON.stringify(result)).toBe('{"email":"[REDACTED]"}');
  });

  test("protects boxed strings as one value", () => {
    const result = redactValue(new String("jane@example.com"));
    const typedResult: string = result;

    expect(typedResult).toBe("[REDACTED]");
    expect(result).toBe("[REDACTED]");
  });

  test("normalizes callable serializers", () => {
    const serializer = (): string => "ignored";
    serializer.toJSON = (): string => "serializer@example.com";

    const result = redactValue({ serializer });
    const protectedSerializer: unknown = Reflect.get(result, "serializer");
    if (typeof protectedSerializer !== "object" || protectedSerializer === null) {
      throw new Error("Expected the callable to become an object");
    }

    expect(Object.getPrototypeOf(protectedSerializer)).toBeNull();
    expect(Reflect.has(protectedSerializer, "toJSON")).toBe(false);
    expect(JSON.stringify(result)).toBe('{"serializer":{}}');
  });

  test("protects enumerable data properties on class instances", () => {
    class Account {
      email = "jane@example.com";
      self: Account | undefined;

      toJSON = (): Readonly<{ leaked: string }> => ({ leaked: "serializer@example.com" });
    }

    const input = new Account();
    input.self = input;
    const result = redactValue(input);

    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(result.email).toBe("[REDACTED]");
    expect(result.self).toBe(result);
    expect(Reflect.has(result, "toJSON")).toBe(false);
    expect(Reflect.ownKeys(result)).toEqual(["email", "self"]);
  });

  test("protects non-callable toJSON data properties", () => {
    const result = redactValue({ toJSON: "jane@example.com" });

    expect(result.toJSON).toBe("[REDACTED]");
    expect(JSON.stringify(result)).toBe('{"toJSON":"[REDACTED]"}');
  });

  test("reuses the prototype selected for plain-object output", () => {
    const serializer = { toJSON: (): string => "serializer@example.com" };
    let prototypeReads = 0;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        getPrototypeOf: () => {
          prototypeReads += 1;
          return prototypeReads <= 2 ? Object.prototype : serializer;
        },
      },
    );

    const result = redactValue(input);

    expect(prototypeReads).toBe(2);
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(JSON.stringify(result)).toBe('{"email":"[REDACTED]"}');
  });

  test("does not invoke or retain accessors from class instances", () => {
    let reads = 0;
    class Account {
      get email(): string {
        reads += 1;
        throw new Error("Accessor must not run");
      }
    }

    const result = redactValue(new Account());

    expect(reads).toBe(0);
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(Reflect.has(result, "email")).toBe(false);
  });

  test("does not preserve custom subclasses of retained built-ins", () => {
    class AccountDate extends Date {
      email = "jane@example.com";

      override toJSON(): string {
        return "serializer@example.com";
      }
    }

    const result = redactValue(new AccountDate("2026-09-07T00:00:00.000Z"));

    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(result.email).toBe("[REDACTED]");
    expect(Reflect.has(result, "toJSON")).toBe(false);
  });

  test("normalizes custom errors and protects their names", () => {
    class AccountError extends Error {
      toJSON(): Readonly<{ email: string }> {
        return { email: "serializer@example.com" };
      }
    }

    const input = new AccountError("Request for jane@example.com failed");
    input.name = "jane@example.com";
    const result = redactValue(input);

    expect(Object.getPrototypeOf(result)).toBe(Error.prototype);
    expect(result.name).toBe("[REDACTED]");
    expect(result.message).toBe("Request for [REDACTED] failed");
    expect(Reflect.has(result, "toJSON")).toBe(false);
  });

  test("does not invoke inherited error accessors", () => {
    let reads = 0;
    class AccountError extends Error {
      override get name(): string {
        reads += 1;
        throw new Error("Accessor must not run");
      }

      override get message(): string {
        reads += 1;
        throw new Error("Accessor must not run");
      }
    }

    const input = new AccountError();
    const result = redactValue(input);

    expect(reads).toBe(0);
    expect(result.name).toBe("Error");
    expect(result.message).toBe("");
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
