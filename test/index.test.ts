import { describe, expect, test } from "bun:test";
import { runInNewContext } from "node:vm";
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

    expect<unknown>(result).toEqual({
      message: "Email ****************",
      nested: ["IP ***********", 42, { safe: true }],
    });
    expect(result).not.toBe(input);
    expect(result.nested).not.toBe(input.nested);
    expect(Object.getPrototypeOf(result)).toBeNull();
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

  test("does not dispatch through a replaced array push method", () => {
    const inputValue = "jane@example.com";
    const push = Array.prototype.push;
    const input = new Proxy([inputValue], {
      getOwnPropertyDescriptor: (target, key) => {
        if (key === "length") {
          Array.prototype.push = function (value): number {
            return Reflect.apply(push, this, [value === "[REDACTED]" ? inputValue : value]);
          };
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        Array.prototype.push = push;
      }
    })();

    expect(result).toEqual(["[REDACTED]"]);
    expect(Object.hasOwn(result, "toJSON")).toBeTrue();
    expect(JSON.stringify(result)).toBe('["[REDACTED]"]');
  });

  test("shadows array serialization hooks installed during projection", () => {
    const inputValue = "jane@example.com";
    const toJSONDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
    const input = new Proxy([inputValue], {
      getOwnPropertyDescriptor: (target, key) => {
        if (key === "length") {
          Object.defineProperty(Array.prototype, "toJSON", {
            configurable: true,
            value: () => inputValue,
          });
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });

    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(redactValue(input));
    } finally {
      if (toJSONDescriptor === undefined) Reflect.deleteProperty(Array.prototype, "toJSON");
      else Object.defineProperty(Array.prototype, "toJSON", toJSONDescriptor);
    }

    expect(serialized).toBe('["[REDACTED]"]');
  });

  test("does not invoke array index accessors", () => {
    let invoked = false;
    const input = Array.from<string>({ length: 1 });
    Object.defineProperty(input, 0, {
      enumerable: true,
      get: () => {
        invoked = true;
        throw new Error("Accessor must not run");
      },
    });

    const result = redactValue(input);

    expect(invoked).toBeFalse();
    expect(result).toHaveLength(1);
    expect(0 in result).toBeFalse();
    expect(JSON.stringify(result)).toBe("[null]");
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
    expect(Reflect.get(result, "account")).toBe("[REDACTED]");
  });

  test("protects errors across realms", () => {
    const input: unknown = runInNewContext('new Error("Request from 192.168.0.1")');
    const result = redactValue(input);

    expect(result).toBeInstanceOf(Error);
    if (!(result instanceof Error)) throw new Error("Expected a protected Error");
    expect(result.message).toBe("Request from [REDACTED]");
    expect(result.stack).not.toContain("192.168.0.1");
  });

  test("protects proxied errors across realms", () => {
    const crossRealm: unknown = runInNewContext('new Error("Request from 192.168.0.1")');
    if (typeof crossRealm !== "object" || crossRealm === null) {
      throw new Error("Expected a cross-realm Error object");
    }

    const result = redactValue(new Proxy(crossRealm, {}));

    expect(result).toBeInstanceOf(Error);
    if (!(result instanceof Error)) throw new Error("Expected a protected Error");
    expect(result.message).toBe("Request from [REDACTED]");
    expect(result.stack).not.toContain("192.168.0.1");
  });

  test("does not inspect proxy prototypes while classifying errors", () => {
    const input = new Proxy(new Error("Request from 192.168.0.1"), {
      getPrototypeOf: () => {
        throw new Error("Prototype trap must not run");
      },
    });

    const result = redactValue(input);

    expect(result.message).toBe("Request from [REDACTED]");
    expect(result.stack).not.toContain("192.168.0.1");
  });

  test("does not invoke Symbol.toStringTag accessors while classifying values", () => {
    let reads = 0;
    const input = Object.create({
      get [Symbol.toStringTag](): string {
        reads += 1;
        throw new Error("Accessor must not run");
      },
    }) as { email: string };
    input.email = "jane@example.com";

    const result = redactValue(input);

    expect(reads).toBe(0);
    expect(result.email).toBe("[REDACTED]");
  });

  test("shadows Error prototype serialization hooks installed during projection", () => {
    const original = new Error("Request from 192.168.0.1");
    const input = new Proxy(original, {
      getOwnPropertyDescriptor: (target, key) => {
        if (key === "message") {
          Object.defineProperty(Error.prototype, "toJSON", {
            configurable: true,
            value: () => original.message,
          });
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });

    try {
      const result = redactValue(input);
      expect(result.message).toBe("Request from [REDACTED]");
      expect(Object.hasOwn(result, "toJSON")).toBeTrue();
      expect(JSON.stringify(result)).toBe("{}");
    } finally {
      Reflect.deleteProperty(Error.prototype, "toJSON");
    }
  });

  test("defines protected error names without invoking prototype setters", () => {
    const originalNameDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, "name");
    const original = new Error("Request from 192.168.0.1");
    original.name = "Account jane@example.com";
    const input = new Proxy(original, {
      getOwnPropertyDescriptor: (target, key) => {
        if (key === "message") {
          Object.defineProperty(Error.prototype, "name", {
            configurable: true,
            set: (result: Error) => {
              Object.defineProperty(result, "toJSON", {
                configurable: true,
                value: () => original.message,
              });
            },
          });
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        if (originalNameDescriptor === undefined) Reflect.deleteProperty(Error.prototype, "name");
        else Object.defineProperty(Error.prototype, "name", originalNameDescriptor);
      }
    })();

    expect(result.name).toBe("Account [REDACTED]");
    expect(Reflect.get(result, "toJSON")).toBeUndefined();
    expect(JSON.stringify(result)).toBe('{"name":"Account [REDACTED]"}');
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
    class SecretString extends String {}

    const result = redactValue(new String("jane@example.com"));
    const subclassResult = redactValue(new SecretString("jane@example.com"));
    const crossRealmString: unknown = runInNewContext('new String("jane@example.com")');
    const crossRealmResult = redactValue(crossRealmString);

    expect<unknown>(result).toBe("[REDACTED]");
    expect<unknown>(subclassResult).toBe("[REDACTED]");
    expect(crossRealmResult).toBe("[REDACTED]");
  });

  test("protects proxy-wrapped boxed strings as one value", () => {
    const result = redactValue(new Proxy(new String("jane@example.com"), {}));

    expect<unknown>(result).toBe("[REDACTED]");
    expect(JSON.stringify(result)).toBe('"[REDACTED]"');
  });

  test("fails closed for malformed boxed-string candidates", () => {
    const value = "jane@example.com";
    const input = Object.create(null) as object;
    Object.defineProperty(input, "length", { value: value.length });
    for (let index = 0; index < value.length; index += 1) {
      Object.defineProperty(input, index, {
        configurable: false,
        enumerable: true,
        writable: index === 0,
        value: value[index],
      });
    }

    const result = redactValue(input);

    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(JSON.stringify(result)).toBe("{}");
  });

  test("uses the captured boxed-string intrinsic", () => {
    const valueOf = String.prototype.valueOf;
    String.prototype.valueOf = () => {
      throw new Error("Replaced intrinsic must not run");
    };

    try {
      expect<unknown>(redactValue(new String("jane@example.com"))).toBe("[REDACTED]");
    } finally {
      String.prototype.valueOf = valueOf;
    }
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

  test("uses captured WeakMap methods while projecting callable proxies", () => {
    const setDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "set");
    if (setDescriptor === undefined) throw new Error("WeakMap set descriptor is missing");
    const callable = Object.assign(() => "ignored", { email: "jane@example.com" });
    const input = new Proxy(callable, {
      getPrototypeOf: (target) => {
        Object.defineProperty(WeakMap.prototype, "set", {
          configurable: true,
          value: function (
            this: WeakMap<object, unknown>,
            key: object,
            value: unknown,
          ): WeakMap<object, unknown> {
            if ((typeof value === "object" || typeof value === "function") && value !== null) {
              Object.defineProperty(value, "toJSON", {
                configurable: true,
                value: () => callable.email,
              });
            }
            return Reflect.apply(setDescriptor.value, this, [key, value]);
          },
        });
        return Reflect.getPrototypeOf(target);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        Object.defineProperty(WeakMap.prototype, "set", setDescriptor);
      }
    })();

    expect(result.email).toBe("[REDACTED]");
    expect(Reflect.has(result, "toJSON")).toBeFalse();
    expect(JSON.stringify(result)).toBe('{"email":"[REDACTED]"}');
  });

  test("uses captured Map methods while projecting callable proxies", () => {
    const getDescriptor = Object.getOwnPropertyDescriptor(Map.prototype, "get");
    if (getDescriptor === undefined) throw new Error("Map get descriptor is missing");
    const input = new Proxy(
      Object.assign(() => undefined, { email: "jane@example.com" }),
      {
        ownKeys: (target) => {
          Object.defineProperty(Map.prototype, "get", {
            configurable: true,
            value: (key: unknown) => key,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );
    const masker = createPiiMasker({ mode: "redact" });

    const result = (() => {
      try {
        return masker.value(input);
      } finally {
        Object.defineProperty(Map.prototype, "get", getDescriptor);
      }
    })();

    expect(Reflect.get(result, "email")).toBe("[REDACTED]");
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

  test("does not consult or inherit a stateful proxy prototype", () => {
    const serializer = { toJSON: (): string => "serializer@example.com" };
    let prototypeReads = 0;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        getPrototypeOf: () => {
          prototypeReads += 1;
          return prototypeReads === 1 ? Object.prototype : serializer;
        },
      },
    );

    const result = redactValue(input);

    expect(prototypeReads).toBe(0);
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(JSON.stringify(result)).toBe('{"email":"[REDACTED]"}');
  });

  test("does not inherit hooks added to Object.prototype during projection", () => {
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(Object.prototype, "toJSON", {
            configurable: true,
            value: () => "serializer@example.com",
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    try {
      const result = redactValue(input);
      expect(Object.getPrototypeOf(result)).toBeNull();
      expect(JSON.stringify(result)).toBe('{"email":"[REDACTED]"}');
    } finally {
      Reflect.deleteProperty(Object.prototype, "toJSON");
    }
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

  test("normalizes custom errors, protects their names, and shadows serializers", () => {
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
    expect(Object.hasOwn(result, "toJSON")).toBeTrue();
    expect(Reflect.get(result, "toJSON")).toBeUndefined();
    expect(JSON.stringify(result)).toBe('{"name":"[REDACTED]"}');
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

  test("does not cache repeated strings by default", () => {
    let replacements = 0;
    const masker = createPiiMasker({
      mode: "redact",
      replacement: () => {
        replacements += 1;
        return "<pii>";
      },
    });

    expect(masker.text("Email jane@example.com")).toBe("Email <pii>");
    expect(masker.text("Email jane@example.com")).toBe("Email <pii>");
    expect(replacements).toBe(2);
  });

  test("caches repeated strings when explicitly enabled", () => {
    let replacements = 0;
    const masker = createPiiMasker({
      mode: "redact",
      replacement: () => {
        replacements += 1;
        return "<pii>";
      },
      cacheSize: 1,
    });

    expect(masker.text("Email jane@example.com")).toBe("Email <pii>");
    expect(masker.text("Email jane@example.com")).toBe("Email <pii>");
    expect(replacements).toBe(1);
  });

  test("evicts the least recently used string", () => {
    const transformed: string[] = [];
    const masker = createPiiMasker({
      mode: "redact",
      replacement: (entity) => {
        transformed.push(entity.text);
        return "<pii>";
      },
      cacheSize: 2,
    });

    masker.text("first@example.com");
    masker.text("second@example.com");
    masker.text("first@example.com");
    masker.text("third@example.com");
    masker.text("second@example.com");

    expect(transformed).toEqual([
      "first@example.com",
      "second@example.com",
      "third@example.com",
      "second@example.com",
    ]);
  });

  test("shares an explicitly enabled cache between text and value protection", () => {
    let replacements = 0;
    const masker = createPiiMasker({
      mode: "redact",
      replacement: () => {
        replacements += 1;
        return "<pii>";
      },
      cacheSize: 1,
    });

    expect(masker.text("jane@example.com")).toBe("<pii>");
    expect(masker.value(["jane@example.com"])).toEqual(["<pii>"]);
    expect(replacements).toBe(1);
  });

  test("rejects invalid cache sizes", () => {
    for (const cacheSize of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() => createPiiMasker({ cacheSize })).toThrow(
        "cacheSize must be a non-negative safe integer",
      );
    }
  });
});
