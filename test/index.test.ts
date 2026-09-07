import { describe, expect, test } from "bun:test";
import { inspect } from "node:util";
import { runInNewContext } from "node:vm";
import {
  createPiiMasker,
  findPii,
  maskText,
  maskValue,
  type PIIKind,
  redactText,
  redactValue,
} from "../src/index.js";

const requireObjectProjection: <T>(
  value: T,
) => asserts value is Exclude<Extract<T, object>, Error> = (value) => {
  if (typeof value !== "object" || value === null || value instanceof Error) {
    throw new Error("Expected an object projection");
  }
};

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

  test("invokes replacement callbacks without an options receiver", () => {
    let called = false;

    const result = redactText("Email jane@example.com", {
      replacement: function (this: void): string {
        expect(this).toBeUndefined();
        called = true;
        return "[REDACTED]";
      },
    });

    expect(result).toBe("Email [REDACTED]");
    expect(called).toBeTrue();
  });
});

describe("structured values", () => {
  test("deeply masks arrays and plain objects without mutation", () => {
    const input = {
      message: "Email jane@example.com",
      nested: ["IP 192.168.0.1", 42, { safe: true }],
    };

    const result = maskValue(input);
    requireObjectProjection(result);

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
    requireObjectProjection(result);

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

    if (!Array.isArray(result)) throw new Error("Expected a protected array");
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

    if (!Array.isArray(result)) throw new Error("Expected a protected array");
    expect(invoked).toBeFalse();
    expect(result).toHaveLength(1);
    expect(Object.hasOwn(result, 0)).toBeFalse();
    expect(JSON.stringify(result)).toBe("[null]");
  });

  test("does not expose inherited values through array holes", () => {
    const indexDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 0);
    const inputValue = "jane@example.com";
    const target: unknown[] = [];
    target.length = 1;
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (target, key) => {
        if (key === "length") {
          Object.defineProperty(Object.prototype, 0, {
            configurable: true,
            get: () => inputValue,
          });
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        if (indexDescriptor === undefined) Reflect.deleteProperty(Object.prototype, 0);
        else Object.defineProperty(Object.prototype, 0, indexDescriptor);
      }
    })();

    if (!Array.isArray(result)) throw new Error("Expected a protected array");
    expect(Object.hasOwn(result, 0)).toBeTrue();
    expect(result[0]).toBeUndefined();
    expect(JSON.stringify(result)).toBe("[null]");
  });

  test("does not trust proxies inserted into the array prototype chain", () => {
    const originalPrototype = Object.getPrototypeOf(Array.prototype);
    const inherited = new Proxy(Object.create(originalPrototype) as object, {
      get: (target, key, receiver) =>
        key === "0" ? "jane@example.com" : Reflect.get(target, key, receiver),
      has: (target, key) => (key === "0" ? false : Reflect.has(target, key)),
    });
    const target: unknown[] = [];
    target.length = 1;
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "length") Object.setPrototypeOf(Array.prototype, inherited);
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        Object.setPrototypeOf(Array.prototype, originalPrototype);
      }
    })();

    if (!Array.isArray(result)) throw new Error("Expected a protected array");
    expect(Object.hasOwn(result, 0)).toBeTrue();
    expect(result[0]).toBeUndefined();
    expect(JSON.stringify(result)).toBe("[null]");
  });

  test("rechecks array holes after later values mutate prototypes", () => {
    const indexDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 0);
    const target: unknown[] = [];
    target.length = 2;
    target[1] = new Proxy(
      { safe: true },
      {
        ownKeys: (value) => {
          Object.defineProperty(Object.prototype, 0, {
            configurable: true,
            get: () => "jane@example.com",
          });
          return Reflect.ownKeys(value);
        },
      },
    );

    const result = (() => {
      try {
        return redactValue(target);
      } finally {
        if (indexDescriptor === undefined) Reflect.deleteProperty(Object.prototype, 0);
        else Object.defineProperty(Object.prototype, 0, indexDescriptor);
      }
    })();

    if (!Array.isArray(result)) throw new Error("Expected a protected array");
    expect(Object.hasOwn(result, 0)).toBeTrue();
    expect(result[0]).toBeUndefined();
    expect(result[1]).toEqual({ safe: true });
    expect(JSON.stringify(result)).toBe('[null,{"safe":true}]');
  });

  test("rechecks nested array holes after later object properties mutate prototypes", () => {
    const indexDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 0);
    const sparse: unknown[] = [];
    sparse.length = 1;
    const trigger = new Proxy(
      { safe: true },
      {
        ownKeys: (value) => {
          Object.defineProperty(Object.prototype, 0, {
            configurable: true,
            get: () => "jane@example.com",
          });
          return Reflect.ownKeys(value);
        },
      },
    );

    const result = (() => {
      try {
        return redactValue({ sparse, trigger });
      } finally {
        if (indexDescriptor === undefined) Reflect.deleteProperty(Object.prototype, 0);
        else Object.defineProperty(Object.prototype, 0, indexDescriptor);
      }
    })();
    requireObjectProjection(result);
    const protectedSparse = result.sparse;
    if (!Array.isArray(protectedSparse)) throw new Error("Expected a protected array");

    expect(Object.hasOwn(protectedSparse, 0)).toBeTrue();
    expect(protectedSparse[0]).toBeUndefined();
    expect(JSON.stringify(result)).toBe('{"sparse":[null],"trigger":{"safe":true}}');
  });

  test("protects Error messages, stacks, causes, and metadata", () => {
    const cause = new Error("User jane@example.com");
    const input = new Error("Request from 192.168.0.1", { cause });
    Object.assign(input, { account: "jane@example.com" });

    const result = redactValue(input);

    expect(result).toBeInstanceOf(Error);
    expect(result).not.toBe(input);
    if (typeof result === "string") throw new Error("Expected a protected Error");
    expect(result.message).toBe("Request from [REDACTED]");
    expect(result.stack).not.toContain("192.168.0.1");
    expect((result.cause as Error).message).toBe("User [REDACTED]");
    expect(Reflect.get(result, "account")).toBe("[REDACTED]");
  });

  test("projects non-string Error diagnostic fields", () => {
    const branded = new Error("safe");
    Object.defineProperties(branded, {
      message: { configurable: true, value: { email: "jane@example.com" }, writable: true },
      name: { configurable: true, value: { host: "192.168.0.1" }, writable: true },
      stack: { configurable: true, value: { account: "jane@example.com" }, writable: true },
    });
    const structural = Object.create(null) as object;
    Object.defineProperties(structural, {
      message: { configurable: true, value: { email: "jane@example.com" }, writable: true },
      stack: { configurable: true, value: "Request from 192.168.0.1", writable: true },
    });

    const brandedResult = redactValue(branded);
    const structuralResult = redactValue(structural);

    if (typeof brandedResult === "string") throw new Error("Expected a protected Error");
    expect<unknown>(Reflect.get(brandedResult, "message")).toEqual({ email: "[REDACTED]" });
    expect<unknown>(Reflect.get(brandedResult, "name")).toEqual({ host: "[REDACTED]" });
    expect<unknown>(Reflect.get(brandedResult, "stack")).toEqual({ account: "[REDACTED]" });
    if (!(structuralResult instanceof Error)) throw new Error("Expected a protected Error");
    expect<unknown>(Reflect.get(structuralResult, "message")).toEqual({
      email: "[REDACTED]",
    });
    expect(structuralResult.stack).toBe("Request from [REDACTED]");
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

    if (typeof result === "string") throw new Error("Expected a protected Error");
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
    requireObjectProjection(result);
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
      if (typeof result === "string") throw new Error("Expected a protected Error");
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

    if (typeof result === "string") throw new Error("Expected a protected Error");
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

    requireObjectProjection(result);
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

  test("protects boxed strings nested in structured values", () => {
    const result = redactValue({ boxed: new String("jane@example.com") });

    requireObjectProjection(result);
    expect(result.boxed).toBe("[REDACTED]");
  });

  test("protects proxy-wrapped boxed strings as one value", () => {
    const result = redactValue(new Proxy(new String("jane@example.com"), {}));

    expect<unknown>(result).toBe("[REDACTED]");
    expect(JSON.stringify(result)).toBe('"[REDACTED]"');
  });

  test("protects boxed strings before applying structural Error detection", () => {
    const input = new String("jane@example.com");
    Object.defineProperty(input, "message", { value: "diagnostic" });

    const result = redactValue(input);

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
    requireObjectProjection(result);
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

  test("uses guarded detections in reusable structured protectors", () => {
    const execDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, "exec");
    if (execDescriptor === undefined) throw new Error("RegExp exec descriptor is missing");
    const poisonedExec = (): null => null;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(RegExp.prototype, "exec", {
            ...execDescriptor,
            value: poisonedExec,
          });
          return Reflect.ownKeys(target);
        },
      },
    );
    const masker = createPiiMasker({ cacheSize: 0, mode: "redact" });

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = masker.value(input);
        replacementRestored = RegExp.prototype.exec === poisonedExec;
        return protectedValue;
      } finally {
        Object.defineProperty(RegExp.prototype, "exec", execDescriptor);
      }
    })();

    requireObjectProjection(result);
    expect(replacementRestored).toBeTrue();
    expect(result.email).toBe("[REDACTED]");
  });

  test("detects direct strings before traversing later proxy values", () => {
    const getDescriptor = Object.getOwnPropertyDescriptor(Map.prototype, "get");
    if (getDescriptor === undefined) throw new Error("Map get descriptor is missing");
    const poisonedGet = (): undefined => undefined;
    const trigger = new Proxy(Object.create(null) as object, {
      ownKeys: (target) => {
        Object.defineProperty(Map.prototype, "get", {
          ...getDescriptor,
          value: poisonedGet,
        });
        return Reflect.ownKeys(target);
      },
    });

    const result = (() => {
      try {
        return redactValue({ wallet: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", trigger });
      } finally {
        Object.defineProperty(Map.prototype, "get", getDescriptor);
      }
    })();

    requireObjectProjection(result);
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("runs replacement callbacks before traversing later values", () => {
    const events: string[] = [];
    const replacementError = new Error("Replacement failed");
    const later = new Proxy(Object.create(null) as object, {
      ownKeys: (target) => {
        events.push("traverse-later");
        return Reflect.ownKeys(target);
      },
    });
    let thrown: unknown;

    try {
      redactValue(
        { email: "jane@example.com", later },
        {
          replacement: () => {
            events.push("callback");
            throw replacementError;
          },
        },
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBe(replacementError);
    expect(events).toEqual(["callback"]);
  });

  test("uses captured Math.min after proxy traversal", () => {
    const minDescriptor = Object.getOwnPropertyDescriptor(Math, "min");
    if (minDescriptor === undefined) throw new Error("Math.min descriptor is missing");
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(Math, "min", {
            configurable: true,
            value: (_left: number, right: number) => right,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    try {
      const result = maskValue(input);
      requireObjectProjection(result);
      expect(result.email).toBe("****************");
    } finally {
      Object.defineProperty(Math, "min", minDescriptor);
    }
  });

  test("uses the captured entity sorter after proxy traversal", () => {
    const sortDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "sort");
    if (sortDescriptor === undefined) throw new Error("Array sort descriptor is missing");
    const originalSort: (
      this: unknown[],
      compare?: (left: unknown, right: unknown) => number,
    ) => unknown[] = sortDescriptor.value;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(Array.prototype, "sort", {
            configurable: true,
            value: function (
              this: unknown[],
              compare?: (left: unknown, right: unknown) => number,
            ): unknown[] {
              const first = this[0];
              if (typeof first === "object" && first !== null && "start" in first) {
                this.length = 0;
                return this;
              }
              return Reflect.apply(originalSort, this, [compare]);
            },
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    try {
      const result = redactValue(input);
      requireObjectProjection(result);
      expect(result.email).toBe("[REDACTED]");
    } finally {
      Object.defineProperty(Array.prototype, "sort", sortDescriptor);
    }
  });

  test("protects detector array methods after proxy traversal", () => {
    const filterDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "filter");
    if (filterDescriptor === undefined) throw new Error("Array filter descriptor is missing");
    const poisonedFilter = (): never[] => [];
    const input = new Proxy(
      Object.assign(() => undefined, { email: "jane@example.com" }),
      {
        ownKeys: (target) => {
          Object.defineProperty(Array.prototype, "filter", {
            configurable: true,
            value: poisonedFilter,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = Array.prototype.filter === poisonedFilter;
        return protectedValue;
      } finally {
        Object.defineProperty(Array.prototype, "filter", filterDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    expect(result.email).toBe("[REDACTED]");
  });

  test("protects detector string methods after proxy traversal", () => {
    const lastIndexOfDescriptor = Object.getOwnPropertyDescriptor(String.prototype, "lastIndexOf");
    if (lastIndexOfDescriptor === undefined) {
      throw new Error("String lastIndexOf descriptor is missing");
    }
    const poisonedLastIndexOf = (): number => 1000;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(String.prototype, "lastIndexOf", {
            configurable: true,
            value: poisonedLastIndexOf,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = String.prototype.lastIndexOf === poisonedLastIndexOf;
        return protectedValue;
      } finally {
        Object.defineProperty(String.prototype, "lastIndexOf", lastIndexOfDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    requireObjectProjection(result);
    expect(result.email).toBe("[REDACTED]");
  });

  test("protects detector regular expression methods after proxy traversal", () => {
    const execDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, "exec");
    if (execDescriptor === undefined) throw new Error("RegExp exec descriptor is missing");
    const poisonedExec = (): null => null;
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        ownKeys: (target) => {
          Object.defineProperty(RegExp.prototype, "exec", {
            configurable: true,
            value: poisonedExec,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = RegExp.prototype.exec === poisonedExec;
        return protectedValue;
      } finally {
        Object.defineProperty(RegExp.prototype, "exec", execDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    requireObjectProjection(result);
    expect(result.email).toBe("[REDACTED]");
  });

  test("snapshots redaction options before proxy traversal", () => {
    const email = "jane@example.com";
    const options: { kinds: PIIKind[]; replacement: string } = {
      kinds: ["email"],
      replacement: "[REDACTED]",
    };
    const input = new Proxy(
      { email },
      {
        ownKeys: (target) => {
          options.kinds.length = 0;
          options.replacement = email;
          return Reflect.ownKeys(target);
        },
      },
    );

    const result = redactValue(input, options);

    requireObjectProjection(result);
    expect(result.email).toBe("[REDACTED]");
  });

  test("protects detector numeric dependencies after proxy traversal", () => {
    const numberDescriptor = Object.getOwnPropertyDescriptor(globalThis, "Number");
    if (numberDescriptor === undefined) throw new Error("Global Number descriptor is missing");
    const poisonedNumber = (): number => 0;
    const input = new Proxy(
      { wallet: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" },
      {
        ownKeys: (target) => {
          Object.defineProperty(globalThis, "Number", {
            ...numberDescriptor,
            value: poisonedNumber,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = globalThis.Number === poisonedNumber;
        return protectedValue;
      } finally {
        Object.defineProperty(globalThis, "Number", numberDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    requireObjectProjection(result);
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("protects detector iterator steps after proxy traversal", () => {
    const arrayIteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]()) as object;
    const stringIteratorPrototype = Object.getPrototypeOf(""[Symbol.iterator]()) as object;
    const arrayNextDescriptor = Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next");
    const stringNextDescriptor = Object.getOwnPropertyDescriptor(stringIteratorPrototype, "next");
    if (arrayNextDescriptor === undefined)
      throw new Error("Array iterator next descriptor is missing");
    if (stringNextDescriptor === undefined) {
      throw new Error("String iterator next descriptor is missing");
    }
    const poisonedArrayNext = (): never => {
      throw new Error("Poisoned array iterator must not run");
    };
    const poisonedStringNext = (): IteratorResult<string, undefined> => ({
      done: true,
      value: undefined,
    });
    const input = new Proxy(
      { wallet: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" },
      {
        ownKeys: (target) => {
          Object.defineProperty(arrayIteratorPrototype, "next", {
            configurable: true,
            value: poisonedArrayNext,
            writable: true,
          });
          Object.defineProperty(stringIteratorPrototype, "next", {
            configurable: true,
            value: poisonedStringNext,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let arrayReplacementRestored = false;
    let stringReplacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        arrayReplacementRestored =
          Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next")?.value ===
          poisonedArrayNext;
        stringReplacementRestored =
          Object.getOwnPropertyDescriptor(stringIteratorPrototype, "next")?.value ===
          poisonedStringNext;
        return protectedValue;
      } finally {
        Object.defineProperty(arrayIteratorPrototype, "next", arrayNextDescriptor);
        Object.defineProperty(stringIteratorPrototype, "next", stringNextDescriptor);
      }
    })();

    expect(arrayReplacementRestored).toBeTrue();
    expect(stringReplacementRestored).toBeTrue();
    requireObjectProjection(result);
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("restores exact detector descriptors after detection", () => {
    const filterDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "filter");
    const lastIndexOfDescriptor = Object.getOwnPropertyDescriptor(String.prototype, "lastIndexOf");
    const execDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, "exec");
    if (filterDescriptor === undefined) throw new Error("Array filter descriptor is missing");
    if (lastIndexOfDescriptor === undefined) {
      throw new Error("String lastIndexOf descriptor is missing");
    }
    if (execDescriptor === undefined) throw new Error("RegExp exec descriptor is missing");
    const accessor = (): typeof filterDescriptor.value => filterDescriptor.value;
    const callerFilterDescriptor = {
      configurable: true,
      enumerable: false,
      get: accessor,
    } as const;
    const callerExecDescriptor = {
      ...execDescriptor,
      enumerable: !execDescriptor.enumerable,
    };
    let restoredFilterDescriptor: PropertyDescriptor | undefined;
    let restoredLastIndexOfDescriptor: PropertyDescriptor | undefined;
    let restoredExecDescriptor: PropertyDescriptor | undefined;
    let protectedValue = "";

    try {
      Object.defineProperty(Array.prototype, "filter", callerFilterDescriptor);
      Reflect.deleteProperty(String.prototype, "lastIndexOf");
      Object.defineProperty(RegExp.prototype, "exec", callerExecDescriptor);
      protectedValue = redactValue("jane@example.com");
      restoredFilterDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "filter");
      restoredLastIndexOfDescriptor = Object.getOwnPropertyDescriptor(
        String.prototype,
        "lastIndexOf",
      );
      restoredExecDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, "exec");
    } finally {
      Object.defineProperty(Array.prototype, "filter", filterDescriptor);
      Object.defineProperty(String.prototype, "lastIndexOf", lastIndexOfDescriptor);
      Object.defineProperty(RegExp.prototype, "exec", execDescriptor);
    }

    expect(protectedValue).toBe("[REDACTED]");
    expect(restoredFilterDescriptor).toEqual(callerFilterDescriptor);
    expect(restoredLastIndexOfDescriptor).toBeUndefined();
    expect(restoredExecDescriptor).toEqual(callerExecDescriptor);
  });

  test("protects crypto detection from a replaced array fill method", () => {
    const fillDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "fill");
    if (fillDescriptor === undefined) throw new Error("Array fill descriptor is missing");
    const poisonedFill = (): never[] => [];
    const input = new Proxy(
      Object.assign(() => undefined, { wallet: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" }),
      {
        ownKeys: (target) => {
          Object.defineProperty(Array.prototype, "fill", {
            configurable: true,
            value: poisonedFill,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = Array.prototype.fill === poisonedFill;
        return protectedValue;
      } finally {
        Object.defineProperty(Array.prototype, "fill", fillDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("protects crypto detection from replaced typed-array accessors", () => {
    const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
    const bufferDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer");
    const byteLengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength");
    const byteOffsetDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset");
    const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length");
    if (
      bufferDescriptor === undefined ||
      byteLengthDescriptor === undefined ||
      byteOffsetDescriptor === undefined ||
      lengthDescriptor === undefined
    ) {
      throw new Error("Typed-array accessor descriptor is missing");
    }
    const poisonedAccessor = (): never => {
      throw new Error("Poisoned typed-array accessor must not run");
    };
    const input = new Proxy(
      Object.assign(() => undefined, { wallet: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" }),
      {
        ownKeys: (target) => {
          Object.defineProperties(typedArrayPrototype, {
            buffer: { ...bufferDescriptor, get: poisonedAccessor },
            byteLength: { ...byteLengthDescriptor, get: poisonedAccessor },
            byteOffset: { ...byteOffsetDescriptor, get: poisonedAccessor },
            length: { ...lengthDescriptor, get: poisonedAccessor },
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored =
          Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")?.get ===
            poisonedAccessor &&
          Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")?.get ===
            poisonedAccessor &&
          Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset")?.get ===
            poisonedAccessor &&
          Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")?.get === poisonedAccessor;
        return protectedValue;
      } finally {
        Object.defineProperties(typedArrayPrototype, {
          buffer: bufferDescriptor,
          byteLength: byteLengthDescriptor,
          byteOffset: byteOffsetDescriptor,
          length: lengthDescriptor,
        });
      }
    })();

    expect(replacementRestored).toBeTrue();
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("protects crypto detection from concrete typed-array overrides", () => {
    const setDescriptor = Object.getOwnPropertyDescriptor(Uint8Array.prototype, "set");
    const poisonedSet = (): never => {
      throw new Error("Poisoned concrete typed-array method must not run");
    };
    const input = new Proxy(
      Object.assign(() => undefined, {
        wallet: "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE",
      }),
      {
        ownKeys: (target) => {
          Object.defineProperty(Uint8Array.prototype, "set", {
            configurable: true,
            value: poisonedSet,
            writable: true,
          });
          return Reflect.ownKeys(target);
        },
      },
    );

    let replacementRestored = false;
    const result = (() => {
      try {
        const protectedValue = redactValue(input);
        replacementRestored = Uint8Array.prototype.set === poisonedSet;
        return protectedValue;
      } finally {
        if (setDescriptor === undefined) Reflect.deleteProperty(Uint8Array.prototype, "set");
        else Object.defineProperty(Uint8Array.prototype, "set", setDescriptor);
      }
    })();

    expect(replacementRestored).toBeTrue();
    expect(result.wallet).toBe("[REDACTED]");
  });

  test("protects public text crypto detection from concrete typed-array overrides", () => {
    const setDescriptor = Object.getOwnPropertyDescriptor(Uint8Array.prototype, "set");
    const poisonedSet = (): never => {
      throw new Error("Poisoned concrete typed-array method must not run");
    };
    const wallet = "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE";

    try {
      Object.defineProperty(Uint8Array.prototype, "set", {
        configurable: true,
        value: poisonedSet,
        writable: true,
      });
      expect(findPii(wallet).some((entity) => entity.kind === "crypto_address")).toBeTrue();
      expect(maskText(wallet)).not.toBe(wallet);
      expect(redactText(wallet)).toBe("[REDACTED]");
      expect(Uint8Array.prototype.set).toBe(poisonedSet);
    } finally {
      if (setDescriptor === undefined) Reflect.deleteProperty(Uint8Array.prototype, "set");
      else Object.defineProperty(Uint8Array.prototype, "set", setDescriptor);
    }
  });

  test("restores detector methods when detection throws", () => {
    const filterDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "filter");
    if (filterDescriptor === undefined) throw new Error("Array filter descriptor is missing");
    const poisonedFilter = (): never[] => [];
    const detectorError = new Error("Detector failed");
    const invalidInput = new Proxy(Object.create(null) as object, {
      get: () => {
        throw detectorError;
      },
    }) as unknown as string;
    let replacementRestored = false;
    let thrown: unknown;

    try {
      Object.defineProperty(Array.prototype, "filter", {
        ...filterDescriptor,
        value: poisonedFilter,
      });
      try {
        findPii(invalidInput);
      } catch (error) {
        thrown = error;
        replacementRestored = Array.prototype.filter === poisonedFilter;
      }
    } finally {
      Object.defineProperty(Array.prototype, "filter", filterDescriptor);
    }

    expect(thrown).toBe(detectorError);
    expect(replacementRestored).toBeTrue();
  });

  test("does not use a replaced array iterator for entity copies", () => {
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator);
    if (iteratorDescriptor === undefined) throw new Error("Array iterator descriptor is missing");
    const kinds = new Proxy<PIIKind[]>(["email"], {
      get: (target, key, receiver) => {
        if (key === "length") {
          Object.defineProperty(Array.prototype, Symbol.iterator, {
            configurable: true,
            value: function* (): Generator<never> {},
            writable: true,
          });
        }
        return Reflect.get(target, key, receiver);
      },
    });

    try {
      expect(redactText("jane@example.com", { kinds })).toBe("[REDACTED]");
    } finally {
      Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
    }
  });

  test("uses captured string slicing after proxy traversal", () => {
    const sliceDescriptor = Object.getOwnPropertyDescriptor(String.prototype, "slice");
    if (sliceDescriptor === undefined) throw new Error("String slice descriptor is missing");
    const input = new Proxy(
      { email: "jane@example.com" },
      {
        getOwnPropertyDescriptor: (target, key) => {
          Object.defineProperty(String.prototype, "slice", {
            configurable: true,
            value: function (this: string): string {
              return this;
            },
            writable: true,
          });
          return Object.getOwnPropertyDescriptor(target, key);
        },
      },
    );

    try {
      const result = redactValue(input);
      requireObjectProjection(result);
      expect(result.email).toBe("[REDACTED]");
    } finally {
      Object.defineProperty(String.prototype, "slice", sliceDescriptor);
    }
  });

  test("neutralizes prepareStackTrace for structural errors without stacks", () => {
    const prepareDescriptor = Object.getOwnPropertyDescriptor(Error, "prepareStackTrace");
    const target = Object.create(null) as object;
    Object.defineProperty(target, "message", { value: "jane@example.com" });
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "stack") {
          Object.defineProperty(Error, "prepareStackTrace", {
            configurable: true,
            value: () => "jane@example.com",
            writable: true,
          });
        }
        return Object.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      if (!(result instanceof Error)) throw new Error("Expected a protected Error");
      expect(result.stack).toBeUndefined();
      expect(result.message).toBe("[REDACTED]");
    } finally {
      if (prepareDescriptor === undefined) Reflect.deleteProperty(Error, "prepareStackTrace");
      else Object.defineProperty(Error, "prepareStackTrace", prepareDescriptor);
    }
  });

  test("does not inherit array inspection hooks installed during projection", () => {
    const inspectKey = Symbol.for("nodejs.util.inspect.custom");
    const inspectDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, inspectKey);
    const input = new Proxy(["jane@example.com"], {
      getOwnPropertyDescriptor: (target, key) => {
        Object.defineProperty(Array.prototype, inspectKey, {
          configurable: true,
          value: () => target[0],
        });
        return Object.getOwnPropertyDescriptor(target, key);
      },
    });

    try {
      const result = redactValue(input);
      const rendered = inspect(result);
      expect(rendered).toContain("[REDACTED]");
      expect(rendered).not.toContain("jane@example.com");
    } finally {
      if (inspectDescriptor === undefined) {
        Reflect.deleteProperty(Array.prototype, inspectKey);
      } else {
        Object.defineProperty(Array.prototype, inspectKey, inspectDescriptor);
      }
    }
  });

  test("does not inherit array iterators installed during projection", () => {
    const iteratorDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator);
    const entriesDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "entries");
    const keysDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "keys");
    const valuesDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "values");
    const arrayIteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]()) as object;
    const arrayNextDescriptor = Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next");
    const iteratorPrototype = Object.getPrototypeOf(arrayIteratorPrototype) as object;
    const inheritedIteratorDescriptor = Object.getOwnPropertyDescriptor(
      iteratorPrototype,
      Symbol.iterator,
    );
    const returnDescriptor = Object.getOwnPropertyDescriptor(iteratorPrototype, "return");
    const iteratorToJsonDescriptor = Object.getOwnPropertyDescriptor(iteratorPrototype, "toJSON");
    if (iteratorDescriptor === undefined) throw new Error("Array iterator descriptor is missing");
    if (entriesDescriptor === undefined) throw new Error("Array entries descriptor is missing");
    if (keysDescriptor === undefined) throw new Error("Array keys descriptor is missing");
    if (valuesDescriptor === undefined) throw new Error("Array values descriptor is missing");
    if (arrayNextDescriptor === undefined) {
      throw new Error("Array iterator next descriptor is missing");
    }
    if (inheritedIteratorDescriptor === undefined) {
      throw new Error("Array iterator identity descriptor is missing");
    }
    const target = ["jane@example.com"];
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        const poisonedIterator = function* (): Generator<string> {
          yield value[0] ?? "";
        };
        Object.defineProperties(Array.prototype, {
          [Symbol.iterator]: {
            configurable: true,
            value: poisonedIterator,
            writable: true,
          },
          entries: {
            configurable: true,
            value: poisonedIterator,
            writable: true,
          },
          keys: {
            configurable: true,
            value: poisonedIterator,
            writable: true,
          },
          values: {
            configurable: true,
            value: poisonedIterator,
            writable: true,
          },
        });
        Object.defineProperty(iteratorPrototype, Symbol.iterator, {
          configurable: true,
          value: function* (): Generator<string> {
            yield value[0] ?? "";
          },
          writable: true,
        });
        Object.defineProperty(iteratorPrototype, "return", {
          configurable: true,
          value: (): never => {
            throw new Error("Poisoned iterator return must not run");
          },
          writable: true,
        });
        Object.defineProperty(iteratorPrototype, "toJSON", {
          configurable: true,
          value: () => value[0],
          writable: true,
        });
        Object.defineProperty(arrayIteratorPrototype, "next", {
          configurable: true,
          value: (): never => {
            throw new Error("Poisoned array iterator must not run");
          },
          writable: true,
        });
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    let iterated: unknown[] = [];
    let iteratedEntries: unknown[] = [];
    let iteratedKeys: unknown[] = [];
    let iteratedValues: unknown[] = [];
    let iteratorTag = "";
    let iteratorAliasesValues = false;
    let detachedValuesThrew = false;
    let borrowedValues: unknown[] = [];
    let iteratorJson = "";
    let earlyExitSucceeded = false;
    let iteratorPrototypeIsNull = false;
    try {
      const result = redactValue(input);
      if (!Array.isArray(result)) throw new Error("Expected a protected array");
      iteratorTag = Object.prototype.toString.call(result[Symbol.iterator]());
      iteratorAliasesValues = result[Symbol.iterator] === result.values;
      iterated = [...result];
      iteratedEntries = [...result.entries()];
      iteratedKeys = [...result.keys()];
      iteratedValues = [...result.values()];
      const valuesIterator = result.values();
      iteratorPrototypeIsNull = Object.getPrototypeOf(valuesIterator) === null;
      iteratorJson = JSON.stringify(valuesIterator);
      for (const _value of result) {
        earlyExitSucceeded = true;
        break;
      }
      const detachedValues = result.values as unknown as () => ArrayIterator<unknown>;
      try {
        detachedValues();
      } catch (error) {
        detachedValuesThrew = error instanceof TypeError;
      }
      borrowedValues = [...Reflect.apply(result.values, ["safe"], [])];
    } finally {
      Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
      Object.defineProperty(Array.prototype, "entries", entriesDescriptor);
      Object.defineProperty(Array.prototype, "keys", keysDescriptor);
      Object.defineProperty(Array.prototype, "values", valuesDescriptor);
      Object.defineProperty(arrayIteratorPrototype, "next", arrayNextDescriptor);
      Object.defineProperty(iteratorPrototype, Symbol.iterator, inheritedIteratorDescriptor);
      if (returnDescriptor === undefined) Reflect.deleteProperty(iteratorPrototype, "return");
      else Object.defineProperty(iteratorPrototype, "return", returnDescriptor);
      if (iteratorToJsonDescriptor === undefined)
        Reflect.deleteProperty(iteratorPrototype, "toJSON");
      else Object.defineProperty(iteratorPrototype, "toJSON", iteratorToJsonDescriptor);
    }

    expect(iteratorTag).toBe("[object Array Iterator]");
    expect(iteratorAliasesValues).toBeTrue();
    expect(detachedValuesThrew).toBeTrue();
    expect(borrowedValues).toEqual(["safe"]);
    expect(iteratorJson).toBe("{}");
    expect(earlyExitSucceeded).toBeTrue();
    expect(iteratorPrototypeIsNull).toBeTrue();
    expect(iterated).toEqual(["[REDACTED]"]);
    expect(iteratedEntries).toEqual([[0, "[REDACTED]"]]);
    expect(iteratedKeys).toEqual([0]);
    expect(iteratedValues).toEqual(["[REDACTED]"]);
  });

  test("does not inherit array methods installed during projection", () => {
    const mapDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "map");
    if (mapDescriptor === undefined) throw new Error("Array map descriptor is missing");
    const target = ["jane@example.com"];
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        Object.defineProperty(Array.prototype, "map", {
          ...mapDescriptor,
          value: (): string[] => [value[0] ?? ""],
        });
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    let mapped: string[] = [];
    let inheritsNativeArrayPrototype = true;
    try {
      const result = redactValue(input);
      if (!Array.isArray(result)) throw new Error("Expected a protected array");
      inheritsNativeArrayPrototype = result instanceof Array;
      mapped = result.map((value) => value).map((value) => value);
    } finally {
      Object.defineProperty(Array.prototype, "map", mapDescriptor);
    }

    expect(inheritsNativeArrayPrototype).toBeFalse();
    expect(mapped).toEqual(["[REDACTED]"]);
  });

  test("does not inherit protocol hooks installed during projection", async () => {
    const thenDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "then");
    const target = ["jane@example.com"];
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        // oxlint-disable-next-line unicorn/no-thenable -- This regression deliberately installs a hostile thenable hook.
        Object.defineProperty(Array.prototype, "then", {
          configurable: true,
          value: (resolve: (value: string) => void): void => resolve(value[0] ?? ""),
        });
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    let resolved: unknown;
    try {
      const result = redactValue(input);
      resolved = await Promise.resolve(result);
    } finally {
      if (thenDescriptor === undefined) Reflect.deleteProperty(Array.prototype, "then");
      // oxlint-disable-next-line unicorn/no-thenable -- Restore a pre-existing descriptor exactly.
      else Object.defineProperty(Array.prototype, "then", thenDescriptor);
    }

    expect(resolved).toEqual(["[REDACTED]"]);
  });

  test("protects arrays returned by change-by-copy methods", () => {
    const inspectKey = Symbol.for("nodejs.util.inspect.custom");
    const inspectDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, inspectKey);
    const target = [{ email: "jane@example.com" }];
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        Object.defineProperty(Array.prototype, inspectKey, {
          configurable: true,
          value: () => value[0],
        });
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      if (!Array.isArray(result)) throw new Error("Expected a protected array");
      const copied = result.toReversed().toReversed();
      expect(String(copied)).toBe("[object Object]");
      expect(inspect(copied)).not.toContain("jane@example.com");
      expect(copied instanceof Array).toBeFalse();
    } finally {
      if (inspectDescriptor === undefined) Reflect.deleteProperty(Array.prototype, inspectKey);
      else Object.defineProperty(Array.prototype, inspectKey, inspectDescriptor);
    }
  });

  test("stringifies projected object elements without invoking missing hooks", () => {
    const result = redactValue([{ email: "jane@example.com" }]);
    if (!Array.isArray(result)) throw new Error("Expected a protected array");

    expect(result.toString()).toBe("[object Object]");
    expect(String(result)).toBe("[object Object]");
    expect(result.join(" | ")).toBe("[object Object]");
    expect(result.toLocaleString()).toBe("[object Object]");
    expect(String(result.map((value) => value))).toBe("[object Object]");
  });

  test("preserves array join coercion order and symbol errors", () => {
    const result = redactValue([1, 2]);
    if (!Array.isArray(result)) throw new Error("Expected a protected array");
    const separator = {
      toString: (): string => {
        result.length = 0;
        return "|";
      },
    };

    const join = result.join;
    if (typeof join !== "function") throw new Error("Expected a protected join method");
    expect(Reflect.apply(join, result, [separator])).toBe("|");
    const symbolResult = redactValue([1, 2]);
    if (!Array.isArray(symbolResult)) throw new Error("Expected a protected array");
    const symbolJoin = symbolResult.join;
    if (typeof symbolJoin !== "function") throw new Error("Expected a protected join method");
    expect(() => Reflect.apply(symbolJoin, symbolResult, [Symbol("separator")])).toThrow(TypeError);
  });

  test("preserves locale formatting for projected array primitives", () => {
    const result = redactValue([1234.5, 1234n, Symbol("safe")]);
    if (!Array.isArray(result)) throw new Error("Expected a protected array");

    expect(result.toLocaleString("de-DE")).toBe("1.234,5,1.234,Symbol(safe)");
  });

  test("stringifies and inspects circular projected arrays", () => {
    const input: unknown[] = [];
    input[0] = input;

    const result = redactValue(input);
    if (!Array.isArray(result)) throw new Error("Expected a protected array");

    expect(String(result)).toBe("");
    expect(inspect(result)).toContain("[Circular");
  });

  test("preserves native symbol stringification errors", () => {
    const result = redactValue([Symbol("jane@example.com")]);
    if (!Array.isArray(result)) throw new Error("Expected a protected array");

    expect(() => String(result)).toThrow(TypeError);
  });

  test("does not use poisoned array iteration while projecting Error keys", () => {
    const arrayIteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]()) as object;
    const nextDescriptor = Object.getOwnPropertyDescriptor(arrayIteratorPrototype, "next");
    if (nextDescriptor === undefined) throw new Error("Array iterator next descriptor is missing");
    const target = Object.assign(new Error("safe"), { email: "jane@example.com" });
    const input = new Proxy(target, {
      ownKeys: (error) => {
        Object.defineProperty(arrayIteratorPrototype, "next", {
          configurable: true,
          value: (): never => {
            throw new Error("Poisoned array iterator must not run");
          },
          writable: true,
        });
        return Reflect.ownKeys(error);
      },
    });

    const result = (() => {
      try {
        return redactValue(input);
      } finally {
        Object.defineProperty(arrayIteratorPrototype, "next", nextDescriptor);
      }
    })();

    if (!(result instanceof Error)) throw new Error("Expected a protected Error");
    expect(Reflect.get(result, "email")).toBe("[REDACTED]");
  });

  test("does not inherit Error inspection hooks installed during projection", () => {
    const inspectKey = Symbol.for("nodejs.util.inspect.custom");
    const inspectDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, inspectKey);
    const target = new Error("jane@example.com");
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (error, key) => {
        Object.defineProperty(Error.prototype, inspectKey, {
          configurable: true,
          value: () => error.message,
        });
        return Object.getOwnPropertyDescriptor(error, key);
      },
    });

    try {
      const result = redactValue(input);
      expect(inspect(result).split("\n")[0]).toBe("Error: [REDACTED]");
    } finally {
      if (inspectDescriptor === undefined) {
        Reflect.deleteProperty(Error.prototype, inspectKey);
      } else {
        Object.defineProperty(Error.prototype, inspectKey, inspectDescriptor);
      }
    }
  });

  test("does not inherit an Error name installed during projection", () => {
    const nameDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, "name");
    if (nameDescriptor === undefined) throw new Error("Error name descriptor is missing");
    const input = new Proxy(new Error("safe"), {
      ownKeys: (error) => {
        Object.defineProperty(Error.prototype, "name", {
          ...nameDescriptor,
          value: "jane@example.com",
        });
        return Reflect.ownKeys(error);
      },
    });

    let result: Error;
    try {
      const protectedValue = redactValue(input);
      if (!(protectedValue instanceof Error)) throw new Error("Expected a protected Error");
      result = protectedValue;
    } finally {
      Object.defineProperty(Error.prototype, "name", nameDescriptor);
    }

    expect(String(result)).toBe("Error: safe");
  });

  test("shadows arbitrary Error prototype additions installed during projection", () => {
    const leakDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, "leak");
    const input = new Proxy(new Error("jane@example.com"), {
      getOwnPropertyDescriptor: (error, key) => {
        if (key === "message") {
          Object.defineProperty(Error.prototype, "leak", {
            configurable: true,
            enumerable: true,
            value: "jane@example.com",
          });
        }
        return Object.getOwnPropertyDescriptor(error, key);
      },
    });

    try {
      const result = redactValue(input);
      if (!(result instanceof Error)) throw new Error("Expected a protected Error");
      const inheritedKeys: PropertyKey[] = [];
      for (const key in result) inheritedKeys.push(key);
      expect(Reflect.get(result, "leak")).toBeUndefined();
      expect(Object.hasOwn(result, "leak")).toBeTrue();
      expect(inheritedKeys).not.toContain("leak");
    } finally {
      if (leakDescriptor === undefined) Reflect.deleteProperty(Error.prototype, "leak");
      else Object.defineProperty(Error.prototype, "leak", leakDescriptor);
    }
  });

  test("shadows additions from Error prototype chains replaced during projection", () => {
    const originalPrototype = Object.getPrototypeOf(Error.prototype);
    const insertedTarget = Object.create(originalPrototype) as object;
    let ownKeysCalls = 0;
    const insertedPrototype = new Proxy(insertedTarget, {
      ownKeys: (target) => {
        ownKeysCalls += 1;
        const keys = Reflect.ownKeys(target);
        Object.defineProperty(target, "leak", {
          configurable: true,
          enumerable: true,
          value: "jane@example.com",
        });
        return keys;
      },
    });
    const input = new Proxy(new Error("jane@example.com"), {
      getOwnPropertyDescriptor: (error, key) => {
        if (key === "message") Object.setPrototypeOf(Error.prototype, insertedPrototype);
        return Object.getOwnPropertyDescriptor(error, key);
      },
    });

    try {
      const result = redactValue(input);
      if (typeof result === "string") throw new Error("Expected a protected Error");
      const inheritedKeys: PropertyKey[] = [];
      for (const key in result) inheritedKeys.push(key);
      expect(Reflect.get(result, "leak")).toBeUndefined();
      expect(Object.getPrototypeOf(result)).toBeNull();
      expect(ownKeysCalls).toBe(0);
      expect(inheritedKeys).not.toContain("leak");
    } finally {
      Object.setPrototypeOf(Error.prototype, originalPrototype);
    }
  });

  test("does not inherit coercion hooks installed during array projection", () => {
    const coercionDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.toPrimitive);
    const target = ["jane@example.com"];
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "length") {
          Object.defineProperty(Array.prototype, Symbol.toPrimitive, {
            configurable: true,
            value: () => value[0],
          });
        }
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      expect(String(result)).toBe("[REDACTED]");
    } finally {
      if (coercionDescriptor === undefined) {
        Reflect.deleteProperty(Array.prototype, Symbol.toPrimitive);
      } else {
        Object.defineProperty(Array.prototype, Symbol.toPrimitive, coercionDescriptor);
      }
    }
  });

  test("does not inherit coercion hooks installed during Error projection", () => {
    const coercionDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, Symbol.toPrimitive);
    const target = new Error("jane@example.com");
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "message") {
          Object.defineProperty(Error.prototype, Symbol.toPrimitive, {
            configurable: true,
            value: () => value.message,
          });
        }
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      expect(String(result)).toBe("Error: [REDACTED]");
    } finally {
      if (coercionDescriptor === undefined) {
        Reflect.deleteProperty(Error.prototype, Symbol.toPrimitive);
      } else {
        Object.defineProperty(Error.prototype, Symbol.toPrimitive, coercionDescriptor);
      }
    }
  });

  test("shadows Object methods changed during Error projection", () => {
    const localeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "toLocaleString");
    if (localeDescriptor === undefined) throw new Error("Object locale descriptor is missing");
    const target = new Error("jane@example.com");
    const input = new Proxy(target, {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "message") {
          Object.defineProperty(Object.prototype, "toLocaleString", {
            ...localeDescriptor,
            value: (): string => value.message,
          });
        }
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      if (!(result instanceof Error)) throw new Error("Expected a protected Error");
      expect(result.toLocaleString()).toBe("Error: [REDACTED]");
      expect(Object.hasOwn(result, "toLocaleString")).toBeTrue();
    } finally {
      Object.defineProperty(Object.prototype, "toLocaleString", localeDescriptor);
    }
  });

  test("shadows protocol hooks changed during Error projection", () => {
    const hasInstanceDescriptor = Object.getOwnPropertyDescriptor(
      Error.prototype,
      Symbol.hasInstance,
    );
    const asyncDisposeDescriptor = Object.getOwnPropertyDescriptor(
      Error.prototype,
      Symbol.asyncDispose,
    );
    const disposeDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, Symbol.dispose);
    const input = new Proxy(new Error("jane@example.com"), {
      getOwnPropertyDescriptor: (value, key) => {
        if (key === "message") {
          Object.defineProperties(Error.prototype, {
            [Symbol.asyncDispose]: { configurable: true, value: (): string => value.message },
            [Symbol.dispose]: { configurable: true, value: (): string => value.message },
            [Symbol.hasInstance]: { configurable: true, value: (): boolean => true },
          });
        }
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
    });

    try {
      const result = redactValue(input);
      if (!(result instanceof Error)) throw new Error("Expected a protected Error");
      expect(Reflect.get(result, Symbol.dispose)).toBeUndefined();
      expect(Reflect.get(result, Symbol.asyncDispose)).toBeUndefined();
      expect(Reflect.get(result, Symbol.hasInstance)).toBeUndefined();
    } finally {
      if (asyncDisposeDescriptor === undefined) {
        Reflect.deleteProperty(Error.prototype, Symbol.asyncDispose);
      } else {
        Object.defineProperty(Error.prototype, Symbol.asyncDispose, asyncDisposeDescriptor);
      }
      if (disposeDescriptor === undefined) Reflect.deleteProperty(Error.prototype, Symbol.dispose);
      else Object.defineProperty(Error.prototype, Symbol.dispose, disposeDescriptor);
      if (hasInstanceDescriptor === undefined) {
        Reflect.deleteProperty(Error.prototype, Symbol.hasInstance);
      } else {
        Object.defineProperty(Error.prototype, Symbol.hasInstance, hasInstanceDescriptor);
      }
    }
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

    requireObjectProjection(result);
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(result.email).toBe("[REDACTED]");
    expect(result.self).toBe(result);
    expect(Reflect.has(result, "toJSON")).toBe(false);
    expect(Reflect.ownKeys(result)).toEqual(["email", "self"]);
  });

  test("protects non-callable toJSON data properties", () => {
    const result = redactValue({ toJSON: "jane@example.com" });

    requireObjectProjection(result);
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
    requireObjectProjection(result);
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

    requireObjectProjection(result);
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

    if (typeof result === "string") throw new Error("Expected a protected Error");
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

    if (typeof result === "string") throw new Error("Expected a protected Error");
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

  test("reuses cached structured replacements", () => {
    let replacements = 0;
    const masker = createPiiMasker({
      mode: "redact",
      replacement: () => {
        replacements += 1;
        return "[REDACTED]";
      },
    });

    expect(masker.value({ email: "jane@example.com" })).toEqual({ email: "[REDACTED]" });
    expect(masker.value({ email: "jane@example.com" })).toEqual({ email: "[REDACTED]" });
    expect(replacements).toBe(1);
  });

  test("does not trust text cache entries seeded during structured traversal", () => {
    const execDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, "exec");
    if (execDescriptor === undefined) throw new Error("RegExp exec descriptor is missing");
    const masker = createPiiMasker({ mode: "redact" });
    const email = "jane@example.com";
    const trigger = new Proxy(Object.create(null) as object, {
      ownKeys: (target) => {
        Object.defineProperty(RegExp.prototype, "exec", {
          ...execDescriptor,
          value: (): null => null,
        });
        expect(masker.text(email)).toBe(email);
        return Reflect.ownKeys(target);
      },
    });

    const result = (() => {
      try {
        return masker.value({ email, trigger });
      } finally {
        Object.defineProperty(RegExp.prototype, "exec", execDescriptor);
      }
    })();

    requireObjectProjection(result);
    expect(result.email).toBe("[REDACTED]");
  });

  test("does not expose structured cache provenance through text arguments", () => {
    const email = "jane@example.com";

    for (const cacheSize of [0, 2]) {
      const masker = createPiiMasker({ cacheSize, mode: "redact" });
      expect(Reflect.apply(masker.text, undefined, [email, []])).toBe("[REDACTED]");
      expect(masker.value({ email })).toEqual({ email: "[REDACTED]" });
    }
  });

  test("counts reentrant cache inserts once", () => {
    let reenter: ((input: string) => string) | undefined;
    let replacements = 0;
    const masker = createPiiMasker({
      cacheSize: 2,
      mode: "redact",
      replacement: ({ text }) => {
        replacements += 1;
        if (reenter !== undefined) {
          const invoke = reenter;
          reenter = undefined;
          invoke(text);
        }
        return "[REDACTED]";
      },
    });
    reenter = masker.text;

    expect(masker.text("a@example.com")).toBe("[REDACTED]");
    expect(masker.text("b@example.com")).toBe("[REDACTED]");
    expect(masker.text("a@example.com")).toBe("[REDACTED]");
    expect(replacements).toBe(3);
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
