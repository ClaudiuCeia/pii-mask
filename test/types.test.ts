import { expect, test } from "bun:test";
import { redactValue, type ProtectedValue } from "../src/index.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;

type Extends<Left, Right> = [Left] extends [Right] ? true : false;
type TenDigits = "1234567890";
type HundredDigits =
  `${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}${TenDigits}`;
type ThousandDigitKey =
  `${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}${HundredDigits}`;

type Projected<Shape> = Readonly<Shape> & {
  readonly [K in Exclude<ObjectPrototypeKey, keyof Shape>]?: unknown;
};

type OpaqueProjected = { readonly [K in PropertyKey]?: unknown } & {
  readonly [K in ObjectPrototypeKey]?: unknown;
};

type ObjectPrototypeKey =
  | "constructor"
  | "hasOwnProperty"
  | "isPrototypeOf"
  | "propertyIsEnumerable"
  | "toLocaleString"
  | "toString"
  | "valueOf";

test("transformed value types widen strings and preserve record structure", () => {
  const input = {
    email: "jane@example.com",
    nested: ["192.168.0.1", 42],
  } as const;
  const result = redactValue(input);

  const resultType: Equal<
    typeof result,
    | string
    | Error
    | Projected<
        Readonly<{
          email?: string;
          nested?: ProtectedValue<typeof input.nested>;
        }>
      >
  > = true;
  expect(resultType).toBeTrue();
  expect<unknown>(result).toEqual({
    email: "[REDACTED]",
    nested: ["[REDACTED]", 42],
  });
});

test("transformed value types conservatively represent errors and opaque objects", () => {
  class Account {
    readonly email = "jane@example.com" as const;

    get domain(): string {
      return this.email.split("@")[1] ?? "";
    }

    label(): string {
      return this.email;
    }
  }

  type ProtectedAccount = ProtectedValue<Account>;
  type ProtectedAccountProjection = Exclude<ProtectedAccount, string | Error>;
  const emailType: Equal<ProtectedAccountProjection["email"], string | undefined> = true;
  const labelIsCallable: Extends<
    NonNullable<ProtectedAccountProjection["label"]>,
    () => string
  > = false;
  expect(emailType).toBeTrue();
  expect(labelIsCallable).toBeFalse();

  const error = redactValue(new TypeError("jane@example.com"));
  const errorBranch: Extends<Error, typeof error> = true;
  const errorStringBranch: Extends<string, typeof error> = true;
  expect(errorBranch).toBeTrue();
  expect(errorStringBranch).toBeTrue();
  if (typeof error === "string") throw new Error("Expected a protected Error");
  expect(error.message).toBe("[REDACTED]");

  const structuralError: Error = {
    name: "Error",
    message: "jane@example.com",
  };
  const structuralResult = redactValue(structuralError);
  const structuralErrorBranch: Extends<Error, typeof structuralResult> = true;
  const structuralStringBranch: Extends<string, typeof structuralResult> = true;
  expect(structuralErrorBranch).toBeTrue();
  expect(structuralStringBranch).toBeTrue();
  expect<unknown>(structuralResult).toEqual({
    name: "Error",
    message: "[REDACTED]",
  });

  class MutableAccount {
    email = "jane@example.com";
    emails: "jane@example.com"[] = ["jane@example.com"];
    groups: "jane@example.com"[][] = [["jane@example.com"]];
  }
  const retained = redactValue(new MutableAccount());
  type RetainedProjection = Exclude<typeof retained, string | Error>;
  const emailsAreGuaranteedArrays: Extends<
    NonNullable<RetainedProjection["emails"]>,
    readonly unknown[]
  > = false;
  const groupsAreGuaranteedArrays: Extends<
    NonNullable<RetainedProjection["groups"]>,
    readonly unknown[]
  > = false;
  expect(emailsAreGuaranteedArrays).toBeFalse();
  expect(groupsAreGuaranteedArrays).toBeFalse();
});

test("transformed value types do not infer runtime identity structurally", () => {
  const boxedResult = redactValue(new String("jane@example.com"));
  const boxedStringBranch: Extends<string, typeof boxedResult> = true;
  const boxedIsObject: Extends<typeof boxedResult, object> = false;
  expect(boxedStringBranch).toBeTrue();
  expect(boxedIsObject).toBeFalse();
  expect<unknown>(boxedResult).toBe("[REDACTED]");

  const proxiedString: InstanceType<StringConstructor> = new Proxy(
    new String("jane@example.com"),
    {},
  );
  const proxiedResult = redactValue(proxiedString);
  const proxiedStringBranch: Extends<string, typeof proxiedResult> = true;
  const proxiedIsObject: Extends<typeof proxiedResult, object> = false;
  expect(proxiedStringBranch).toBeTrue();
  expect(proxiedIsObject).toBeFalse();
  expect<unknown>(proxiedResult).toBe("[REDACTED]");

  const callable = Object.assign(() => "ignored", {
    email: "jane@example.com" as const,
  });
  const callableResult = redactValue(callable);
  const callableType: Equal<typeof callableResult, Projected<{ email?: string }>> = true;
  const toStringIsAbsent: Extends<typeof callableResult.toString, undefined> = false;
  expect(callableType).toBeTrue();
  expect(toStringIsAbsent).toBeFalse();
  expect<unknown>(callableResult).toEqual({ email: "[REDACTED]" });

  const callableError = Object.defineProperties(() => "ignored", {
    message: { value: "jane@example.com" },
    name: { value: "Error" },
  }) as (() => string) & Error;
  const callableErrorResult = redactValue(callableError);
  const callableErrorType: Equal<
    typeof callableErrorResult,
    Projected<{ cause?: unknown; message?: string; name?: string; stack?: string }>
  > = true;
  expect(callableErrorType).toBeTrue();
  expect<unknown>(callableErrorResult).toEqual({});

  class DescribedValue {
    toString(): string {
      return "jane@example.com";
    }
  }
  const describedResult = redactValue(new DescribedValue());
  const describedStringBranch: Extends<string, typeof describedResult> = true;
  if (typeof describedResult === "string") throw new Error("Expected an object projection");
  const describedToStringIsGuaranteed: Extends<typeof describedResult.toString, () => string> =
    false;
  expect(describedStringBranch).toBeTrue();
  expect(describedToStringIsGuaranteed).toBeFalse();
  expect(Object.getPrototypeOf(describedResult)).toBeNull();
});

test("transformed value types omit array subclass members and preserve inherited methods", () => {
  class Labels extends Array<string> {
    label(): string {
      return this.join(",");
    }
  }

  class Accounts extends Array<{ email: "jane@example.com" }> {}

  const labels = redactValue(new Labels("jane@example.com"));
  const labelsArrayBranch: Extends<string[], typeof labels> = true;
  const accounts = redactValue(new Accounts({ email: "jane@example.com" }));
  const accountsArrayBranch: Extends<
    Array<Projected<{ readonly email?: string }>>,
    typeof accounts
  > = true;
  const mapIsGuaranteed: Extends<
    Exclude<typeof accounts, string | Error>["map"],
    typeof Array.prototype.map
  > = false;
  const retained = redactValue({ accounts: new Accounts({ email: "jane@example.com" }) });
  if (typeof retained === "string" || retained instanceof Error) {
    throw new Error("Expected an object projection");
  }
  const retainedMapIsGuaranteed: Extends<
    Exclude<NonNullable<typeof retained.accounts>, string | Error>["map"],
    typeof Array.prototype.map
  > = false;
  expect(labelsArrayBranch).toBeTrue();
  expect(accountsArrayBranch).toBeTrue();
  expect(mapIsGuaranteed).toBeFalse();
  expect(retainedMapIsGuaranteed).toBeFalse();
  expect(labels).toEqual(["[REDACTED]"]);
  expect<unknown>(accounts).toEqual([{ email: "[REDACTED]" }]);
});

test("transformed value types represent structural array impostors", () => {
  const target = { 0: "jane@example.com", length: 1 };
  const input = new Proxy(target, {
    get: (value, key, receiver) => {
      if (Reflect.has(value, key)) return Reflect.get(value, key, receiver);
      const member: unknown = Reflect.get(Array.prototype, key);
      return typeof member === "function" ? member.bind(value) : member;
    },
  }) as unknown as string[];

  expect(input.map((value) => value)).toEqual(["jane@example.com"]);

  const result = redactValue(input);
  type ObjectResult = Exclude<typeof result, string | Error>;
  const mapIsGuaranteed: Extends<ObjectResult["map"], typeof Array.prototype.map> = false;
  const toStringIsGuaranteed: Extends<typeof result.toString, () => string> = false;
  expect(mapIsGuaranteed).toBeFalse();
  expect(toStringIsGuaranteed).toBeFalse();
  if (typeof result === "string" || result instanceof Error) {
    throw new Error("Expected an object projection");
  }
  expect(Reflect.get(result, "map")).toBeUndefined();
  expect(Reflect.get(result, "toString")).toBeUndefined();
  expect<unknown>(result).toEqual({ 0: "[REDACTED]", length: 1 });
});

test("transformed value types include primitive outputs for broad objects", () => {
  const input: object = new String("jane@example.com");
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const resultIsObject: Extends<typeof result, object> = false;

  expect(stringBranch).toBeTrue();
  expect(resultIsObject).toBeFalse();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed value types include strings concealed by narrow object types", () => {
  const input: { foo: string } = Object.assign(new String("jane@example.com"), { foo: "safe" });
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const resultIsObject: Extends<typeof result, object> = false;

  expect(stringBranch).toBeTrue();
  expect(resultIsObject).toBeFalse();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed value types include primitive outputs for boxed-string supertypes", () => {
  const input: { readonly length: number } = new String("jane@example.com");
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const resultIsObject: Extends<typeof result, object> = false;

  expect(stringBranch).toBeTrue();
  expect(resultIsObject).toBeFalse();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed value types include primitive outputs for boxed-string candidates", () => {
  const source = "jane@example.com";
  const input = Object.create(null) as { readonly [key: number]: string; readonly length: 16 };
  Object.defineProperty(input, "length", { value: source.length });
  for (let index = 0; index < source.length; index += 1) {
    Object.defineProperty(input, index, {
      configurable: false,
      enumerable: true,
      value: source[index],
      writable: false,
    });
  }
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const resultIsObject: Extends<typeof result, object> = false;

  expect(stringBranch).toBeTrue();
  expect(resultIsObject).toBeFalse();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed precise array types include special outputs", () => {
  const input: string[] = Object.assign(new String("jane@example.com"), [] as string[]);
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const errorBranch: Extends<Error, typeof result> = true;
  const resultIsObject: Extends<typeof result, object> = false;

  expect(stringBranch).toBeTrue();
  expect(errorBranch).toBeTrue();
  expect(resultIsObject).toBeFalse();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed tuple types include special outputs", () => {
  const input: readonly [] = Object.assign(new String("jane@example.com"), [] as const);
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;
  const errorBranch: Extends<Error, typeof result> = true;

  expect(stringBranch).toBeTrue();
  expect(errorBranch).toBeTrue();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed broad array types include Error outputs", () => {
  const input: unknown[] = Object.assign(new Error("jane@example.com"), [] as unknown[]);
  const result = redactValue(input);
  const errorBranch: Extends<Error, typeof result> = true;

  expect(errorBranch).toBeTrue();
  expect(result).toBeInstanceOf(Error);
});

test("transformed value types include Error outputs for diagnostic supertypes", () => {
  const input = Object.create(null) as { message: string };
  Object.defineProperty(input, "message", { value: "jane@example.com", writable: true });
  const result = redactValue(input);
  const errorBranch: Extends<Error, typeof result> = true;

  expect(errorBranch).toBeTrue();
  if (typeof result === "string") throw new Error("Expected a protected Error");
  expect(result.message).toBe("[REDACTED]");
});

test("transformed value types include Error outputs for extended diagnostic shapes", () => {
  const input = Object.create(null) as { message: string; requestId: string };
  Object.defineProperties(input, {
    message: { value: "jane@example.com", writable: true },
    requestId: { enumerable: true, value: "request-1", writable: true },
  });
  const result = redactValue(input);
  const errorBranch: Extends<Error, typeof result> = true;

  expect(errorBranch).toBeTrue();
  if (typeof result === "string") throw new Error("Expected a protected Error");
  expect(result.message).toBe("[REDACTED]");
});

test("transformed value types include strings for finite boxed-string candidates", () => {
  const source = "jane@example.com";
  const input = Object.create(null) as { readonly 0: string; readonly length: 16 };
  Object.defineProperty(input, "length", { value: source.length });
  for (let index = 0; index < source.length; index += 1) {
    Object.defineProperty(input, index, {
      configurable: false,
      enumerable: true,
      value: source[index],
      writable: false,
    });
  }
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;

  expect(stringBranch).toBeTrue();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed value types include strings for Error-typed boxed candidates", () => {
  const input: Error = Object.assign(new String("jane@example.com"), {
    message: "diagnostic",
    name: "Error",
  });
  const result = redactValue(input);
  const stringBranch: Extends<string, typeof result> = true;

  expect(stringBranch).toBeTrue();
  expect<unknown>(result).toBe("[REDACTED]");
});

test("transformed value types allow concealed Object-named data properties", () => {
  const input: object = { toString: "jane@example.com" };
  const result = redactValue(input);
  if (typeof result === "string" || result instanceof Error) {
    throw new Error("Expected an object projection");
  }
  const toStringCanBePresent: Extends<string, typeof result.toString> = true;
  const toStringIsAbsent: Extends<typeof result.toString, undefined> = false;

  expect(toStringCanBePresent).toBeTrue();
  expect(toStringIsAbsent).toBeFalse();
  expect(result.toString).toBe("[REDACTED]");
});

test("transformed value types allow prototype-named fields concealed by narrow shapes", () => {
  const source = { foo: "safe", toString: "jane@example.com" };
  const input: { foo: string } = source;
  const result = redactValue(input);
  if (typeof result === "string" || result instanceof Error) {
    throw new Error("Expected an object projection");
  }
  const toStringIsAbsent: Extends<typeof result.toString, undefined> = false;

  expect(toStringIsAbsent).toBeFalse();
  expect(result.toString).toBe("[REDACTED]");
});

test("transformed value types retain projected callable Object-named fields", () => {
  const input = {
    toString: Object.assign(() => "ignored", { email: "jane@example.com" as const }),
  };
  const result = redactValue(input);
  const toStringIsAbsent: Extends<typeof result.toString, undefined> = false;

  expect(toStringIsAbsent).toBeFalse();
  expect<unknown>(result.toString).toEqual({ email: "[REDACTED]" });
});

test("transformed value types retain projected callable data fields", () => {
  const input = {
    callback: Object.assign(() => "ignored", { email: "jane@example.com" as const }),
  };
  const result = redactValue(input);
  if (typeof result === "string" || result instanceof Error) {
    throw new Error("Expected an object projection");
  }
  const callbackIsAbsent: Extends<typeof result.callback, undefined> = false;

  expect(callbackIsAbsent).toBeFalse();
  expect<unknown>(result.callback).toEqual({ email: "[REDACTED]" });
});

test("transformed value types preserve primitives accepted by non-nullish top types", () => {
  const input: {} = 42;
  // oxlint-disable-next-line typescript/no-wrapper-object-types -- Verify callers typed with Object.
  const objectInput: Object = 42;
  const result = redactValue(input);
  const objectResult = redactValue(objectInput);
  const numberBranch: Extends<number, typeof result> = true;
  const objectNumberBranch: Extends<number, typeof objectResult> = true;

  expect(numberBranch).toBeTrue();
  expect(objectNumberBranch).toBeTrue();
  expect(result).toBe(42);
  expect(objectResult).toBe(42);
});

test("transformed value types preserve variadic tuple heads", () => {
  const input: readonly ["jane@example.com", ...number[]] = ["jane@example.com", 1, 2];
  const result = redactValue(input);
  const tupleBranch: Extends<readonly [string, ...number[]], typeof result> = true;

  expect(tupleBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]", 1, 2]);
});

test("transformed value types preserve variadic tuple tails", () => {
  const input: readonly [...number[], "jane@example.com"] = [1, 2, "jane@example.com"];
  const result = redactValue(input);
  const tupleBranch: Extends<readonly [...number[], string], typeof result> = true;

  expect(tupleBranch).toBeTrue();
  expect(result).toEqual([1, 2, "[REDACTED]"]);
});

test("transformed value types omit augmented tuple properties", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    tag: "pii" as const,
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  expect(Reflect.has(result, "tag")).toBeFalse();
});

test("transformed value types treat overridden array members as augmentations", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    at: "serializer@example.com" as const,
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  expect(typeof Reflect.get(result, "at")).toBe("function");
});

test("transformed value types do not claim hidden numeric tuple augmentation values", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    [7]: { secret: "jane@example.com" as const },
  });
  const result = redactValue(input);
  const hiddenValueType: Equal<Exclude<typeof result, string | Error>[7], unknown> = true;

  expect(hiddenValueType).toBeTrue();
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  expect<unknown>(result[7]).toEqual({ secret: "[REDACTED]" });
});

test("transformed value types omit non-index numeric tuple properties", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    "-1": { secret: "jane@example.com" },
    "01": { secret: "jane@example.com" },
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  expect(Reflect.has(result, "-1")).toBeFalse();
  expect(Reflect.has(result, "01")).toBeFalse();
});

test("transformed value types omit integers outside the array-index range", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    "4294967295": { secret: "jane@example.com" },
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  expect(Reflect.has(result, "4294967295")).toBeFalse();
});

test("transformed value types bound numeric tuple augmentation analysis", () => {
  const augmentation = {} as Record<ThousandDigitKey, { secret: "jane@example.com" }>;
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], augmentation);
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve tuple indices with iterator overrides", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    [Symbol.iterator]: () => [][Symbol.iterator](),
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve optional tuple positions", () => {
  const input: readonly ["jane@example.com"?] = ["jane@example.com"];
  const result = redactValue(input);
  const tupleBranch: Extends<readonly [string?], typeof result> = true;

  expect(tupleBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve optional variadic tuple heads", () => {
  const input: readonly ["jane@example.com"?, ...number[]] = ["jane@example.com", 1, 2];
  const result = redactValue(input);
  const tupleBranch: Extends<readonly [string?, ...number[]], typeof result> = true;

  expect(tupleBranch).toBeTrue();
  expect(result).toEqual(["[REDACTED]", 1, 2]);
});

test("transformed value types support long fixed tuples", () => {
  const input = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    48,
    "jane@example.com",
  ] as const;
  const result = redactValue(input);
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  const last: string | undefined = result[49];

  expect(last).toBe("[REDACTED]");
  expect(result).toHaveLength(50);
});

test("transformed value types support long variadic tuple prefixes", () => {
  const prefix = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55,
  ] as const;
  const input: readonly [...typeof prefix, ...string[]] = [...prefix, "jane@example.com"];
  const result = redactValue(input);
  if (!Array.isArray(result)) throw new Error("Expected a protected array");
  const lastPrefix: 55 | undefined = result[55];
  const tail: unknown = result[56];

  expect(lastPrefix).toBe(55);
  expect(tail).toBe("[REDACTED]");
});

test("transformed value types project broad function interfaces", () => {
  const broad: Function = () => "jane@example.com";
  const callable: CallableFunction = () => "jane@example.com";
  const newable: NewableFunction = class Account {};
  const broadResult = redactValue(broad);
  const callableResult = redactValue(callable);
  const newableResult = redactValue(newable);
  const broadType: Equal<typeof broadResult, string | Error | OpaqueProjected> = true;
  const callableType: Equal<typeof callableResult, string | Error | OpaqueProjected> = true;
  const newableType: Equal<typeof newableResult, string | Error | OpaqueProjected> = true;

  expect(broadType).toBeTrue();
  expect(callableType).toBeTrue();
  expect(newableType).toBeTrue();
  if (typeof broadResult === "string" || broadResult instanceof Error) {
    throw new Error("Expected an object projection");
  }
  if (typeof callableResult === "string" || callableResult instanceof Error) {
    throw new Error("Expected an object projection");
  }
  if (typeof newableResult === "string" || newableResult instanceof Error) {
    throw new Error("Expected an object projection");
  }
  expect(Object.getPrototypeOf(broadResult)).toBeNull();
  expect(Object.getPrototypeOf(callableResult)).toBeNull();
  expect(Object.getPrototypeOf(newableResult)).toBeNull();

  const structuralFunction = Object.defineProperties(
    {},
    {
      apply: { get: () => Function.prototype.apply },
      bind: { get: () => Function.prototype.bind },
      call: { get: () => Function.prototype.call },
    },
  ) as Function;
  const structuralResult = redactValue(structuralFunction);
  const structuralType: Equal<typeof structuralResult, string | Error | OpaqueProjected> = true;
  expect(structuralType).toBeTrue();
  if (typeof structuralResult === "string" || structuralResult instanceof Error) {
    throw new Error("Expected an object projection");
  }
  expect(Reflect.has(structuralResult, "apply")).toBeFalse();

  const boxedFunction: Function = Object.assign(new String("jane@example.com"), {
    [Symbol.hasInstance]: Function.prototype[Symbol.hasInstance],
    [Symbol.metadata]: null,
    apply: Function.prototype.apply,
    arguments: null,
    bind: Function.prototype.bind,
    call: Function.prototype.call,
    caller: Function.prototype,
    name: "String",
    prototype: {},
  });
  const boxedResult = redactValue(boxedFunction);
  const boxedStringBranch: Extends<string, typeof boxedResult> = true;
  const boxedErrorBranch: Extends<Error, typeof boxedResult> = true;
  expect(boxedStringBranch).toBeTrue();
  expect(boxedErrorBranch).toBeTrue();
  expect<unknown>(boxedResult).toBe("[REDACTED]");

  const augmentedBoxedFunction: Function & typeof String.prototype & { readonly tag: "boxed" } =
    Object.assign(new String("jane@example.com"), {
      [Symbol.hasInstance]: Function.prototype[Symbol.hasInstance],
      [Symbol.metadata]: null,
      apply: Function.prototype.apply,
      arguments: null,
      bind: Function.prototype.bind,
      call: Function.prototype.call,
      caller: Function.prototype,
      name: "String",
      prototype: {},
      tag: "boxed" as const,
    });
  const augmentedBoxedResult = redactValue(augmentedBoxedFunction);
  const augmentedBoxedType: Equal<typeof augmentedBoxedResult, string | Error | OpaqueProjected> =
    true;
  expect(augmentedBoxedType).toBeTrue();
  expect<unknown>(augmentedBoxedResult).toBe("[REDACTED]");

  interface BrandedFunction extends Function {
    readonly tag: "error";
  }
  const brandedError: BrandedFunction & Error = Object.assign(new Error("jane@example.com"), {
    [Symbol.hasInstance]: Function.prototype[Symbol.hasInstance],
    [Symbol.metadata]: null,
    apply: Function.prototype.apply,
    arguments: null,
    bind: Function.prototype.bind,
    call: Function.prototype.call,
    caller: Function.prototype,
    length: 0,
    prototype: {},
    tag: "error" as const,
  });
  const brandedErrorResult = redactValue(brandedError);
  const brandedErrorType: Equal<typeof brandedErrorResult, string | Error | OpaqueProjected> = true;
  expect(brandedErrorType).toBeTrue();
  if (!(brandedErrorResult instanceof Error)) throw new Error("Expected a protected Error");
  expect(brandedErrorResult.message).toBe("[REDACTED]");
});

test("transformed value types project construct-only functions", () => {
  class Account {
    readonly email = "jane@example.com";
  }

  const result = redactValue(Account);
  const resultType: Equal<
    typeof result,
    Projected<{ prototype?: string | Error | Projected<{ readonly email?: string }> }>
  > = true;

  expect(resultType).toBeTrue();
  expect(Object.getPrototypeOf(result)).toBeNull();
  expect<unknown>(result).toEqual({});

  class ShadowedConstructor {
    static readonly apply = "jane@example.com";
    readonly email = "jane@example.com";
  }
  const shadowedResult = redactValue(ShadowedConstructor);
  const shadowedType: Equal<
    typeof shadowedResult,
    Projected<{
      apply?: string;
      prototype?: string | Error | Projected<{ readonly email?: string }>;
    }>
  > = true;
  expect(shadowedType).toBeTrue();
  expect<unknown>(shadowedResult).toEqual({ apply: "[REDACTED]" });
});
