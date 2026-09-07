import { expect, test } from "bun:test";
import { redactValue, type ProtectedValue } from "../src/index.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;

type Extends<Left, Right> = [Left] extends [Right] ? true : false;

type Projected<Shape> = Readonly<Shape> & {
  readonly [K in Exclude<ObjectPrototypeKey, keyof Shape>]?: never;
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
    Projected<
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
  const accountType: Equal<
    ProtectedAccount,
    Projected<{ readonly email?: string; readonly domain?: string }>
  > = true;
  expect(accountType).toBeTrue();

  const error = redactValue(new TypeError("jane@example.com"));
  const errorType: Equal<
    typeof error,
    Projected<{ name?: string; message?: string; stack?: string; cause?: unknown }>
  > = true;
  expect(errorType).toBeTrue();
  expect(error.message).toBe("[REDACTED]");

  const structuralError: Error = {
    name: "Error",
    message: "jane@example.com",
  };
  const structuralResult = redactValue(structuralError);
  const structuralType: Equal<
    typeof structuralResult,
    Projected<{ name?: string; message?: string; stack?: string; cause?: unknown }>
  > = true;
  expect(structuralType).toBeTrue();
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
  const emailsAreGuaranteedArrays: Extends<
    NonNullable<typeof retained.emails>,
    readonly unknown[]
  > = false;
  const groupsAreGuaranteedArrays: Extends<
    NonNullable<typeof retained.groups>,
    readonly unknown[]
  > = false;
  expect(emailsAreGuaranteedArrays).toBeFalse();
  expect(groupsAreGuaranteedArrays).toBeFalse();
});

test("transformed value types do not infer runtime identity structurally", () => {
  const boxedResult = redactValue(new String("jane@example.com"));
  const boxedIsString: Equal<typeof boxedResult, string> = false;
  expect(boxedIsString).toBeFalse();
  expect<unknown>(boxedResult).toBe("[REDACTED]");

  const proxiedString: InstanceType<StringConstructor> = new Proxy(
    new String("jane@example.com"),
    {},
  );
  const proxiedResult = redactValue(proxiedString);
  const proxiedIsString: Equal<typeof proxiedResult, string> = false;
  expect(proxiedIsString).toBeFalse();
  expect<unknown>(proxiedResult).toBe("[REDACTED]");

  const callable = Object.assign(() => "ignored", {
    email: "jane@example.com" as const,
  });
  const callableResult = redactValue(callable);
  const callableType: Equal<typeof callableResult, Projected<{ email?: string }>> = true;
  const toStringType: Equal<typeof callableResult.toString, undefined> = true;
  expect(callableType).toBeTrue();
  expect(toStringType).toBeTrue();
  expect<unknown>(callableResult).toEqual({ email: "[REDACTED]" });

  class DescribedValue {
    toString(): string {
      return "jane@example.com";
    }
  }
  const describedResult = redactValue(new DescribedValue());
  const describedToStringType: Equal<typeof describedResult.toString, undefined> = true;
  expect(describedToStringType).toBeTrue();
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
  const mapIsGuaranteed: "map" extends keyof typeof accounts ? true : false = false;
  const retained = redactValue({ accounts: new Accounts({ email: "jane@example.com" }) });
  const retainedMapIsGuaranteed: "map" extends keyof NonNullable<typeof retained.accounts>
    ? true
    : false = false;
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
  const mapIsGuaranteed: "map" extends keyof typeof result ? true : false = false;
  expect(mapIsGuaranteed).toBeFalse();
  expect(Reflect.get(result, "map")).toBeUndefined();
  expect(result).toEqual({ 0: "[REDACTED]", length: 1 });
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
  expect(Reflect.has(result, "tag")).toBeFalse();
});

test("transformed value types treat overridden array members as augmentations", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    at: "serializer@example.com" as const,
  });
  const result = redactValue(input);
  const arrayBranch: Extends<string[], typeof result> = true;

  expect(arrayBranch).toBeTrue();
  expect(typeof Reflect.get(result, "at")).toBe("function");
});

test("transformed value types do not claim hidden numeric tuple augmentation values", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    [7]: { secret: "jane@example.com" as const },
  });
  const result = redactValue(input);
  const hiddenValueType: Equal<(typeof result)[7], unknown> = true;

  expect(hiddenValueType).toBeTrue();
  expect(result[7]).toEqual({ secret: "[REDACTED]" });
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
  expect(Reflect.has(result, "4294967295")).toBeFalse();
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
  const broadType: Equal<typeof broadResult, Projected<object>> = true;
  const callableType: Equal<typeof callableResult, Projected<object>> = true;
  const newableType: Equal<typeof newableResult, Projected<object>> = true;

  expect(broadType).toBeTrue();
  expect(callableType).toBeTrue();
  expect(newableType).toBeTrue();
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
  const structuralType: Equal<typeof structuralResult, Projected<object>> = true;
  expect(structuralType).toBeTrue();
  expect(Reflect.has(structuralResult, "apply")).toBeFalse();
});

test("transformed value types project construct-only functions", () => {
  class Account {
    readonly email = "jane@example.com";
  }

  const result = redactValue(Account);
  const resultType: Equal<
    typeof result,
    Projected<{ prototype?: Projected<{ readonly email?: string }> }>
  > = true;

  expect(resultType).toBeTrue();
  expect(Object.getPrototypeOf(result)).toBeNull();
  expect<unknown>(result).toEqual({});
});
