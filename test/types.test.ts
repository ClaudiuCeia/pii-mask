import { expect, test } from "bun:test";
import { redactValue, type ProtectedValue } from "../src/index.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;

test("transformed value types widen strings and preserve record structure", () => {
  const result = redactValue({
    email: "jane@example.com",
    nested: ["192.168.0.1", 42],
  } as const);

  const resultType: Equal<
    typeof result,
    Readonly<{
      email?: string;
      nested?: readonly [string, 42];
    }>
  > = true;
  expect(resultType).toBeTrue();
  expect(result).toEqual({
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
    { readonly email?: string; readonly domain?: string }
  > = true;
  expect(accountType).toBeTrue();

  const error = redactValue(new TypeError("jane@example.com"));
  const errorType: Equal<
    typeof error,
    { name?: string; message?: string; stack?: string; cause?: unknown }
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
    { name?: string; message?: string; stack?: string; cause?: unknown }
  > = true;
  expect(structuralType).toBeTrue();
  expect(structuralResult).toEqual({
    name: "Error",
    message: "[REDACTED]",
  });
});

test("transformed value types do not infer runtime identity structurally", () => {
  const boxedResult = redactValue(new String("jane@example.com"));
  const boxedIsString: Equal<typeof boxedResult, string> = false;
  expect(boxedIsString).toBeFalse();
  expect(boxedResult).toBe("[REDACTED]");

  const proxiedString: InstanceType<StringConstructor> = new Proxy(
    new String("jane@example.com"),
    {},
  );
  const proxiedResult = redactValue(proxiedString);
  const proxiedIsString: Equal<typeof proxiedResult, string> = false;
  expect(proxiedIsString).toBeFalse();
  expect(Object.getPrototypeOf(proxiedResult)).toBeNull();
  expect(Object.values(proxiedResult).join("")).toBe("jane@example.com");

  const callable = Object.assign(() => "ignored", {
    email: "jane@example.com" as const,
  });
  const callableResult = redactValue(callable);
  const callableType: Equal<typeof callableResult, { email?: string }> = true;
  expect(callableType).toBeTrue();
  expect(callableResult).toEqual({ email: "[REDACTED]" });
});

test("transformed value types omit array subclass members", () => {
  class Labels extends Array<string> {
    label(): string {
      return this.join(",");
    }
  }

  const labels = redactValue(new Labels("jane@example.com"));
  const labelsType: Equal<typeof labels, string[]> = true;
  expect(labelsType).toBeTrue();
  expect(labels).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve variadic tuple heads", () => {
  const input: readonly ["jane@example.com", ...number[]] = ["jane@example.com", 1, 2];
  const result = redactValue(input);
  const resultType: Equal<typeof result, readonly [string, ...number[]]> = true;

  expect(resultType).toBeTrue();
  expect(result).toEqual(["[REDACTED]", 1, 2]);
});

test("transformed value types preserve variadic tuple tails", () => {
  const input: readonly [...number[], "jane@example.com"] = [1, 2, "jane@example.com"];
  const result = redactValue(input);
  const resultType: Equal<typeof result, readonly [...number[], string]> = true;

  expect(resultType).toBeTrue();
  expect(result).toEqual([1, 2, "[REDACTED]"]);
});

test("transformed value types omit augmented tuple properties", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    tag: "pii" as const,
  });
  const result = redactValue(input);
  const resultType: Equal<typeof result, string[]> = true;

  expect(resultType).toBeTrue();
  expect(Reflect.has(result, "tag")).toBeFalse();
});

test("transformed value types omit non-index numeric tuple properties", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    "-1": { secret: "jane@example.com" },
    "01": { secret: "jane@example.com" },
  });
  const result = redactValue(input);
  const resultType: Equal<typeof result, string[]> = true;

  expect(resultType).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
  expect(Reflect.has(result, "-1")).toBeFalse();
  expect(Reflect.has(result, "01")).toBeFalse();
});

test("transformed value types preserve tuple indices with iterator overrides", () => {
  const input = Object.assign(["jane@example.com"] as ["jane@example.com"], {
    [Symbol.iterator]: () => [][Symbol.iterator](),
  });
  const result = redactValue(input);
  const resultType: Equal<typeof result, string[]> = true;

  expect(resultType).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve optional tuple positions", () => {
  const input: readonly ["jane@example.com"?] = ["jane@example.com"];
  const result = redactValue(input);
  const resultType: Equal<typeof result, readonly [string?]> = true;

  expect(resultType).toBeTrue();
  expect(result).toEqual(["[REDACTED]"]);
});

test("transformed value types preserve optional variadic tuple heads", () => {
  const input: readonly ["jane@example.com"?, ...number[]] = ["jane@example.com", 1, 2];
  const result = redactValue(input);
  const resultType: Equal<typeof result, readonly [string?, ...number[]]> = true;

  expect(resultType).toBeTrue();
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
  const last: string = result[49];

  expect(last).toBe("[REDACTED]");
  expect(result).toHaveLength(50);
});

test("transformed value types project construct-only functions", () => {
  class Account {
    readonly email = "jane@example.com";
  }

  const result = redactValue(Account);
  const resultType: Equal<typeof result, { prototype?: { readonly email?: string } }> = true;

  expect(resultType).toBeTrue();
  expect(Object.getPrototypeOf(result)).toBeNull();
  expect(result).toEqual({});
});
