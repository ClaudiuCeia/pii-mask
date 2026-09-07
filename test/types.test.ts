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

test("transformed value types normalize errors and opaque objects", () => {
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
  const errorType: Equal<typeof error, Error> = true;
  expect(errorType).toBeTrue();
  expect(error.message).toBe("[REDACTED]");
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
