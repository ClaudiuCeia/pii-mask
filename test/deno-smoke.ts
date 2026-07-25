import { findPii, maskText, maskValue, redactText, redactValue } from "../src/index.ts";

Deno.test("findPii detects email and IP", () => {
  const entities = findPii("Contact jane@example.com from 192.168.0.1");
  const kinds = entities.map(({ kind }) => kind);
  if (!kinds.includes("email") || !kinds.includes("ip")) {
    throw new Error(`Expected email and ip, got ${kinds.join(", ")}`);
  }
});

Deno.test("maskText masks PII", () => {
  const result = maskText("Email jane@example.com");
  if (result !== "Email ****************") {
    throw new Error(`Expected masked output, got "${result}"`);
  }
});

Deno.test("redactText replaces PII", () => {
  const result = redactText("Email jane@example.com from 192.168.0.1");
  if (result !== "Email [REDACTED] from [REDACTED]") {
    throw new Error(`Expected redacted output, got "${result}"`);
  }
});

Deno.test("maskValue works on structured data", () => {
  const input = { message: "Email jane@example.com" };
  const result = maskValue(input);
  if (result.message !== "Email ****************") {
    throw new Error(`Expected masked message, got "${result.message}"`);
  }
});

Deno.test("redactValue works on structured data", () => {
  const input = { message: "Email jane@example.com" };
  const result = redactValue(input);
  if (result.message !== "Email [REDACTED]") {
    throw new Error(`Expected redacted message, got "${result.message}"`);
  }
});
