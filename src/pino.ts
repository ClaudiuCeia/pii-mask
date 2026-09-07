/**
 * Pino integration for automatic PII masking.
 *
 * Uses Pino's `streamWrite` hook to transform the complete serialized entry
 * immediately before it reaches the destination.
 *
 * @module
 */
import type { LoggerOptions } from "pino";
import { createPiiMasker, type PiiMaskerOptions } from "./index.js";

/** Options accepted by {@link pinoPiiMasking}. Same as {@link PiiMaskerOptions}. */
export type PinoPiiMaskingOptions = PiiMaskerOptions;

/** Non-retryable failure raised when a preceding Pino hook produces invalid JSON output. */
export class PinoOutputError extends Error {
  /** Stable machine-readable failure code. */
  readonly code = "PII_MASK_INVALID_PINO_OUTPUT" as const;
  /** Invalid serialized output cannot succeed when retried unchanged. */
  readonly retryable = false as const;

  constructor() {
    super("Pino produced invalid JSON output");
    this.name = "PinoOutputError";
  }
}

const isJsonWhitespace = (character: string | undefined): boolean =>
  character === " " || character === "\n" || character === "\r" || character === "\t";

const validatePinoJson = (input: string): void => {
  let value: unknown;
  try {
    value = JSON.parse(input);
  } catch {
    throw new PinoOutputError();
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PinoOutputError();
  }
};

const transformJsonStringValues = (input: string, transform: (value: string) => string): string => {
  validatePinoJson(input);
  let result = "";
  let unchangedStart = 0;

  for (let start = 0; start < input.length; start += 1) {
    if (input[start] !== '"') continue;

    let end = start + 1;
    while (end < input.length && input[end] !== '"') {
      if (input[end] === "\\") end += 1;
      end += 1;
    }
    if (end >= input.length) throw new PinoOutputError();

    let next = end + 1;
    while (isJsonWhitespace(input[next])) next += 1;
    if (input[next] !== ":") {
      const value: unknown = JSON.parse(input.slice(start, end + 1));
      if (typeof value !== "string") throw new PinoOutputError();
      const transformed = transform(value);
      if (transformed !== value) {
        result += input.slice(unchangedStart, start) + JSON.stringify(transformed);
        unchangedStart = end + 1;
      }
    }
    start = end;
  }

  return result + input.slice(unchangedStart);
};

/**
 * Create Pino options that protect the complete serialized log entry.
 *
 * @example
 * ```ts
 * import pino from "pino";
 * import { pinoPiiMasking } from "@claudiu-ceia/pii-mask/pino";
 *
 * const logger = pino(pinoPiiMasking());
 * ```
 */
export const pinoPiiMasking = (
  options: PinoPiiMaskingOptions = {},
): Pick<LoggerOptions, "hooks"> => {
  const masker = createPiiMasker(options);

  return {
    hooks: {
      streamWrite(line) {
        return transformJsonStringValues(line, masker.text);
      },
    },
  };
};
