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

const OBJECT_KEY_OR_END = 0;
const OBJECT_KEY = 1;
const OBJECT_COLON = 2;
const OBJECT_VALUE = 3;
const OBJECT_COMMA_OR_END = 4;
const ARRAY_VALUE_OR_END = 5;
const ARRAY_VALUE = 6;
const ARRAY_COMMA_OR_END = 7;
type JsonState = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

const isDigitCode = (code: number): boolean => code >= 0x30 && code <= 0x39;

const skipJsonWhitespace = (input: string, start: number): number => {
  let index = start;
  for (
    let code = input.charCodeAt(index);
    code === 0x20 || code === 0x0a || code === 0x0d || code === 0x09;
  ) {
    index += 1;
    code = input.charCodeAt(index);
  }
  return index;
};

const stringEnd = (input: string, start: number): number => {
  let index = start + 1;
  while (index < input.length) {
    const code = input.charCodeAt(index);
    if (code === 0x22) return index + 1;
    if (code < 0x20) throw new PinoOutputError();
    if (code !== 0x5c) {
      index += 1;
      continue;
    }

    const escape = input.charCodeAt(index + 1);
    if (escape === 0x75) {
      for (let offset = 2; offset < 6; offset += 1) {
        const hex = input.charCodeAt(index + offset);
        if (!isDigitCode(hex) && (hex < 0x41 || hex > 0x46) && (hex < 0x61 || hex > 0x66)) {
          throw new PinoOutputError();
        }
      }
      index += 6;
      continue;
    }
    if (
      escape !== 0x22 &&
      escape !== 0x5c &&
      escape !== 0x2f &&
      escape !== 0x62 &&
      escape !== 0x66 &&
      escape !== 0x6e &&
      escape !== 0x72 &&
      escape !== 0x74
    ) {
      throw new PinoOutputError();
    }
    index += 2;
  }
  throw new PinoOutputError();
};

const numberEnd = (input: string, start: number): number => {
  let index = start;
  if (input[index] === "-") index += 1;

  if (input[index] === "0") {
    index += 1;
    if (isDigitCode(input.charCodeAt(index))) throw new PinoOutputError();
  } else {
    const firstDigit = input.charCodeAt(index);
    if (firstDigit < 0x31 || firstDigit > 0x39) {
      throw new PinoOutputError();
    }
    while (isDigitCode(input.charCodeAt(index))) index += 1;
  }

  if (input[index] === ".") {
    index += 1;
    if (!isDigitCode(input.charCodeAt(index))) throw new PinoOutputError();
    while (isDigitCode(input.charCodeAt(index))) index += 1;
  }

  if (input[index] === "e" || input[index] === "E") {
    index += 1;
    if (input[index] === "+" || input[index] === "-") index += 1;
    if (!isDigitCode(input.charCodeAt(index))) throw new PinoOutputError();
    while (isDigitCode(input.charCodeAt(index))) index += 1;
  }
  return index;
};

const transformJsonStringValues = (input: string, transform: (value: string) => string): string => {
  let result = "";
  let unchangedStart = 0;
  let index = skipJsonWhitespace(input, 0);
  if (input[index] !== "{") throw new PinoOutputError();
  index += 1;

  const states: JsonState[] = [OBJECT_KEY_OR_END];
  while (states.length > 0) {
    index = skipJsonWhitespace(input, index);
    const stateIndex = states.length - 1;
    const state = states[stateIndex];
    if (state === undefined) throw new PinoOutputError();

    if (state === OBJECT_KEY_OR_END || state === OBJECT_KEY) {
      if (state === OBJECT_KEY_OR_END && input[index] === "}") {
        states.pop();
        index += 1;
        continue;
      }
      if (input[index] !== '"') throw new PinoOutputError();
      index = stringEnd(input, index);
      states[stateIndex] = OBJECT_COLON;
      continue;
    }

    if (state === OBJECT_COLON) {
      if (input[index] !== ":") throw new PinoOutputError();
      states[stateIndex] = OBJECT_VALUE;
      index += 1;
      continue;
    }

    if (state === OBJECT_COMMA_OR_END || state === ARRAY_COMMA_OR_END) {
      const closing = state === OBJECT_COMMA_OR_END ? "}" : "]";
      if (input[index] === closing) {
        states.pop();
        index += 1;
        continue;
      }
      if (input[index] !== ",") throw new PinoOutputError();
      states[stateIndex] = state === OBJECT_COMMA_OR_END ? OBJECT_KEY : ARRAY_VALUE;
      index += 1;
      continue;
    }

    if (state === ARRAY_VALUE_OR_END && input[index] === "]") {
      states.pop();
      index += 1;
      continue;
    }

    states[stateIndex] = state === OBJECT_VALUE ? OBJECT_COMMA_OR_END : ARRAY_COMMA_OR_END;
    const start = index;
    if (input[index] === '"') {
      index = stringEnd(input, index);
      const encoded = input.slice(start + 1, index - 1);
      let value = encoded;
      if (encoded.includes("\\")) {
        const decoded: unknown = JSON.parse(input.slice(start, index));
        if (typeof decoded !== "string") throw new PinoOutputError();
        value = decoded;
      }
      const transformed = transform(value);
      if (transformed !== value) {
        result += input.slice(unchangedStart, start) + JSON.stringify(transformed);
        unchangedStart = index;
      }
    } else if (input[index] === "{") {
      states.push(OBJECT_KEY_OR_END);
      index += 1;
    } else if (input[index] === "[") {
      states.push(ARRAY_VALUE_OR_END);
      index += 1;
    } else if (input.startsWith("true", index)) {
      index += 4;
    } else if (input.startsWith("false", index)) {
      index += 5;
    } else if (input.startsWith("null", index)) {
      index += 4;
    } else {
      index = numberEnd(input, index);
    }
  }

  index = skipJsonWhitespace(input, index);
  if (index !== input.length) throw new PinoOutputError();
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
