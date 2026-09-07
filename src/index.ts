/**
 * Deterministic PII masking and redaction for TypeScript.
 *
 * Uses {@link findPii} to locate sensitive spans via ts-duckling, then
 * replaces them with masked (`***`) or redacted (`[REDACTED]`) values.
 * Structured-value traversal copies data without retaining unsafe prototypes
 * or serialization hooks and without mutating the input.
 *
 * @module
 */
import { Duckling, PIIParsers, type PIIEntity } from "@claudiu-ceia/ts-duckling";

/** A PII entity kind recognized by ts-duckling's built-in PII parsers. */
export type PIIKind = PIIEntity["kind"];

/** Base options for selecting which PII entity kinds to transform. */
export interface PIISelectionOptions {
  /** Restrict transformation to these entity kinds. All PII kinds are used by default. */
  kinds?: readonly PIIKind[];
}

/** Options for masking PII with `*` characters while preserving edges. */
export interface MaskOptions extends PIISelectionOptions {
  /** Token repeated over masked characters. Defaults to `"*"`. */
  mask?: string;
  /** Number of characters to preserve at the start of every match. */
  keepStart?: number;
  /** Number of characters to preserve at the end of every match. */
  keepEnd?: number;
}

/** Options for redacting PII with a static or entity-aware replacement. */
export interface RedactOptions extends PIISelectionOptions {
  /** Static replacement or a replacement function. Defaults to `"[REDACTED]"`. */
  replacement?: string | ((entity: PIIEntity) => string);
}

/** Options for the LRU cache on {@link createPiiMasker}. */
export interface PiiMaskerCacheOptions {
  /**
   * Bound for the LRU cache of already-transformed strings. Each entry retains
   * the original input string and its transformed result. Set to `0` to
   * disable. Defaults to `1024`.
   */
  cacheSize?: number;
}

/** Configuration for {@link createPiiMasker}. Defaults to mask mode with caching enabled. */
export type PiiMaskerOptions =
  | ({ mode?: "mask" } & MaskOptions & PiiMaskerCacheOptions)
  | ({ mode: "redact" } & RedactOptions & PiiMaskerCacheOptions);

/** Reusable protector created by {@link createPiiMasker}. */
export interface PiiMasker {
  /** Protect PII in one string. */
  text(input: string): string;
  /** Protect strings in structured data without mutating the input. */
  value<T>(input: T): ProtectedValue<T>;
}

/** Result type for a value copied through a PII transformation. */
export type ProtectedValue<T> = T extends string
  ? string
  : T extends Function
    ? ProtectedFunction<T>
    : T extends readonly unknown[]
      ? ProtectedArray<T>
      : T extends object
        ? ProtectedObject<T>
        : T;

type ProtectedFunction<T extends Function> = Function extends T
  ? ProtectedObject<object>
  : CallableFunction extends T
    ? ProtectedObject<object>
    : NewableFunction extends T
      ? ProtectedObject<object>
      : ProtectedObject<T>;

type ProtectedObject<T extends object> = {
  readonly [
    K in keyof T as T[K] extends (...arguments_: never[]) => unknown ? never : K
  ]?: ProtectedObjectValue<T[K]>;
} & { readonly [K in Exclude<ObjectPrototypeKey, RetainedObjectPrototypeKey<T>>]?: never };

type ProtectedObjectValue<T> = T extends readonly unknown[]
  ? Readonly<ProtectedArray<T>>
  : ProtectedValue<T>;

type RetainedObjectPrototypeKey<T extends object> = {
  [K in Extract<ObjectPrototypeKey, keyof T>]: T[K] extends (...arguments_: never[]) => unknown
    ? never
    : K;
}[Extract<ObjectPrototypeKey, keyof T>];

type ObjectPrototypeKey =
  | "constructor"
  | "hasOwnProperty"
  | "isPrototypeOf"
  | "propertyIsEnumerable"
  | "toLocaleString"
  | "toString"
  | "valueOf";

type ProtectedArray<T extends readonly unknown[]> =
  ArrayAugmentation<T> extends never
    ? { [K in keyof T]: ProtectedValue<T[K]> }
    : T extends unknown[]
      ? Array<ProtectedValue<T[number]>>
      : ReadonlyArray<ProtectedValue<T[number]>>;

type ArrayAugmentation<T extends readonly unknown[]> =
  | Exclude<keyof T, keyof ArrayShape<T> | CanonicalArrayIndex<keyof T>>
  | OverriddenArrayMember<T>;

type ArrayShape<T extends readonly unknown[]> = T extends unknown[]
  ? Array<T[number]>
  : ReadonlyArray<T[number]>;

type OverriddenArrayMember<
  T extends readonly unknown[],
  Shape extends ArrayShape<T> = ArrayShape<T>,
> = {
  [K in Exclude<keyof Shape, number | "length">]: K extends keyof T
    ? Shape[K] extends T[K]
      ? never
      : K
    : never;
}[Exclude<keyof Shape, number | "length">];

type Digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9";

type DigitsOf<Value extends string, Result extends Digit[] = []> = Value extends ""
  ? Result
  : Value extends `${infer Head extends Digit}${infer Tail}`
    ? DigitsOf<Tail, [...Result, Head]>
    : never;

type DigitRank = {
  "0": [];
  "1": [unknown];
  "2": [unknown, unknown];
  "3": [unknown, unknown, unknown];
  "4": [unknown, unknown, unknown, unknown];
  "5": [unknown, unknown, unknown, unknown, unknown];
  "6": [unknown, unknown, unknown, unknown, unknown, unknown];
  "7": [unknown, unknown, unknown, unknown, unknown, unknown, unknown];
  "8": [unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown];
  "9": [unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown];
};

type CompareDigit<Left extends Digit, Right extends Digit> = DigitRank[Left] extends [
  ...DigitRank[Right],
  ...infer Extra,
]
  ? Extra extends []
    ? "equal"
    : "greater"
  : "less";

type IsAtMost<
  Value extends string,
  Maximum extends string,
> = Value extends `${infer ValueHead extends Digit}${infer ValueTail}`
  ? Maximum extends `${infer MaximumHead extends Digit}${infer MaximumTail}`
    ? CompareDigit<ValueHead, MaximumHead> extends infer Comparison
      ? Comparison extends "equal"
        ? IsAtMost<ValueTail, MaximumTail>
        : Comparison extends "less"
          ? true
          : false
      : never
    : false
  : true;

type IsArrayIndex<Value extends string> = DigitsOf<Value>["length"] extends
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9
  ? true
  : DigitsOf<Value>["length"] extends 10
    ? IsAtMost<Value, "4294967294">
    : false;

type CanonicalArrayIndex<Key> = Key extends string
  ? Key extends `${bigint}`
    ? Key extends `-${string}`
      ? never
      : IsArrayIndex<Key> extends true
        ? Key
        : never
    : never
  : never;

const detector = Duckling(PIIParsers);
const errorIsError = Error.isError;
const stringValueOf = String.prototype.valueOf;

/** Find PII spans in free-form text using ts-duckling. */
export const findPii = (input: string): PIIEntity[] => detector.extract(input);

const selectedEntities = (input: string, kinds?: readonly PIIKind[]): PIIEntity[] => {
  const entities = findPii(input);
  if (kinds === undefined) return entities;

  const selected = new Set<PIIKind>(kinds);
  return entities.filter((entity) => selected.has(entity.kind));
};

const replaceEntities = (
  input: string,
  entities: readonly PIIEntity[],
  replacement: (entity: PIIEntity) => string,
): string => {
  if (entities.length === 0) return input;

  let result = input;
  let boundary = input.length;
  const ordered = [...entities].sort(
    (left, right) => right.start - left.start || right.end - left.end,
  );

  for (const entity of ordered) {
    if (entity.end > boundary) continue;
    result = result.slice(0, entity.start) + replacement(entity) + result.slice(entity.end);
    boundary = entity.start;
  }

  return result;
};

const naturalNumber = (name: string, value: number | undefined): number => {
  if (value === undefined) return 0;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
  return value;
};

/** Mask detected PII while optionally preserving leading or trailing characters. */
export const maskText = (input: string, options: MaskOptions = {}): string => {
  const mask = options.mask ?? "*";
  if (mask.length === 0) throw new RangeError("mask must not be empty");

  const keepStart = naturalNumber("keepStart", options.keepStart);
  const keepEnd = naturalNumber("keepEnd", options.keepEnd);
  const entities = selectedEntities(input, options.kinds);

  return replaceEntities(input, entities, (entity) => {
    const length = entity.end - entity.start;
    const visibleStart = Math.min(keepStart, length);
    const visibleEnd = Math.min(keepEnd, length - visibleStart);
    return (
      entity.text.slice(0, visibleStart) +
      mask.repeat(length - visibleStart - visibleEnd) +
      entity.text.slice(length - visibleEnd)
    );
  });
};

/** Replace each detected PII span with a fixed or entity-aware value. */
export const redactText = (input: string, options: RedactOptions = {}): string => {
  const replacement = options.replacement ?? "[REDACTED]";
  const entities = selectedEntities(input, options.kinds);
  return replaceEntities(input, entities, (entity) =>
    typeof replacement === "function" ? replacement(entity) : replacement,
  );
};

const unboxString = (value: object): string | undefined => {
  try {
    const unboxed: unknown = Reflect.apply(stringValueOf, value, []);
    return typeof unboxed === "string" ? unboxed : undefined;
  } catch {
    return undefined;
  }
};

const transformError = (
  error: object,
  transform: (input: string) => string,
  seen: WeakMap<object, unknown>,
): Error => {
  const messageDescriptor = Object.getOwnPropertyDescriptor(error, "message");
  const message =
    messageDescriptor && "value" in messageDescriptor && typeof messageDescriptor.value === "string"
      ? messageDescriptor.value
      : "";
  const transformed = new Error(transform(message));
  Object.defineProperty(transformed, "toJSON", {
    configurable: true,
    writable: true,
    value: undefined,
  });
  seen.set(error, transformed);

  const nameDescriptor = Object.getOwnPropertyDescriptor(error, "name");
  if (nameDescriptor && "value" in nameDescriptor && typeof nameDescriptor.value === "string") {
    transformed.name = transform(nameDescriptor.value);
  }

  const stackDescriptor = Object.getOwnPropertyDescriptor(error, "stack");
  if (stackDescriptor && "value" in stackDescriptor && typeof stackDescriptor.value === "string") {
    transformed.stack = transform(stackDescriptor.value);
  }

  const causeDescriptor = Object.getOwnPropertyDescriptor(error, "cause");
  if (causeDescriptor && "value" in causeDescriptor) {
    Object.defineProperty(transformed, "cause", {
      configurable: true,
      writable: true,
      value: transformValue(causeDescriptor.value, transform, seen),
    });
  }

  for (const key of Reflect.ownKeys(error)) {
    if (key === "name" || key === "message" || key === "stack" || key === "cause") {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      Object.defineProperty(transformed, key, {
        ...descriptor,
        value: transformValue(descriptor.value, transform, seen),
      });
    }
  }

  return transformed;
};

const transformValue = (
  input: unknown,
  transform: (input: string) => string,
  seen: WeakMap<object, unknown>,
): unknown => {
  if (typeof input === "string") return transform(input);
  if ((typeof input !== "object" && typeof input !== "function") || input === null) return input;

  const existing = seen.get(input);
  if (existing !== undefined) return existing;

  if (input instanceof Error || errorIsError(input)) return transformError(input, transform, seen);

  if (Array.isArray(input)) {
    const result: unknown[] = [];
    seen.set(input, result);
    for (let index = 0; index < input.length; index += 1) {
      result.push(transformValue(input[index], transform, seen));
    }
    return result;
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, "length");
  if (
    lengthDescriptor !== undefined &&
    "value" in lengthDescriptor &&
    typeof lengthDescriptor.value === "number" &&
    !lengthDescriptor.configurable &&
    !lengthDescriptor.enumerable &&
    !lengthDescriptor.writable
  ) {
    const boxedString = unboxString(input);
    if (boxedString !== undefined) return transform(boxedString);
  }

  const result = Object.create(null) as Record<PropertyKey, unknown>;
  seen.set(input, result);
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      Object.defineProperty(result, key, {
        ...descriptor,
        value: transformValue(descriptor.value, transform, seen),
      });
    }
  }
  return result;
};

const protectValue = <T>(input: T, transform: (input: string) => string): ProtectedValue<T> =>
  transformValue(input, transform, new WeakMap()) as ProtectedValue<T>;

/** Mask strings nested in structured data. */
export const maskValue = <T>(input: T, options: MaskOptions = {}): ProtectedValue<T> =>
  protectValue(input, (value) => maskText(value, options));

/** Redact strings nested in structured data. */
export const redactValue = <T>(input: T, options: RedactOptions = {}): ProtectedValue<T> =>
  protectValue(input, (value) => redactText(value, options));

const DEFAULT_CACHE_SIZE = 1024;

const withCache = (
  transform: (input: string) => string,
  cacheSize: number,
): ((input: string) => string) => {
  if (cacheSize === 0) return transform;

  const cache = new Map<string, string>();
  return (input) => {
    const hit = cache.get(input);
    if (hit !== undefined) {
      // Refresh recency.
      cache.delete(input);
      cache.set(input, hit);
      return hit;
    }

    const transformed = transform(input);
    if (cache.size >= cacheSize) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(input, transformed);
    return transformed;
  };
};

/** Create a reusable text and structured-value protector. */
export const createPiiMasker = (options: PiiMaskerOptions = {}): PiiMasker => {
  const cacheSize = options.cacheSize ?? DEFAULT_CACHE_SIZE;
  if (!Number.isSafeInteger(cacheSize) || cacheSize < 0) {
    throw new RangeError("cacheSize must be a non-negative safe integer");
  }

  const base =
    options.mode === "redact"
      ? (input: string) => redactText(input, options)
      : (input: string) => maskText(input, options);
  const transform = withCache(base, cacheSize);

  return {
    text: transform,
    value: <T>(input: T): ProtectedValue<T> => protectValue(input, transform),
  };
};
