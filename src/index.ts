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
  : T extends readonly unknown[]
    ? T extends unknown[]
      ? ProtectedArrayItems<T>
      : Readonly<ProtectedArrayItems<T>>
    : T extends object
      ? {
          [
            K in keyof T as T[K] extends (...arguments_: never[]) => unknown ? never : K
          ]?: ProtectedValue<T[K]>;
        }
      : T;

type ProtectedArrayItems<T extends readonly unknown[]> =
  Exclude<keyof T, keyof unknown[] | CanonicalArrayIndex<keyof T>> extends never
    ? Array<T[number]>[typeof Symbol.iterator] extends T[typeof Symbol.iterator]
      ? number extends T["length"]
        ? T extends readonly [infer Head, ...infer Tail]
          ? [ProtectedValue<Head>, ...ProtectedArrayItems<Tail>]
          : T extends readonly [...infer Initial, infer Last]
            ? [...ProtectedArrayItems<Initial>, ProtectedValue<Last>]
            : "0" extends keyof T
              ? T extends readonly [(infer Head)?, ...infer Tail]
                ? [ProtectedValue<Head>?, ...ProtectedArrayItems<Tail>]
                : Array<ProtectedValue<T[number]>>
              : Array<ProtectedValue<T[number]>>
        : { [K in keyof T]: ProtectedValue<T[K]> }
      : Array<ProtectedValue<T[number]>>
    : Array<ProtectedValue<T[number]>>;

type CanonicalArrayIndex<Key> = Key extends string
  ? Key extends `${bigint}`
    ? Key extends `-${string}`
      ? never
      : Key
    : never
  : never;

const detector = Duckling(PIIParsers);

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
    const unboxed: unknown = Reflect.apply(String.prototype.valueOf, value, []);
    return typeof unboxed === "string" ? unboxed : undefined;
  } catch {
    return undefined;
  }
};

const transformError = (
  error: Error,
  transform: (input: string) => string,
  seen: WeakMap<object, unknown>,
): Error => {
  const messageDescriptor = Object.getOwnPropertyDescriptor(error, "message");
  const message =
    messageDescriptor && "value" in messageDescriptor && typeof messageDescriptor.value === "string"
      ? messageDescriptor.value
      : "";
  const transformed = new Error(transform(message));
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

  if (input instanceof Error) return transformError(input, transform, seen);

  if (Array.isArray(input)) {
    const result: unknown[] = [];
    seen.set(input, result);
    for (let index = 0; index < input.length; index += 1) {
      result.push(transformValue(input[index], transform, seen));
    }
    return result;
  }

  const prototype = Object.getPrototypeOf(input);
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

  const result = Object.create(
    prototype === Object.prototype || prototype === null ? prototype : null,
  ) as Record<PropertyKey, unknown>;
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
