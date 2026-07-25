import { Duckling, PIIParsers, type PIIEntity } from "@claudiu-ceia/ts-duckling";

/** A PII entity kind recognized by ts-duckling's built-in PII parsers. */
export type PIIKind = PIIEntity["kind"];

export interface PIISelectionOptions {
  /** Restrict transformation to these entity kinds. All PII kinds are used by default. */
  kinds?: readonly PIIKind[];
}

export interface MaskOptions extends PIISelectionOptions {
  /** Token repeated over masked characters. Defaults to `"*"`. */
  mask?: string;
  /** Number of characters to preserve at the start of every match. */
  keepStart?: number;
  /** Number of characters to preserve at the end of every match. */
  keepEnd?: number;
}

export interface RedactOptions extends PIISelectionOptions {
  /** Static replacement or a replacement function. Defaults to `"[REDACTED]"`. */
  replacement?: string | ((entity: PIIEntity) => string);
}

export interface PiiMaskerCacheOptions {
  /**
   * Bound for the LRU cache of already-transformed strings. Logging workloads
   * repeat the same strings constantly, so caching makes them nearly free.
   * Set to `0` to disable. Defaults to `1024`.
   */
  cacheSize?: number;
}

export type PiiMaskerOptions =
  | ({ mode?: "mask" } & MaskOptions & PiiMaskerCacheOptions)
  | ({ mode: "redact" } & RedactOptions & PiiMaskerCacheOptions);

export interface PiiMasker {
  /** Protect PII in one string. */
  text(input: string): string;
  /** Protect every string in a plain object, array, or Error without mutating it. */
  value<T>(input: T): T;
}

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
  const ordered = entities.toSorted(
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

const isPlainObject = (value: object): boolean => {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const transformError = (
  error: Error,
  transform: (input: string) => string,
  seen: WeakMap<object, unknown>,
): Error => {
  const transformed = new Error(transform(error.message));
  Object.setPrototypeOf(transformed, Object.getPrototypeOf(error));
  transformed.name = error.name;
  if (error.stack !== undefined) transformed.stack = transform(error.stack);
  seen.set(error, transformed);

  if ("cause" in error) {
    Object.defineProperty(transformed, "cause", {
      configurable: true,
      writable: true,
      value: transformValue(error.cause, transform, seen),
    });
  }

  for (const key of Reflect.ownKeys(error)) {
    if (key === "name" || key === "message" || key === "stack" || key === "cause") {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor?.enumerable && "value" in descriptor) {
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
  if (typeof input !== "object" || input === null) return input;

  const existing = seen.get(input);
  if (existing !== undefined) return existing;

  if (input instanceof Error) return transformError(input, transform, seen);

  if (Array.isArray(input)) {
    const result: unknown[] = [];
    seen.set(input, result);
    for (const item of input) result.push(transformValue(item, transform, seen));
    return result;
  }

  if (!isPlainObject(input)) return input;

  const result = Object.create(Object.getPrototypeOf(input)) as Record<PropertyKey, unknown>;
  seen.set(input, result);
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      Object.defineProperty(result, key, {
        ...descriptor,
        value: transformValue(descriptor.value, transform, seen),
      });
    }
  }
  return result;
};

const protectValue = <T>(input: T, transform: (input: string) => string): T =>
  transformValue(input, transform, new WeakMap()) as T;

/** Mask every string nested in a plain object, array, or Error. */
export const maskValue = <T>(input: T, options: MaskOptions = {}): T =>
  protectValue(input, (value) => maskText(value, options));

/** Redact every string nested in a plain object, array, or Error. */
export const redactValue = <T>(input: T, options: RedactOptions = {}): T =>
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
    value: <T>(input: T) => protectValue(input, transform),
  };
};
