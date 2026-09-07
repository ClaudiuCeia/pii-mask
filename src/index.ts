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

/**
 * Possible result shapes for a value passed through a PII transformation.
 * Array-shaped types include both array and conservative object projections
 * because TypeScript cannot prove their runtime brand.
 */
export type ProtectedValue<T> = T extends string
  ? string
  : T extends typeof String.prototype
    ? string | ProtectedObject<T>
    : T extends Error
      ? Error | ProtectedObject<T>
      : T extends Function
        ? ProtectedFunction<T>
        : T extends readonly unknown[]
          ? ProtectedArray<T>
          : T extends object
            ? object extends T
              ? string | ProtectedObject<T>
              : ProtectedObject<T>
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
  ? ProtectedRetainedArray<T>
  : ProtectedValue<T>;

type ProtectedRetainedValue<T> = T extends readonly unknown[]
  ? ProtectedRetainedArray<T>
  : ProtectedValue<T>;

type ProtectedRetainedArray<T extends readonly unknown[]> =
  | ProtectedRetainedActualArray<T>
  | ProtectedArrayObject<T>;

type ProtectedRetainedActualArray<T extends readonly unknown[]> =
  ArrayAugmentation<T> extends never
    ? ArraySkeleton<T> extends T
      ? ProtectedRetainedArrayItems<ArraySkeleton<T>>
      : readonly unknown[]
    : ReadonlyArray<ProtectedRetainedValue<T[number]>>;

type ProtectedRetainedArrayItems<T extends readonly unknown[]> = {
  readonly [K in keyof T]: ProtectedRetainedValue<T[K]>;
};

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
  | ProtectedActualArray<T>
  | ProtectedArrayObject<T>;

type ProtectedActualArray<T extends readonly unknown[]> =
  ArrayAugmentation<T> extends never
    ? ArraySkeleton<T> extends T
      ? ProtectedArrayItems<ArraySkeleton<T>>
      : T extends unknown[]
        ? unknown[]
        : readonly unknown[]
    : T extends unknown[]
      ? Array<ProtectedValue<T[number]>>
      : ReadonlyArray<ProtectedValue<T[number]>>;

type ProtectedArrayItems<T extends readonly unknown[]> = {
  [K in keyof T]: ProtectedValue<T[K]>;
};

type ProtectedArrayObject<T extends readonly unknown[]> = {
  readonly [
    K in keyof T as T[K] extends (...arguments_: never[]) => unknown ? never : K
  ]?: K extends number ? unknown : ProtectedObjectValue<T[K]>;
} & { readonly [K in Exclude<ObjectPrototypeKey, RetainedObjectPrototypeKey<T>>]?: never };

type ArraySkeleton<T extends readonly unknown[]> = T extends unknown[] ? [...T] : readonly [...T];

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

type DigitsOf<Value extends string, Result extends Digit[] = []> = Result["length"] extends 10
  ? Value extends ""
    ? Result
    : [...Result, Digit]
  : Value extends ""
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
const NativeError = Error;
const NativeMap = Map;
const NativeWeakMap = WeakMap;
const arrayIsArray = Array.isArray;
const createObject = Object.create;
const defineProperty = Object.defineProperty;
const errorIsError = NativeError.isError;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const mapDelete = NativeMap.prototype.delete;
const mapGet = NativeMap.prototype.get;
const mapIteratorNext = Object.getPrototypeOf(new NativeMap().keys())
  .next as () => IteratorResult<unknown>;
const mapKeys = NativeMap.prototype.keys;
const mapSet = NativeMap.prototype.set;
const numberIsSafeInteger = Number.isSafeInteger;
const ownKeys = Reflect.ownKeys;
const reflectApply = Reflect.apply;
const stringValueOf = String.prototype.valueOf;
const weakMapGet = NativeWeakMap.prototype.get;
const weakMapSet = NativeWeakMap.prototype.set;

const getSeen = (seen: WeakMap<object, unknown>, input: object): unknown =>
  reflectApply(weakMapGet, seen, [input]);

const setSeen = (seen: WeakMap<object, unknown>, input: object, output: unknown): void => {
  reflectApply(weakMapSet, seen, [input, output]);
};

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
    const unboxed: unknown = reflectApply(stringValueOf, value, []);
    return typeof unboxed === "string" ? unboxed : undefined;
  } catch {
    return undefined;
  }
};

type DataDescriptor = PropertyDescriptor & { value: unknown };

const getOwnDataDescriptor = (input: object, key: PropertyKey): DataDescriptor | undefined => {
  const descriptor = getOwnPropertyDescriptor(input, key);
  return descriptor !== undefined && "value" in descriptor
    ? (descriptor as DataDescriptor)
    : undefined;
};

type BoxedStringProbe =
  | { readonly kind: "not-candidate" }
  | { readonly kind: "value"; readonly value: string }
  | { readonly kind: "invalid" };

const probeBoxedString = (input: object): BoxedStringProbe => {
  if (typeof input === "function") return { kind: "not-candidate" };

  const lengthDescriptor = getOwnDataDescriptor(input, "length");
  if (
    lengthDescriptor === undefined ||
    typeof lengthDescriptor.value !== "number" ||
    lengthDescriptor.configurable ||
    lengthDescriptor.enumerable ||
    lengthDescriptor.writable
  ) {
    return { kind: "not-candidate" };
  }

  const unboxed = unboxString(input);
  if (unboxed !== undefined) return { kind: "value", value: unboxed };

  const length = lengthDescriptor.value;
  if (!numberIsSafeInteger(length) || length < 0) return { kind: "invalid" };

  const keys = ownKeys(input);
  if (length >= keys.length) return { kind: "invalid" };

  let value = "";
  for (let index = 0; index < length; index += 1) {
    const descriptor = getOwnDataDescriptor(input, index);
    if (
      descriptor === undefined ||
      descriptor.configurable ||
      !descriptor.enumerable ||
      descriptor.writable ||
      typeof descriptor.value !== "string" ||
      descriptor.value.length !== 1
    ) {
      return { kind: "invalid" };
    }
    value += descriptor.value;
  }

  return { kind: "value", value };
};

interface ErrorSnapshot {
  readonly cause: DataDescriptor | undefined;
  readonly message: DataDescriptor | undefined;
  readonly name: DataDescriptor | undefined;
  readonly stack: DataDescriptor | undefined;
}

const snapshotError = (input: object, branded: boolean): ErrorSnapshot | undefined => {
  if (!branded && typeof input === "function") return undefined;

  const message = getOwnDataDescriptor(input, "message");
  const stack = getOwnDataDescriptor(input, "stack");
  const hasDiagnosticShape =
    (message !== undefined && !message.enumerable && typeof message.value === "string") ||
    (stack !== undefined && !stack.enumerable && typeof stack.value === "string");

  if (!branded && !hasDiagnosticShape) return undefined;
  return {
    cause: getOwnDataDescriptor(input, "cause"),
    message,
    name: getOwnDataDescriptor(input, "name"),
    stack,
  };
};

const transformError = (
  error: object,
  snapshot: ErrorSnapshot,
  transform: (input: string) => string,
  seen: WeakMap<object, unknown>,
): Error => {
  const message =
    snapshot.message !== undefined && typeof snapshot.message.value === "string"
      ? snapshot.message.value
      : "";
  const transformed = new NativeError(transform(message));
  defineProperty(transformed, "toJSON", {
    configurable: true,
    writable: true,
    value: undefined,
  });
  setSeen(seen, error, transformed);

  if (snapshot.name !== undefined && typeof snapshot.name.value === "string") {
    defineProperty(transformed, "name", {
      ...snapshot.name,
      value: transform(snapshot.name.value),
    });
  }

  if (snapshot.stack !== undefined && typeof snapshot.stack.value === "string") {
    defineProperty(transformed, "stack", {
      ...snapshot.stack,
      value: transform(snapshot.stack.value),
    });
  }

  if (snapshot.cause !== undefined) {
    defineProperty(transformed, "cause", {
      configurable: true,
      writable: true,
      value: transformValue(snapshot.cause.value, transform, seen),
    });
  }

  for (const key of ownKeys(error)) {
    if (key === "name" || key === "message" || key === "stack" || key === "cause") {
      continue;
    }
    const descriptor = getOwnDataDescriptor(error, key);
    if (descriptor?.enumerable) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      defineProperty(transformed, key, {
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

  const existing = getSeen(seen, input);
  if (existing !== undefined) return existing;

  if (arrayIsArray(input)) {
    const result: unknown[] = [];
    defineProperty(result, "toJSON", {
      configurable: true,
      writable: true,
      value: undefined,
    });
    setSeen(seen, input, result);
    const lengthDescriptor = getOwnDataDescriptor(input, "length");
    if (lengthDescriptor === undefined || typeof lengthDescriptor.value !== "number") return result;
    const length = lengthDescriptor.value;
    defineProperty(result, "length", { value: length, writable: true });
    for (let index = 0; index < length; index += 1) {
      const descriptor = getOwnDataDescriptor(input, index);
      if (descriptor === undefined) continue;
      defineProperty(result, index, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: transformValue(descriptor.value, transform, seen),
      });
    }
    return result;
  }

  const brandedError =
    typeof errorIsError === "function" && reflectApply(errorIsError, NativeError, [input]);
  const errorSnapshot = snapshotError(input, brandedError);
  if (errorSnapshot !== undefined) {
    return transformError(input, errorSnapshot, transform, seen);
  }

  const boxedString = probeBoxedString(input);
  if (boxedString.kind === "value") return transform(boxedString.value);
  if (boxedString.kind === "invalid") {
    const result = createObject(null) as Record<PropertyKey, unknown>;
    setSeen(seen, input, result);
    return result;
  }

  const result = createObject(null) as Record<PropertyKey, unknown>;
  setSeen(seen, input, result);
  for (const key of ownKeys(input)) {
    const descriptor = getOwnPropertyDescriptor(input, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      defineProperty(result, key, {
        ...descriptor,
        value: transformValue(descriptor.value, transform, seen),
      });
    }
  }
  return result;
};

const protectValue = <T>(input: T, transform: (input: string) => string): ProtectedValue<T> =>
  transformValue(input, transform, new NativeWeakMap()) as ProtectedValue<T>;

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

  const cache = new NativeMap<string, string>();
  let size = 0;
  return (input) => {
    const hit = reflectApply(mapGet, cache, [input]) as string | undefined;
    if (hit !== undefined) {
      // Refresh recency.
      reflectApply(mapDelete, cache, [input]);
      reflectApply(mapSet, cache, [input, hit]);
      return hit;
    }

    const transformed = transform(input);
    if (size >= cacheSize) {
      const keys = reflectApply(mapKeys, cache, []);
      const oldest = reflectApply(mapIteratorNext, keys, []) as IteratorResult<string>;
      if (!oldest.done) {
        reflectApply(mapDelete, cache, [oldest.value]);
        size -= 1;
      }
    }
    reflectApply(mapSet, cache, [input, transformed]);
    size += 1;
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
