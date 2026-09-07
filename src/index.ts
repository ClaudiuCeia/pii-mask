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
 * Structural object types conservatively include every possible runtime brand
 * and projection because TypeScript cannot prove object identity.
 */
export type ProtectedValue<T> = T extends string
  ? string
  : T extends typeof String.prototype
    ? string | ProtectedObject<T>
    : T extends Error
      ? string | Error | ProtectedObject<T>
      : T extends Function
        ? ProtectedFunction<T>
        : T extends readonly unknown[]
          ? ProtectedArray<T>
          : T extends object
            ? ProtectedStructuredObject<T> | ProtectedPossiblePrimitive<T>
            : T;

type ProtectedFunction<T extends Function> = Function extends T
  ? ProtectedUnknownObject
  : CallableFunction extends T
    ? ProtectedUnknownObject
    : NewableFunction extends T
      ? ProtectedUnknownObject
      : ProtectedObject<T>;

type ProtectedObjectProjection<T extends object> = object extends T
  ? ProtectedUnknownObject
  : ProtectedObject<T>;

type ProtectedStructuredObject<T extends object> = string | Error | ProtectedObjectProjection<T>;

type ProtectedPossiblePrimitive<T> =
  | (number extends T ? number : never)
  | (boolean extends T ? boolean : never)
  | (bigint extends T ? bigint : never)
  | (symbol extends T ? symbol : never);

type ProtectedUnknownObject = { readonly [K in PropertyKey]?: unknown } & {
  readonly [K in ObjectPrototypeKey]?: unknown;
};

type ProtectedObject<T extends object> = {
  readonly [
    K in keyof T as K extends "toJSON"
      ? T[K] extends (...arguments_: never[]) => unknown
        ? never
        : K
      : K
  ]?: ProtectedObjectValue<T[K]>;
} & { readonly [K in Exclude<ObjectPrototypeKey, RetainedObjectPrototypeKey<T>>]?: unknown };

type ProtectedObjectValue<T> = T extends readonly unknown[]
  ? ProtectedRetainedArray<T>
  : ProtectedValue<T>;

type ProtectedRetainedValue<T> = T extends readonly unknown[]
  ? ProtectedRetainedArray<T>
  : ProtectedValue<T>;

type ProtectedRetainedArray<T extends readonly unknown[]> =
  | PossibleArraySpecialOutput
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

type RetainedObjectPrototypeKey<T extends object> = Extract<ObjectPrototypeKey, keyof T>;

type ObjectPrototypeKey =
  | "constructor"
  | "hasOwnProperty"
  | "isPrototypeOf"
  | "propertyIsEnumerable"
  | "toLocaleString"
  | "toString"
  | "valueOf";

type ProtectedArray<T extends readonly unknown[]> =
  | PossibleArraySpecialOutput
  | ProtectedActualArray<T>
  | ProtectedArrayObject<T>;

type PossibleArraySpecialOutput = string | Error;

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
    K in keyof T as K extends "toJSON"
      ? T[K] extends (...arguments_: never[]) => unknown
        ? never
        : K
      : K
  ]?: K extends number ? unknown : ProtectedObjectValue<T[K]>;
} & { readonly [K in Exclude<ObjectPrototypeKey, RetainedObjectPrototypeKey<T>>]?: unknown };

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

type DataDescriptor = PropertyDescriptor & { value: unknown };

interface ProtectedIntrinsic {
  readonly descriptor: PropertyDescriptor | undefined;
  readonly key: PropertyKey;
  readonly target: object;
}

const NativeArray = Array;
const NativeBigInt = BigInt;
const NativeDataView = DataView;
const NativeError = Error;
const NativeMap = Map;
const NativeNumber = Number;
const NativeObjectPrototype = Object.prototype;
const NativeRegExp = RegExp;
const NativeSet = Set;
const NativeString = String;
const NativeUint8Array = Uint8Array;
const NativeWeakMap = WeakMap;
const arrayEntries = NativeArray.prototype.entries;
const arrayIterator = NativeArray.prototype[Symbol.iterator];
const arrayKeys = NativeArray.prototype.keys;
const arrayJoin = NativeArray.prototype.join;
const arraySort = NativeArray.prototype.sort;
const arrayToLocaleString = NativeArray.prototype.toLocaleString;
const arrayValues = NativeArray.prototype.values;
const arrayIsArray = NativeArray.isArray;
const bigIntToLocaleString = NativeBigInt.prototype.toLocaleString;
const createObject = Object.create;
const defineProperties = Object.defineProperties;
const defineProperty = Object.defineProperty;
const errorIsError = NativeError.isError;
const errorToString = NativeError.prototype.toString;
const freezeObject = Object.freeze;
const functionBind = Function.prototype.bind;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const getPrototypeOf = Object.getPrototypeOf;
const setPrototypeOf = Object.setPrototypeOf;
const mapDelete = NativeMap.prototype.delete;
const mapGet = NativeMap.prototype.get;
const mapHas = NativeMap.prototype.has;
const mapIteratorNext = getPrototypeOf(new NativeMap().keys())
  .next as () => IteratorResult<unknown>;
const mapKeys = NativeMap.prototype.keys;
const mapSet = NativeMap.prototype.set;
const mathMin = Math.min;
const numberToLocaleString = NativeNumber.prototype.toLocaleString;
const numberIsSafeInteger = Number.isSafeInteger;
const ownKeys = Reflect.ownKeys;
const reflectApply = Reflect.apply;
const reflectDeleteProperty = Reflect.deleteProperty;
const setAdd = NativeSet.prototype.add;
const setDelete = NativeSet.prototype.delete;
const setHas = NativeSet.prototype.has;
const stringConcat = NativeString.prototype.concat;
const textEncoderDescriptor = getOwnPropertyDescriptor(globalThis, "TextEncoder");
const NativeTextEncoderPrototype = (() => {
  if (textEncoderDescriptor === undefined) return undefined;
  const constructor =
    "value" in textEncoderDescriptor
      ? textEncoderDescriptor.value
      : textEncoderDescriptor.get === undefined
        ? undefined
        : reflectApply(textEncoderDescriptor.get, globalThis, []);
  if (typeof constructor !== "function") return undefined;
  const prototype: unknown = Reflect.get(constructor, "prototype");
  return typeof prototype === "object" && prototype !== null ? prototype : undefined;
})();
const arrayIteratorPrototype = getPrototypeOf(reflectApply(arrayIterator, [], []));
const arrayIteratorNext = arrayIteratorPrototype.next as () => IteratorResult<unknown>;
const stringIterator = NativeString.prototype[Symbol.iterator];
const stringIteratorPrototype = getPrototypeOf(reflectApply(stringIterator, "", []));
const setIterator = NativeSet.prototype[Symbol.iterator];
const setIteratorPrototype = getPrototypeOf(reflectApply(setIterator, new NativeSet(), []));
const iteratorPrototype = getPrototypeOf(arrayIteratorPrototype);
const NativeTypedArray = getPrototypeOf(NativeUint8Array);
const NativeTypedArrayPrototype = getPrototypeOf(NativeUint8Array.prototype);
const customInspect = Symbol.for("nodejs.util.inspect.custom");
const denoCustomInspect = Symbol.for("Deno.customInspect");
const repeatString = Function.prototype.call.bind(String.prototype.repeat) as (
  input: string,
  count: number,
) => string;
const sliceString = Function.prototype.call.bind(String.prototype.slice) as (
  input: string,
  start: number,
  end?: number,
) => string;
const stringValueOf = String.prototype.valueOf;
const weakMapGet = NativeWeakMap.prototype.get;
const weakMapSet = NativeWeakMap.prototype.set;

const captureDataDescriptor = (target: object, key: PropertyKey): DataDescriptor => {
  const descriptor = getOwnPropertyDescriptor(target, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`Missing detector intrinsic ${String(key)}`);
  }
  return descriptor as DataDescriptor;
};

const captureIntrinsics = (
  target: object,
  keys: readonly PropertyKey[],
): readonly ProtectedIntrinsic[] => {
  const intrinsics: ProtectedIntrinsic[] = [];
  let count = 0;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    const descriptor = captureDataDescriptor(target, key);
    defineProperty(intrinsics, count, {
      configurable: true,
      enumerable: true,
      value: { descriptor, key, target },
      writable: true,
    });
    count += 1;
  }
  return intrinsics;
};

const detectorArrayKeys = ["from", "isArray"] as const;
const detectorArrayPrototypeKeys = [
  Symbol.iterator,
  "every",
  "fill",
  "filter",
  "find",
  "flat",
  "includes",
  "join",
  "map",
  "pop",
  "push",
  "reduce",
  "reverse",
  "slice",
  "sort",
] as const;
const detectorStringKeys = ["fromCharCode", "fromCodePoint"] as const;
const detectorStringPrototypeKeys = [
  Symbol.iterator,
  "charAt",
  "charCodeAt",
  "codePointAt",
  "endsWith",
  "includes",
  "indexOf",
  "lastIndexOf",
  "localeCompare",
  "match",
  "padEnd",
  "padStart",
  "repeat",
  "replace",
  "replaceAll",
  "slice",
  "split",
  "startsWith",
  "substring",
  "toLowerCase",
  "toUpperCase",
] as const;
const detectorRegExpPrototypeKeys = [
  Symbol.match,
  Symbol.matchAll,
  Symbol.replace,
  Symbol.search,
  Symbol.split,
  "exec",
  "test",
] as const;
const protectedDetectorIntrinsics = [
  { target: globalThis, key: "Array", descriptor: captureDataDescriptor(globalThis, "Array") },
  ...captureIntrinsics(NativeArray, detectorArrayKeys),
  ...captureIntrinsics(NativeArray.prototype, detectorArrayPrototypeKeys),
  ...captureIntrinsics(arrayIteratorPrototype, ["next"]),
  {
    target: iteratorPrototype,
    key: "return",
    descriptor: getOwnPropertyDescriptor(iteratorPrototype, "return"),
  },
] as const satisfies readonly ProtectedIntrinsic[];

const protectedStructuredDetectorIntrinsics = [
  ...protectedDetectorIntrinsics,
  { target: globalThis, key: "Map", descriptor: captureDataDescriptor(globalThis, "Map") },
  { target: globalThis, key: "Math", descriptor: captureDataDescriptor(globalThis, "Math") },
  { target: globalThis, key: "Number", descriptor: captureDataDescriptor(globalThis, "Number") },
  { target: globalThis, key: "RegExp", descriptor: captureDataDescriptor(globalThis, "RegExp") },
  { target: globalThis, key: "Set", descriptor: captureDataDescriptor(globalThis, "Set") },
  { target: globalThis, key: "String", descriptor: captureDataDescriptor(globalThis, "String") },
  {
    target: globalThis,
    key: "TextEncoder",
    descriptor: textEncoderDescriptor,
  },
  {
    target: globalThis,
    key: "Uint8Array",
    descriptor: captureDataDescriptor(globalThis, "Uint8Array"),
  },
  {
    target: globalThis,
    key: "Uint32Array",
    descriptor: captureDataDescriptor(globalThis, "Uint32Array"),
  },
  {
    target: globalThis,
    key: "DataView",
    descriptor: captureDataDescriptor(globalThis, "DataView"),
  },
  { target: globalThis, key: "WeakMap", descriptor: captureDataDescriptor(globalThis, "WeakMap") },
  ...captureIntrinsics(NativeMap.prototype, ["delete", "get", "has", "keys", "set"]),
  {
    target: NativeMap.prototype,
    key: "size",
    descriptor: getOwnPropertyDescriptor(NativeMap.prototype, "size"),
  },
  ...captureIntrinsics(getPrototypeOf(reflectApply(mapKeys, new NativeMap(), [])), ["next"]),
  ...captureIntrinsics(NativeNumber, ["isFinite", "isInteger", "isNaN", "isSafeInteger"]),
  ...captureIntrinsics(NativeRegExp.prototype, detectorRegExpPrototypeKeys),
  {
    target: NativeRegExp.prototype,
    key: "flags",
    descriptor: getOwnPropertyDescriptor(NativeRegExp.prototype, "flags"),
  },
  {
    target: NativeRegExp.prototype,
    key: "source",
    descriptor: getOwnPropertyDescriptor(NativeRegExp.prototype, "source"),
  },
  ...captureIntrinsics(NativeSet.prototype, [Symbol.iterator, "add", "has"]),
  ...captureIntrinsics(setIteratorPrototype, ["next"]),
  ...captureIntrinsics(NativeString, detectorStringKeys),
  ...captureIntrinsics(NativeString.prototype, detectorStringPrototypeKeys),
  ...captureIntrinsics(stringIteratorPrototype, ["next"]),
  ...(NativeTextEncoderPrototype === undefined
    ? []
    : captureIntrinsics(NativeTextEncoderPrototype, ["encode"])),
  ...captureIntrinsics(NativeTypedArray, ["from"]),
  ...captureIntrinsics(NativeTypedArrayPrototype, ["fill", "set", "slice", "subarray"]),
  {
    target: NativeTypedArrayPrototype,
    key: "buffer",
    descriptor: getOwnPropertyDescriptor(NativeTypedArrayPrototype, "buffer"),
  },
  {
    target: NativeTypedArrayPrototype,
    key: "byteLength",
    descriptor: getOwnPropertyDescriptor(NativeTypedArrayPrototype, "byteLength"),
  },
  {
    target: NativeTypedArrayPrototype,
    key: "byteOffset",
    descriptor: getOwnPropertyDescriptor(NativeTypedArrayPrototype, "byteOffset"),
  },
  {
    target: NativeTypedArrayPrototype,
    key: "length",
    descriptor: getOwnPropertyDescriptor(NativeTypedArrayPrototype, "length"),
  },
  ...captureIntrinsics(NativeDataView.prototype, ["getUint32", "setUint32"]),
  ...captureIntrinsics(NativeWeakMap.prototype, ["get", "set"]),
  ...captureIntrinsics(Math, ["floor", "max", "min", "trunc"]),
  { target: globalThis, key: "atob", descriptor: getOwnPropertyDescriptor(globalThis, "atob") },
  {
    target: globalThis,
    key: "parseInt",
    descriptor: captureDataDescriptor(globalThis, "parseInt"),
  },
  { target: JSON, key: "parse", descriptor: captureDataDescriptor(JSON, "parse") },
] as const satisfies readonly ProtectedIntrinsic[];

const dataDescriptorsEqual = (
  left: PropertyDescriptor | undefined,
  right: PropertyDescriptor | undefined,
): boolean => {
  if (left === undefined || right === undefined) return left === right;
  if (left.configurable !== right.configurable || left.enumerable !== right.enumerable)
    return false;
  if ("value" in left || "value" in right) {
    return (
      "value" in left &&
      "value" in right &&
      left.value === right.value &&
      left.writable === right.writable
    );
  }
  return left.get === right.get && left.set === right.set;
};

const withProtectedDetectorIntrinsics = <T>(
  operation: () => T,
  intrinsics: readonly ProtectedIntrinsic[] = protectedDetectorIntrinsics,
): T => {
  const changedDescriptors: (PropertyDescriptor | undefined)[] = [];
  const changedIndexes: number[] = [];
  let changedCount = 0;

  try {
    for (let index = 0; index < intrinsics.length; index += 1) {
      const intrinsic = intrinsics[index];
      if (intrinsic === undefined) continue;
      const current = getOwnPropertyDescriptor(intrinsic.target, intrinsic.key);
      if (dataDescriptorsEqual(current, intrinsic.descriptor)) continue;
      defineProperty(changedDescriptors, changedCount, {
        configurable: true,
        enumerable: true,
        value: current,
        writable: true,
      });
      defineProperty(changedIndexes, changedCount, {
        configurable: true,
        enumerable: true,
        value: index,
        writable: true,
      });
      if (intrinsic.descriptor === undefined) {
        if (!reflectDeleteProperty(intrinsic.target, intrinsic.key)) {
          throw new TypeError("Unable to protect detector intrinsic");
        }
      } else {
        defineProperty(intrinsic.target, intrinsic.key, intrinsic.descriptor);
      }
      changedCount += 1;
    }
    return operation();
  } finally {
    for (let index = changedCount - 1; index >= 0; index -= 1) {
      const intrinsicIndex = changedIndexes[index];
      if (intrinsicIndex === undefined) continue;
      const intrinsic = intrinsics[intrinsicIndex];
      if (intrinsic === undefined) continue;
      const descriptor = changedDescriptors[index];
      if (descriptor === undefined) {
        reflectDeleteProperty(intrinsic.target, intrinsic.key);
      } else {
        defineProperty(intrinsic.target, intrinsic.key, descriptor);
      }
    }
  }
};

const detector = Duckling(PIIParsers);
const extractPii = (input: string): PIIEntity[] => detector.extract(input);

const getSeen = (seen: WeakMap<object, unknown>, input: object): unknown =>
  reflectApply(weakMapGet, seen, [input]);

const setSeen = (seen: WeakMap<object, unknown>, input: object, output: unknown): void => {
  reflectApply(weakMapSet, seen, [input, output]);
};

const safeValueOf = function (this: unknown): unknown {
  return this;
};

const stringifyProjectedArray = (
  values: unknown[],
  seen: Set<object>,
  separator = ",",
  length = values.length,
): string => {
  if (reflectApply(setHas, seen, [values])) return "";
  reflectApply(setAdd, seen, [values]);
  let result = "";
  try {
    for (let index = 0; index < length; index += 1) {
      if (index > 0) result += separator;
      const descriptor = getOwnDataDescriptor(values, index);
      const value = descriptor?.value;
      if (value === undefined || value === null) continue;
      if (arrayIsArray(value)) {
        result += stringifyProjectedArray(value, seen);
      } else if (typeof value === "object") {
        const valueToString = getOwnDataDescriptor(value, "toString")?.value;
        result +=
          valueToString === safeErrorToString
            ? (reflectApply(safeErrorToString, value, []) as string)
            : "[object Object]";
      } else if (typeof value === "symbol") {
        throw new TypeError("Cannot convert a Symbol value to a string");
      } else {
        result += NativeString(value);
      }
    }
    return result;
  } finally {
    reflectApply(setDelete, seen, [values]);
  }
};

const safeArrayJoin = function (this: unknown, separator?: unknown): string {
  if (!arrayIsArray(this)) return reflectApply(arrayJoin, this, [separator]) as string;
  const length = this.length;
  const resolvedSeparator =
    separator === undefined ? "," : (reflectApply(stringConcat, "", [separator]) as string);
  return stringifyProjectedArray(this, new NativeSet(), resolvedSeparator, length);
};

const safeArrayToString = function (this: unknown): string {
  if (!arrayIsArray(this)) return reflectApply(arrayJoin, this, [","]) as string;
  return stringifyProjectedArray(this, new NativeSet());
};

const localeStringForProjectedValue = (
  value: unknown,
  seen: Set<object>,
  locales: unknown,
  options: unknown,
): string => {
  if (arrayIsArray(value)) return stringifyProjectedArrayLocale(value, seen, locales, options);
  if (typeof value === "number") {
    return reflectApply(numberToLocaleString, value, [locales, options]) as string;
  }
  if (typeof value === "bigint") {
    return reflectApply(bigIntToLocaleString, value, [locales, options]) as string;
  }
  if (value !== null && typeof value === "object") {
    return getOwnDataDescriptor(value, "toString")?.value === safeErrorToString
      ? (reflectApply(safeErrorToString, value, []) as string)
      : "[object Object]";
  }
  return NativeString(value);
};

const stringifyProjectedArrayLocale = (
  values: unknown[],
  seen: Set<object>,
  locales: unknown,
  options: unknown,
): string => {
  if (reflectApply(setHas, seen, [values])) return "";
  reflectApply(setAdd, seen, [values]);
  const length = values.length;
  let result = "";
  try {
    for (let index = 0; index < length; index += 1) {
      if (index > 0) result += ",";
      const value = getOwnDataDescriptor(values, index)?.value;
      if (value === undefined || value === null) continue;
      result += localeStringForProjectedValue(value, seen, locales, options);
    }
    return result;
  } finally {
    reflectApply(setDelete, seen, [values]);
  }
};

const safeArrayToLocaleString = function (
  this: unknown,
  locales?: unknown,
  options?: unknown,
): string {
  if (!arrayIsArray(this)) {
    return reflectApply(arrayToLocaleString, this, [locales, options]) as string;
  }
  return stringifyProjectedArrayLocale(this, new NativeSet(), locales, options);
};

const safeErrorToString = function (this: unknown): string {
  return reflectApply(errorToString, this, []) as string;
};

const protectedErrorDescriptors = (() => {
  const result = createObject(null) as Record<PropertyKey, PropertyDescriptor>;
  const sources = [NativeObjectPrototype, NativeError.prototype];
  for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
    const source = sources[sourceIndex];
    if (source === undefined) continue;
    const keys = ownKeys(source);
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const key = keys[keyIndex];
      if (key === undefined) continue;
      const descriptor = getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined) continue;
      defineProperty(result, key, {
        configurable: true,
        enumerable: true,
        value: descriptor,
        writable: true,
      });
    }
  }
  const overrides: Record<PropertyKey, PropertyDescriptor> = {
    name: { configurable: true, value: "Error", writable: true },
    stack: { configurable: true, value: undefined, writable: true },
    // oxlint-disable-next-line unicorn/no-thenable -- Explicitly shadow inherited thenable hooks.
    then: { configurable: true, value: undefined, writable: true },
    toJSON: { configurable: true, value: undefined, writable: true },
    toString: { configurable: true, value: safeErrorToString, writable: true },
    valueOf: { configurable: true, value: safeValueOf, writable: true },
    [Symbol.asyncIterator]: { configurable: true, value: undefined, writable: true },
    [Symbol.asyncDispose]: { configurable: true, value: undefined, writable: true },
    [Symbol.dispose]: { configurable: true, value: undefined, writable: true },
    [Symbol.hasInstance]: { configurable: true, value: undefined, writable: true },
    [Symbol.isConcatSpreadable]: { configurable: true, value: undefined, writable: true },
    [Symbol.iterator]: { configurable: true, value: undefined, writable: true },
    [Symbol.match]: { configurable: true, value: undefined, writable: true },
    [Symbol.matchAll]: { configurable: true, value: undefined, writable: true },
    [Symbol.replace]: { configurable: true, value: undefined, writable: true },
    [Symbol.search]: { configurable: true, value: undefined, writable: true },
    [Symbol.split]: { configurable: true, value: undefined, writable: true },
    [Symbol.toPrimitive]: { configurable: true, value: undefined, writable: true },
    [Symbol.toStringTag]: { configurable: true, value: undefined, writable: true },
    [customInspect]: { configurable: true, value: undefined, writable: true },
    [denoCustomInspect]: { configurable: true, value: undefined, writable: true },
  };
  const keys = ownKeys(overrides);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    defineProperty(result, key, {
      configurable: true,
      enumerable: true,
      value: overrides[key],
      writable: true,
    });
  }
  return freezeObject(result);
})();

const shadowErrorPrototypeAdditions = (error: Error): void => {
  const sources = [NativeObjectPrototype, NativeError.prototype];
  for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
    const source = sources[sourceIndex];
    if (source === undefined) continue;
    const keys = ownKeys(source);
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const key = keys[keyIndex];
      if (key === undefined || getOwnPropertyDescriptor(error, key) !== undefined) continue;
      defineProperty(error, key, { configurable: true, value: undefined, writable: true });
    }
  }
};

/** Find PII spans in free-form text using ts-duckling. */
export const findPii = (input: string): PIIEntity[] =>
  withProtectedDetectorIntrinsics(() => extractPii(input));

const selectedEntities = (entities: PIIEntity[], kinds?: readonly PIIKind[]): PIIEntity[] => {
  if (kinds === undefined) return entities;

  const selected: PIIEntity[] = [];
  let selectedCount = 0;
  for (let entityIndex = 0; entityIndex < entities.length; entityIndex += 1) {
    const entity = entities[entityIndex];
    if (entity === undefined) continue;
    let included = false;
    for (let kindIndex = 0; kindIndex < kinds.length; kindIndex += 1) {
      if (kinds[kindIndex] === entity.kind) {
        included = true;
        break;
      }
    }
    if (!included) continue;
    defineProperty(selected, selectedCount, {
      configurable: true,
      enumerable: true,
      value: entity,
      writable: true,
    });
    selectedCount += 1;
  }
  return selected;
};

const replaceEntities = (
  input: string,
  entities: PIIEntity[],
  replacement: (entity: PIIEntity) => string,
): string => {
  if (entities.length === 0) return input;

  let result = input;
  let boundary = input.length;
  const ordered = entities;
  reflectApply(arraySort, ordered, [
    (left: PIIEntity, right: PIIEntity) => right.start - left.start || right.end - left.end,
  ]);

  for (let index = 0; index < ordered.length; index += 1) {
    const entity = ordered[index];
    if (entity === undefined) continue;
    if (entity.end > boundary) continue;
    result =
      sliceString(result, 0, entity.start) + replacement(entity) + sliceString(result, entity.end);
    boundary = entity.start;
  }

  return result;
};

const naturalNumber = (name: string, value: number | undefined): number => {
  if (value === undefined) return 0;
  if (!numberIsSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
  return value;
};

interface ResolvedMaskOptions {
  readonly keepEnd: number;
  readonly keepStart: number;
  readonly kinds: readonly PIIKind[] | undefined;
  readonly mask: string;
}

interface ResolvedRedactOptions {
  readonly kinds: readonly PIIKind[] | undefined;
  readonly replacement: string | ((entity: PIIEntity) => string);
}

const snapshotKinds = (kinds: readonly PIIKind[] | undefined): readonly PIIKind[] | undefined => {
  if (kinds === undefined) return undefined;
  const result: PIIKind[] = [];
  const length = kinds.length;
  for (let index = 0; index < length; index += 1) {
    defineProperty(result, index, {
      configurable: true,
      enumerable: true,
      value: kinds[index],
      writable: true,
    });
  }
  return result;
};

const resolveMaskOptions = (options: MaskOptions): ResolvedMaskOptions => {
  const mask = options.mask ?? "*";
  if (mask.length === 0) throw new RangeError("mask must not be empty");
  return {
    keepEnd: naturalNumber("keepEnd", options.keepEnd),
    keepStart: naturalNumber("keepStart", options.keepStart),
    kinds: snapshotKinds(options.kinds),
    mask,
  };
};

const resolveRedactOptions = (options: RedactOptions): ResolvedRedactOptions => ({
  kinds: snapshotKinds(options.kinds),
  replacement: options.replacement ?? "[REDACTED]",
});

const maskDetectedText = (
  input: string,
  entities: PIIEntity[],
  options: ResolvedMaskOptions,
): string => {
  const selected = selectedEntities(entities, options.kinds);
  return replaceEntities(input, selected, (entity) => {
    const length = entity.end - entity.start;
    const visibleStart = mathMin(options.keepStart, length);
    const visibleEnd = mathMin(options.keepEnd, length - visibleStart);
    return (
      sliceString(entity.text, 0, visibleStart) +
      repeatString(options.mask, length - visibleStart - visibleEnd) +
      sliceString(entity.text, length - visibleEnd)
    );
  });
};

/** Mask detected PII while optionally preserving leading or trailing characters. */
export const maskText = (input: string, options: MaskOptions = {}): string => {
  const resolved = resolveMaskOptions(options);
  return maskDetectedText(input, findPii(input), resolved);
};

const redactDetectedText = (
  input: string,
  entities: PIIEntity[],
  options: ResolvedRedactOptions,
): string => {
  const replacement = options.replacement;
  const selected = selectedEntities(entities, options.kinds);
  return replaceEntities(input, selected, (entity) =>
    typeof replacement === "function" ? replacement(entity) : replacement,
  );
};

/** Replace each detected PII span with a fixed or entity-aware value. */
export const redactText = (input: string, options: RedactOptions = {}): string =>
  redactDetectedText(input, findPii(input), resolveRedactOptions(options));

const unboxString = (value: object): string | undefined => {
  try {
    const unboxed: unknown = reflectApply(stringValueOf, value, []);
    return typeof unboxed === "string" ? unboxed : undefined;
  } catch {
    return undefined;
  }
};

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

interface PendingString {
  readonly descriptor: DataDescriptor;
  readonly key: PropertyKey;
  readonly target: object;
  readonly value: string;
}

type ValueTransform = ((input: string, entities: PIIEntity[]) => string) & {
  readonly peek?: (input: string) => string | undefined;
};

type CachedTextTransform = (input: string) => string;

interface CachedTransforms {
  readonly text: CachedTextTransform;
  readonly value: ValueTransform;
}

const transformOneString = (input: string, transform: ValueTransform): string => {
  const cached = transform.peek?.(input);
  if (cached !== undefined) return cached;
  const entities = withProtectedDetectorIntrinsics(
    () => extractPii(input),
    protectedStructuredDetectorIntrinsics,
  );
  return transform(input, entities);
};

const appendPendingString = (pendingStrings: PendingString[], pending: PendingString): void => {
  defineProperty(pendingStrings, pendingStrings.length, {
    configurable: true,
    enumerable: true,
    value: pending,
    writable: true,
  });
};

const projectStringProperty = (
  target: object,
  key: PropertyKey,
  descriptor: DataDescriptor,
  value: string,
  pendingStrings: PendingString[],
  eagerTransform: ValueTransform | undefined,
): void => {
  if (eagerTransform !== undefined) {
    defineProperty(target, key, {
      ...descriptor,
      value: transformOneString(value, eagerTransform),
    });
    return;
  }
  defineProperty(target, key, {
    configurable: true,
    enumerable: descriptor.enumerable ?? false,
    value: undefined,
    writable: true,
  });
  appendPendingString(pendingStrings, { descriptor, key, target, value });
};

const flushPendingStrings = (pendingStrings: PendingString[], transform: ValueTransform): void => {
  if (pendingStrings.length === 0) return;
  if (pendingStrings.length === 1) {
    const pending = pendingStrings[0];
    if (pending === undefined) return;
    const cached = transform.peek?.(pending.value);
    if (cached !== undefined) {
      defineProperty(pending.target, pending.key, {
        ...pending.descriptor,
        value: cached,
      });
      defineProperty(pendingStrings, "length", { value: 0 });
      return;
    }
    const entities = withProtectedDetectorIntrinsics(
      () => extractPii(pending.value),
      protectedStructuredDetectorIntrinsics,
    );
    defineProperty(pending.target, pending.key, {
      ...pending.descriptor,
      value: transform(pending.value, entities),
    });
    defineProperty(pendingStrings, "length", { value: 0 });
    return;
  }

  const pendingEntities: PIIEntity[][] = [];
  const cachedValues: (string | undefined)[] = [];
  const detectedByInput = new NativeMap<string, PIIEntity[]>();
  withProtectedDetectorIntrinsics(() => {
    for (let index = 0; index < pendingStrings.length; index += 1) {
      const pending = pendingStrings[index];
      if (pending === undefined) continue;
      const cached = transform.peek?.(pending.value);
      if (cached !== undefined) {
        defineProperty(cachedValues, index, {
          configurable: true,
          enumerable: true,
          value: cached,
          writable: true,
        });
        continue;
      }
      let entities = reflectApply(mapGet, detectedByInput, [pending.value]) as
        | PIIEntity[]
        | undefined;
      if (entities === undefined) {
        entities = extractPii(pending.value);
        reflectApply(mapSet, detectedByInput, [pending.value, entities]);
      }
      defineProperty(pendingEntities, index, {
        configurable: true,
        enumerable: true,
        value: entities,
        writable: true,
      });
    }
  }, protectedStructuredDetectorIntrinsics);

  for (let index = 0; index < pendingStrings.length; index += 1) {
    const pending = pendingStrings[index];
    const cached = cachedValues[index];
    if (pending !== undefined && cached !== undefined) {
      defineProperty(pending.target, pending.key, {
        ...pending.descriptor,
        value: cached,
      });
      continue;
    }
    const entities = pendingEntities[index];
    if (pending === undefined || entities === undefined) continue;
    defineProperty(pending.target, pending.key, {
      ...pending.descriptor,
      value: transform(pending.value, entities),
    });
  }
  defineProperty(pendingStrings, "length", { value: 0 });
};

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
  seen: WeakMap<object, unknown>,
  sparseArrays: unknown[][],
  protectedErrors: Error[],
  pendingStrings: PendingString[],
  eagerTransform: ValueTransform | undefined,
): Error => {
  const message =
    snapshot.message !== undefined && typeof snapshot.message.value === "string"
      ? snapshot.message.value
      : "";
  const transformed = new NativeError(message === "" ? "" : undefined);
  defineProperties(transformed, protectedErrorDescriptors);
  defineProperty(protectedErrors, protectedErrors.length, {
    configurable: true,
    enumerable: true,
    value: transformed,
    writable: true,
  });
  setSeen(seen, error, transformed);

  if (snapshot.message !== undefined && typeof snapshot.message.value === "string") {
    projectStringProperty(
      transformed,
      "message",
      snapshot.message,
      snapshot.message.value,
      pendingStrings,
      eagerTransform,
    );
  }

  if (snapshot.name !== undefined && typeof snapshot.name.value === "string") {
    projectStringProperty(
      transformed,
      "name",
      snapshot.name,
      snapshot.name.value,
      pendingStrings,
      eagerTransform,
    );
  }

  if (snapshot.stack !== undefined && typeof snapshot.stack.value === "string") {
    projectStringProperty(
      transformed,
      "stack",
      snapshot.stack,
      snapshot.stack.value,
      pendingStrings,
      eagerTransform,
    );
  }

  if (snapshot.cause !== undefined) {
    defineProjectedProperty(
      transformed,
      "cause",
      snapshot.cause,
      seen,
      sparseArrays,
      protectedErrors,
      pendingStrings,
      eagerTransform,
    );
  }

  const keys = ownKeys(error);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    if (key === "name" || key === "message" || key === "stack" || key === "cause") {
      continue;
    }
    const descriptor = getOwnDataDescriptor(error, key);
    if (descriptor?.enumerable) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      defineProjectedProperty(
        transformed,
        key,
        descriptor,
        seen,
        sparseArrays,
        protectedErrors,
        pendingStrings,
        eagerTransform,
      );
    }
  }

  return transformed;
};

const createArrayIterator = (
  values: unknown,
  factory: (this: unknown) => ArrayIterator<unknown>,
): ArrayIterator<unknown> => {
  const iterator = reflectApply(factory, values, []);
  setPrototypeOf(iterator, null);
  defineProperties(iterator, {
    next: { configurable: true, value: arrayIteratorNext, writable: true },
    [Symbol.iterator]: {
      configurable: true,
      value: function (this: ArrayIterator<unknown>): ArrayIterator<unknown> {
        return this;
      },
      writable: true,
    },
    [Symbol.toStringTag]: { configurable: true, value: "Array Iterator" },
  });
  return iterator;
};

const safeArrayEntries = function (this: unknown): ArrayIterator<unknown> {
  return createArrayIterator(this, arrayEntries);
};

const safeArrayKeys = function (this: unknown): ArrayIterator<unknown> {
  return createArrayIterator(this, arrayKeys);
};

const safeArrayValues = function (this: unknown): ArrayIterator<unknown> {
  return createArrayIterator(this, arrayValues);
};

function SafeArraySpecies(length = 0): unknown[] {
  return createProtectedArray(length);
}

const safeArrayConstructor = createObject(null) as object;
defineProperty(safeArrayConstructor, Symbol.species, {
  value: freezeObject(SafeArraySpecies),
});
freezeObject(safeArrayConstructor);

const createSafeArrayCopyMethod = (key: PropertyKey): unknown => {
  const method = getOwnDataDescriptor(NativeArray.prototype, key)?.value;
  if (typeof method !== "function") return undefined;
  return function (this: unknown, ...args: unknown[]): unknown {
    const result = reflectApply(method, this, args);
    if (arrayIsArray(result)) setPrototypeOf(result, safeArrayPrototype);
    return result;
  };
};

const safeArrayCopyMethods = {
  toReversed: createSafeArrayCopyMethod("toReversed"),
  toSorted: createSafeArrayCopyMethod("toSorted"),
  toSpliced: createSafeArrayCopyMethod("toSpliced"),
  with: createSafeArrayCopyMethod("with"),
};

const safeArrayPrototype = (() => {
  const result = createObject(null) as object;
  const sources = [NativeObjectPrototype, NativeArray.prototype];
  for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
    const source = sources[sourceIndex];
    if (source === undefined) continue;
    const keys = ownKeys(source);
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const key = keys[keyIndex];
      if (key === undefined) continue;
      const descriptor = getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined) continue;
      defineProperty(result, key, descriptor);
    }
  }
  defineProperties(result, {
    constructor: { configurable: true, value: safeArrayConstructor, writable: true },
    entries: { configurable: true, value: safeArrayEntries, writable: true },
    join: { configurable: true, value: safeArrayJoin, writable: true },
    keys: { configurable: true, value: safeArrayKeys, writable: true },
    toJSON: { configurable: true, value: undefined, writable: true },
    toLocaleString: { configurable: true, value: safeArrayToLocaleString, writable: true },
    toString: { configurable: true, value: safeArrayToString, writable: true },
    valueOf: { configurable: true, value: safeValueOf, writable: true },
    values: { configurable: true, value: safeArrayValues, writable: true },
    [Symbol.iterator]: { configurable: true, value: safeArrayValues, writable: true },
    [Symbol.toPrimitive]: { configurable: true, value: undefined, writable: true },
    [Symbol.toStringTag]: { configurable: true, value: undefined, writable: true },
    [customInspect]: { configurable: true, value: undefined, writable: true },
    [denoCustomInspect]: { configurable: true, value: undefined, writable: true },
  });
  const copyMethodKeys = ownKeys(safeArrayCopyMethods);
  for (let index = 0; index < copyMethodKeys.length; index += 1) {
    const key = copyMethodKeys[index];
    if (key === undefined) continue;
    const method = getOwnDataDescriptor(safeArrayCopyMethods, key)?.value;
    if (typeof method !== "function") continue;
    defineProperty(result, key, { configurable: true, value: method, writable: true });
  }
  return freezeObject(result);
})();

const createProtectedArray = (length = 0): unknown[] => {
  const result: unknown[] = [];
  setPrototypeOf(result, safeArrayPrototype);
  defineProperties(result, {
    length: { value: length, writable: true },
    toJSON: { configurable: true, value: undefined, writable: true },
  });
  return result;
};

const defineProjectedProperty = (
  target: object,
  key: PropertyKey,
  descriptor: DataDescriptor,
  seen: WeakMap<object, unknown>,
  sparseArrays: unknown[][],
  protectedErrors: Error[],
  pendingStrings: PendingString[],
  eagerTransform: ValueTransform | undefined,
): void => {
  if (typeof descriptor.value === "string") {
    projectStringProperty(
      target,
      key,
      descriptor,
      descriptor.value,
      pendingStrings,
      eagerTransform,
    );
    return;
  }
  const value = transformValue(
    descriptor.value,
    seen,
    sparseArrays,
    protectedErrors,
    pendingStrings,
    eagerTransform,
  );
  if (typeof value === "string" && eagerTransform === undefined) {
    projectStringProperty(target, key, descriptor, value, pendingStrings, eagerTransform);
    return;
  }
  defineProperty(target, key, { ...descriptor, value });
};

const transformValue = (
  input: unknown,
  seen: WeakMap<object, unknown>,
  sparseArrays: unknown[][],
  protectedErrors: Error[],
  pendingStrings: PendingString[],
  eagerTransform: ValueTransform | undefined,
): unknown => {
  if (typeof input === "string") {
    return eagerTransform === undefined ? input : transformOneString(input, eagerTransform);
  }
  if ((typeof input !== "object" && typeof input !== "function") || input === null) return input;
  const existing = getSeen(seen, input);
  if (existing !== undefined) return existing;

  if (arrayIsArray(input)) {
    const result = createProtectedArray();
    setSeen(seen, input, result);
    const lengthDescriptor = getOwnDataDescriptor(input, "length");
    if (lengthDescriptor === undefined || typeof lengthDescriptor.value !== "number") return result;
    const length = lengthDescriptor.value;
    let skippedIndex = false;
    defineProperty(result, "length", { value: length, writable: true });
    for (let index = 0; index < length; index += 1) {
      const descriptor = getOwnDataDescriptor(input, index);
      if (descriptor === undefined) {
        skippedIndex = true;
        continue;
      }
      defineProjectedProperty(
        result,
        index,
        {
          configurable: true,
          enumerable: true,
          writable: true,
          value: descriptor.value,
        },
        seen,
        sparseArrays,
        protectedErrors,
        pendingStrings,
        eagerTransform,
      );
    }
    if (skippedIndex) {
      defineProperty(sparseArrays, sparseArrays.length, {
        configurable: true,
        enumerable: true,
        value: result,
        writable: true,
      });
    }
    return result;
  }

  const brandedError =
    typeof errorIsError === "function" && reflectApply(errorIsError, NativeError, [input]);
  if (brandedError) {
    const errorSnapshot = snapshotError(input, true);
    if (errorSnapshot !== undefined) {
      return transformError(
        input,
        errorSnapshot,
        seen,
        sparseArrays,
        protectedErrors,
        pendingStrings,
        eagerTransform,
      );
    }
  }

  const boxedString = probeBoxedString(input);
  if (boxedString.kind === "value") {
    return eagerTransform === undefined
      ? boxedString.value
      : transformOneString(boxedString.value, eagerTransform);
  }
  if (boxedString.kind === "invalid") {
    const result = createObject(null) as Record<PropertyKey, unknown>;
    setSeen(seen, input, result);
    return result;
  }

  const errorSnapshot = snapshotError(input, false);
  if (errorSnapshot !== undefined) {
    return transformError(
      input,
      errorSnapshot,
      seen,
      sparseArrays,
      protectedErrors,
      pendingStrings,
      eagerTransform,
    );
  }

  const result = createObject(null) as Record<PropertyKey, unknown>;
  setSeen(seen, input, result);
  const keys = ownKeys(input);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    const descriptor = getOwnPropertyDescriptor(input, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      if (key === "toJSON" && typeof descriptor.value === "function") continue;
      defineProjectedProperty(
        result,
        key,
        descriptor as DataDescriptor,
        seen,
        sparseArrays,
        protectedErrors,
        pendingStrings,
        eagerTransform,
      );
    }
  }
  return result;
};

const finalizeSparseArrays = (sparseArrays: unknown[][]): void => {
  const nativePrototypeChainIsIntact =
    getPrototypeOf(NativeArray.prototype) === NativeObjectPrototype &&
    getPrototypeOf(NativeObjectPrototype) === null;
  for (let arrayIndex = 0; arrayIndex < sparseArrays.length; arrayIndex += 1) {
    const array = sparseArrays[arrayIndex];
    if (array === undefined) continue;
    for (let index = 0; index < array.length; index += 1) {
      if (getOwnPropertyDescriptor(array, index) !== undefined) continue;
      if (nativePrototypeChainIsIntact) {
        const inheritedDescriptor =
          getOwnPropertyDescriptor(NativeArray.prototype, index) ??
          getOwnPropertyDescriptor(NativeObjectPrototype, index);
        if (inheritedDescriptor === undefined) continue;
      }
      defineProperty(array, index, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: undefined,
      });
    }
  }
};

const finalizeProtectedErrors = (protectedErrors: Error[]): void => {
  for (let index = 0; index < protectedErrors.length; index += 1) {
    const error = protectedErrors[index];
    if (error !== undefined) shadowErrorPrototypeAdditions(error);
  }
};

const protectValue = <T>(input: T, transform: ValueTransform, eager = false): ProtectedValue<T> => {
  const sparseArrays: unknown[][] = [];
  const protectedErrors: Error[] = [];
  const pendingStrings: PendingString[] = [];
  const result = transformValue(
    input,
    new NativeWeakMap(),
    sparseArrays,
    protectedErrors,
    pendingStrings,
    eager ? transform : undefined,
  );
  if (typeof result === "string") {
    if (eager) return result as ProtectedValue<T>;
    const cached = transform.peek?.(result);
    if (cached !== undefined) return cached as ProtectedValue<T>;
    const entities = withProtectedDetectorIntrinsics(
      () => extractPii(result),
      protectedStructuredDetectorIntrinsics,
    );
    return transform(result, entities) as ProtectedValue<T>;
  }
  flushPendingStrings(pendingStrings, transform);
  finalizeSparseArrays(sparseArrays);
  finalizeProtectedErrors(protectedErrors);
  return result as ProtectedValue<T>;
};

/** Mask strings nested in structured data. */
export const maskValue = <T>(input: T, options: MaskOptions = {}): ProtectedValue<T> => {
  const resolved = resolveMaskOptions(options);
  return protectValue(input, (value, entities) => maskDetectedText(value, entities, resolved));
};

/** Redact strings nested in structured data. */
export const redactValue = <T>(input: T, options: RedactOptions = {}): ProtectedValue<T> => {
  const resolved = resolveRedactOptions(options);
  return protectValue(
    input,
    (value, entities) => redactDetectedText(value, entities, resolved),
    typeof resolved.replacement === "function",
  );
};

const DEFAULT_CACHE_SIZE = 1024;

const withCache = (
  transform: (input: string, entities?: PIIEntity[]) => string,
  cacheSize: number,
): CachedTransforms => {
  if (cacheSize === 0) {
    return { text: (input) => transform(input), value: transform };
  }

  const cache = new NativeMap<string, string>();
  const cacheDelete = reflectApply(functionBind, mapDelete, [cache]) as (input: string) => boolean;
  const cacheGet = reflectApply(functionBind, mapGet, [cache]) as (
    input: string,
  ) => string | undefined;
  const cacheHas = reflectApply(functionBind, mapHas, [cache]) as (input: string) => boolean;
  const cacheKeys = reflectApply(functionBind, mapKeys, [cache]) as () => MapIterator<string>;
  const cacheSet = reflectApply(functionBind, mapSet, [cache]) as (
    input: string,
    output: string,
  ) => Map<string, string>;
  const structuredInputs = new NativeSet<string>();
  const structuredAdd = reflectApply(functionBind, setAdd, [structuredInputs]) as (
    input: string,
  ) => Set<string>;
  const structuredDelete = reflectApply(functionBind, setDelete, [structuredInputs]) as (
    input: string,
  ) => boolean;
  const structuredHas = reflectApply(functionBind, setHas, [structuredInputs]) as (
    input: string,
  ) => boolean;
  let size = 0;
  const lookup = (input: string): string | undefined => {
    if (!structuredHas(input)) return undefined;
    const hit = cacheGet(input);
    if (hit === undefined) return undefined;
    cacheDelete(input);
    cacheSet(input, hit);
    return hit;
  };
  const store = (input: string, transformed: string, structured: boolean): string => {
    const insertedReentrantly = cacheHas(input);
    if (insertedReentrantly) {
      cacheDelete(input);
      cacheSet(input, transformed);
      if (!structured) structuredDelete(input);
      else structuredAdd(input);
      return transformed;
    }
    if (size >= cacheSize) {
      const keys = cacheKeys();
      const oldest = reflectApply(mapIteratorNext, keys, []) as IteratorResult<string>;
      if (!oldest.done) {
        cacheDelete(oldest.value);
        structuredDelete(oldest.value);
        size -= 1;
      }
    }
    cacheSet(input, transformed);
    if (structured) structuredAdd(input);
    size += 1;
    return transformed;
  };
  const cachedTextTransform = (input: string): string => {
    const hit = cacheGet(input);
    if (hit !== undefined) {
      cacheDelete(input);
      cacheSet(input, hit);
      return hit;
    }
    return store(input, transform(input), false);
  };
  const valueTransform = ((input: string, entities: PIIEntity[]): string => {
    const hit = cacheGet(input);
    if (hit !== undefined && structuredHas(input)) {
      cacheDelete(input);
      cacheSet(input, hit);
      return hit;
    }
    return store(input, transform(input, entities), true);
  }) as ValueTransform;
  defineProperty(valueTransform, "peek", { value: lookup });
  return { text: cachedTextTransform, value: valueTransform };
};

/** Create a reusable text and structured-value protector. */
export const createPiiMasker = (options: PiiMaskerOptions = {}): PiiMasker => {
  const cacheSize = options.cacheSize ?? DEFAULT_CACHE_SIZE;
  if (!Number.isSafeInteger(cacheSize) || cacheSize < 0) {
    throw new RangeError("cacheSize must be a non-negative safe integer");
  }

  const redactOptions = options.mode === "redact" ? resolveRedactOptions(options) : undefined;
  const maskOptions = redactOptions === undefined ? resolveMaskOptions(options) : undefined;
  const base = (input: string, entities?: PIIEntity[]): string => {
    if (redactOptions !== undefined) {
      return entities === undefined
        ? redactDetectedText(input, findPii(input), redactOptions)
        : redactDetectedText(input, entities, redactOptions);
    }
    if (maskOptions === undefined) throw new TypeError("Missing mask options");
    return entities === undefined
      ? maskDetectedText(input, findPii(input), maskOptions)
      : maskDetectedText(input, entities, maskOptions);
  };
  const transforms = withCache(base, cacheSize);

  return {
    text: transforms.text,
    value: <T>(input: T): ProtectedValue<T> =>
      protectValue(input, transforms.value, typeof redactOptions?.replacement === "function"),
  };
};
