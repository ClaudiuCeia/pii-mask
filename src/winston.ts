/**
 * Winston integration for automatic PII masking.
 *
 * Returns a {@link Logform.Format} that scans every log entry's `message`
 * and metadata fields before downstream formats like `json()` serialise it.
 *
 * @module
 */
import winston, { type Logform } from "winston";
import { createPiiMasker, type PiiMaskerOptions } from "./index.js";

const createObject = Object.create;
const defineProperties = Object.defineProperties;
const defineProperty = Object.defineProperty;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const ownKeys = Reflect.ownKeys;

/** Options accepted by {@link winstonPiiMasking}. Same as {@link PiiMaskerOptions}. */
export type WinstonPiiMaskingOptions = PiiMaskerOptions;

interface TransformableFields {
  info: Logform.TransformableInfo;
  level: string;
  message: unknown;
}

const readTransformableInfo = (value: unknown): TransformableFields | undefined => {
  if (typeof value !== "object" || value === null || !("level" in value) || !("message" in value)) {
    return undefined;
  }

  const level = value.level;
  if (typeof level !== "string") return undefined;
  return { info: value as Logform.TransformableInfo, level, message: value.message };
};

const restoreRequiredInfo = (
  protectedInfo: object,
  level: string,
  message: unknown,
): Logform.TransformableInfo => {
  const result = createObject(null) as Record<PropertyKey, unknown>;
  for (const key of ownKeys(protectedInfo)) {
    if (key === "level" || key === "message") continue;

    const descriptor = getOwnPropertyDescriptor(protectedInfo, key);
    if (descriptor?.enumerable && "value" in descriptor) {
      defineProperty(result, key, descriptor);
    }
  }
  defineProperties(result, {
    level: { configurable: true, enumerable: true, value: level, writable: true },
    message: { configurable: true, enumerable: true, value: message, writable: true },
  });
  return result as unknown as Logform.TransformableInfo;
};

/**
 * Create a Winston format that protects the message and structured metadata.
 * Place it before finalizing formats such as `json()` or `simple()`.
 *
 * @example
 * ```ts
 * import winston from "winston";
 * import { winstonPiiMasking } from "@claudiu-ceia/pii-mask/winston";
 *
 * const logger = winston.createLogger({
 *   format: winston.format.combine(winstonPiiMasking(), winston.format.json()),
 * });
 * ```
 */
export const winstonPiiMasking = (options: WinstonPiiMaskingOptions = {}): Logform.Format => {
  const masker = createPiiMasker(options);
  return winston.format((info) => {
    const original = readTransformableInfo(info);
    if (original === undefined) return false;

    const protectedInfo = masker.value(info);
    const protectedFields = readTransformableInfo(protectedInfo);
    if (protectedFields !== undefined) {
      const levelDescriptor = getOwnPropertyDescriptor(protectedInfo, "level");
      const messageDescriptor = getOwnPropertyDescriptor(protectedInfo, "message");
      if (levelDescriptor?.enumerable && messageDescriptor?.enumerable) {
        return protectedFields.info;
      }
      return restoreRequiredInfo(
        protectedFields.info,
        protectedFields.level,
        protectedFields.message,
      );
    }
    if (typeof protectedInfo !== "object" || protectedInfo === null) return false;
    return restoreRequiredInfo(
      protectedInfo,
      masker.text(original.level),
      masker.value(original.message),
    );
  })();
};
