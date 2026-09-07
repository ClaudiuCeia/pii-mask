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

/** Options accepted by {@link winstonPiiMasking}. Same as {@link PiiMaskerOptions}. */
export type WinstonPiiMaskingOptions = PiiMaskerOptions;

const isTransformableInfo = (value: unknown): value is Logform.TransformableInfo =>
  typeof value === "object" &&
  value !== null &&
  "level" in value &&
  typeof value.level === "string" &&
  "message" in value;

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
    const protectedInfo = masker.value(info);
    return isTransformableInfo(protectedInfo) ? protectedInfo : false;
  })();
};
