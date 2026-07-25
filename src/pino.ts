/**
 * Pino integration for automatic PII masking.
 *
 * Wraps Pino's `logMethod` hook to transform every argument before
 * serialization. The masker operates on the raw values, so structured
 * fields and message strings are both protected.
 *
 * @module
 */
import type { LoggerOptions } from "pino";
import { createPiiMasker, type PiiMaskerOptions } from "./index.js";

/** Options accepted by {@link pinoPiiMasking}. Same as {@link PiiMaskerOptions}. */
export type PinoPiiMaskingOptions = PiiMaskerOptions;

/**
 * Create Pino options that protect every argument before Pino serializes it.
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
      logMethod(args, method) {
        Reflect.apply(
          method,
          this,
          args.map((argument) => masker.value(argument)),
        );
      },
    },
  };
};
