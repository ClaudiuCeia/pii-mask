import type { LoggerOptions } from "pino";
import { createPiiMasker, type PiiMaskerOptions } from "./index.js";

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
