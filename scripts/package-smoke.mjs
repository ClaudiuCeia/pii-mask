import assert from "node:assert/strict";

import { maskText, redactText } from "../dist/index.js";
import { pinoPiiMasking } from "../dist/pino.js";
import { winstonPiiMasking } from "../dist/winston.js";

assert.equal(maskText("Email jane@example.com"), "Email ****************");
assert.equal(redactText("IP 192.168.0.1"), "IP [REDACTED]");
assert.equal(typeof pinoPiiMasking().hooks?.logMethod, "function");
assert.equal(typeof winstonPiiMasking().transform, "function");
