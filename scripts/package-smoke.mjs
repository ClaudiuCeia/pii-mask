import assert from "node:assert/strict";

import { maskText, redactText } from "@claudiu-ceia/pii-mask";

const modes = new Set(process.argv.slice(2));

assert.equal(maskText("Email jane@example.com"), "Email ****************");
assert.equal(redactText("IP 192.168.0.1"), "IP [REDACTED]");

if (modes.has("pino")) {
  const [{ default: pino }, { pinoPiiMasking }] = await Promise.all([
    import("pino"),
    import("@claudiu-ceia/pii-mask/pino"),
  ]);
  const lines = [];
  const logger = pino(
    {
      ...pinoPiiMasking({ mode: "redact" }),
      base: { owner: "base@example.com" },
      timestamp: false,
      mixin: () => ({ requester: "mixin@example.com" }),
      msgPrefix: "prefix@example.com ",
      serializers: {
        account: () => ({ email: "serializer@example.com" }),
      },
    },
    { write: (line) => lines.push(line) },
  ).child({ client: "child@example.com" });
  logger.setBindings({ actor: "actor@example.com" });
  logger.info({ account: "safe", id: 9_007_199_254_740_993n }, "Request from 192.168.0.1");
  assert.match(lines[0], /"id":9007199254740993/);
  assert.deepEqual(JSON.parse(lines[0]), {
    level: 30,
    owner: "[REDACTED]",
    client: "[REDACTED]",
    actor: "[REDACTED]",
    requester: "[REDACTED]",
    account: { email: "[REDACTED]" },
    id: 9_007_199_254_740_992,
    msg: "[REDACTED] Request from [REDACTED]",
  });
}

if (modes.has("winston")) {
  const [{ default: winston }, { winstonPiiMasking }] = await Promise.all([
    import("winston"),
    import("@claudiu-ceia/pii-mask/winston"),
  ]);
  const entries = [];
  const capture = winston.format((info) => {
    entries.push(info);
    return info;
  });
  const logger = winston.createLogger({
    format: winston.format.combine(winstonPiiMasking({ mode: "redact" }), capture()),
    transports: [new winston.transports.Console({ silent: true })],
  });
  logger.info("Email jane@example.com", { ip: "192.168.0.1" });
  assert.equal(entries[0].message, "Email [REDACTED]");
  assert.equal(entries[0].ip, "[REDACTED]");
}
