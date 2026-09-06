import assert from "node:assert/strict";
import process from "node:process";
import pino from "pino";
import winston from "winston";

const version = process.argv[2];
if (version === undefined || !/^\d+\.\d+\.\d+$/.test(version)) {
  throw new Error("Expected a stable package version argument");
}

const packageRoot = `jsr:@claudiu-ceia/pii-mask@${version}`;
const [core, pinoAdapter, winstonAdapter] = await Promise.all([
  import(packageRoot),
  import(`${packageRoot}/pino`),
  import(`${packageRoot}/winston`),
]);

assert.equal(core.maskText("Email jane@example.com"), "Email ****************");

const pinoLines: string[] = [];
const pinoLogger = pino(
  { ...pinoAdapter.pinoPiiMasking({ mode: "redact" }), base: null, timestamp: false },
  { write: (line: string) => pinoLines.push(line) },
);
pinoLogger.info({ email: "jane@example.com" }, "Request from 192.168.0.1");
assert.deepEqual(JSON.parse(pinoLines[0] ?? "{}"), {
  level: 30,
  email: "[REDACTED]",
  msg: "Request from [REDACTED]",
});

const winstonEntries: Record<PropertyKey, unknown>[] = [];
const capture = winston.format((info) => {
  winstonEntries.push(info);
  return info;
});
const winstonLogger = winston.createLogger({
  format: winston.format.combine(winstonAdapter.winstonPiiMasking({ mode: "redact" }), capture()),
  transports: [new winston.transports.Console({ silent: true })],
});
winstonLogger.info("Email jane@example.com", { ip: "192.168.0.1" });
assert.equal(winstonEntries[0]?.message, "Email [REDACTED]");
assert.equal(winstonEntries[0]?.ip, "[REDACTED]");
