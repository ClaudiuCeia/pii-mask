import { rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

const result = await Bun.build({
  entrypoints: ["src/index.ts", "src/pino.ts", "src/winston.ts"],
  outdir: "dist",
  target: "node",
  format: "esm",
  packages: "external",
  sourcemap: "external",
  naming: "[dir]/[name].js",
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}

const declarations = Bun.spawnSync(["bunx", "tsc", "--project", "tsconfig.build.json"]);

if (!declarations.success) {
  process.stderr.write(declarations.stderr);
  process.exit(declarations.exitCode);
}
