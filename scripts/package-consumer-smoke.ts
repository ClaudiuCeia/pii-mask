import { chmod, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tempDir = await mkdtemp(join(tmpdir(), "pii-mask-consumer-"));
const runtimeOnly = process.argv.includes("--runtime-only");

const run = async (command: string[], cwd: string): Promise<void> => {
  const child = Bun.spawn(command, {
    cwd,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(`${command.join(" ")} exited with ${exitCode}`);
};

const capture = async (command: string[], cwd: string): Promise<string> => {
  const child = Bun.spawn(command, { cwd, stdout: "pipe", stderr: "inherit" });
  const output = await new Response(child.stdout).text();
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(`${command.join(" ")} exited with ${exitCode}`);
  return output.trim();
};

interface ConsumerOptions {
  manager: "bun" | "npm";
  modes: ("core" | "pino" | "winston")[];
  name: string;
  peers?: string[];
  runtimes: ("bun" | "node")[];
  typecheck?: boolean;
}

const createConsumer = async (
  tarball: string,
  { manager, modes, name, peers = [], runtimes, typecheck = false }: ConsumerOptions,
): Promise<void> => {
  const consumerDir = join(tempDir, name);
  await mkdir(consumerDir);
  await writeFile(
    join(consumerDir, "package.json"),
    `${JSON.stringify({ name: `pii-mask-${name}`, private: true, type: "module" }, null, 2)}\n`,
  );

  const packages = [tarball, ...peers, ...(typecheck ? ["@types/node@24"] : [])];
  if (manager === "npm") {
    await run(
      [
        "npm",
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--save-exact",
        ...packages,
      ],
      consumerDir,
    );
    await run(["npm", "ls", "--all"], consumerDir);
  } else {
    await run(["bun", "add", "--ignore-scripts", "--exact", ...packages], consumerDir);
  }

  await copyFile(
    join(repoRoot, "scripts/package-smoke.mjs"),
    join(consumerDir, "package-smoke.mjs"),
  );
  for (const runtime of runtimes) {
    await run([runtime, "package-smoke.mjs", ...modes], consumerDir);
  }

  if (typecheck) {
    const imports = [
      'import { maskText, redactValue, type ProtectedValue } from "@claudiu-ceia/pii-mask";',
      'const masked: string = maskText("jane@example.com");',
      "type Equal<Left, Right> = (<Value>() => Value extends Left ? 1 : 2) extends (<Value>() => Value extends Right ? 1 : 2) ? true : false;",
      'const protectedText = redactValue("jane@example.com" as const);',
      "const textType: Equal<typeof protectedText, string> = true;",
      'const protectedRecord: ProtectedValue<{ readonly email: "jane@example.com" }> = redactValue({ email: "jane@example.com" } as const);',
      "const recordType: Equal<typeof protectedRecord, { readonly email?: string }> = true;",
      "void textType;",
      "void recordType;",
    ];
    if (modes.includes("pino")) {
      imports.push(
        'import { pinoPiiMasking } from "@claudiu-ceia/pii-mask/pino";',
        'const pinoOptions: import("pino").LoggerOptions = pinoPiiMasking();',
      );
    }
    if (modes.includes("winston")) {
      imports.push(
        'import { winstonPiiMasking } from "@claudiu-ceia/pii-mask/winston";',
        'const winstonFormat: import("winston").Logform.Format = winstonPiiMasking();',
      );
    }
    await writeFile(join(consumerDir, "consumer.ts"), `${imports.join("\n")}\n`);
    await run(
      [
        "node",
        join(repoRoot, "node_modules/typescript/bin/tsc"),
        "--noEmit",
        "--strict",
        "--module",
        "NodeNext",
        "--moduleResolution",
        "NodeNext",
        "--target",
        "ES2024",
        "consumer.ts",
      ],
      consumerDir,
    );
  }
};

try {
  const tarballName = await capture(
    ["bun", "pm", "pack", "--destination", tempDir, "--ignore-scripts", "--quiet"],
    repoRoot,
  );
  const tarball = join(tempDir, basename(tarballName));
  const packageJson = await Bun.file(join(repoRoot, "package.json")).json();
  const currentPeers = [
    `pino@${packageJson.devDependencies.pino}`,
    `winston@${packageJson.devDependencies.winston}`,
  ];

  if (!runtimeOnly) {
    await createConsumer(tarball, {
      name: "npm-core",
      manager: "npm",
      modes: ["core"],
      runtimes: ["bun", "node"],
      typecheck: true,
    });
    await createConsumer(tarball, {
      name: "bun-current",
      manager: "bun",
      peers: currentPeers,
      modes: ["core", "pino", "winston"],
      runtimes: ["bun", "node"],
      typecheck: true,
    });
    await createConsumer(tarball, {
      name: "npm-pino-min",
      manager: "npm",
      peers: ["pino@10.0.0"],
      modes: ["core", "pino"],
      runtimes: ["node"],
      typecheck: true,
    });
    await createConsumer(tarball, {
      name: "npm-winston-min",
      manager: "npm",
      peers: ["winston@3.3.0"],
      modes: ["core", "winston"],
      runtimes: ["node"],
      typecheck: true,
    });
  }

  await createConsumer(tarball, {
    name: "npm-current",
    manager: "npm",
    peers: currentPeers,
    modes: ["core", "pino", "winston"],
    runtimes: ["bun", "node"],
    typecheck: !runtimeOnly,
  });
} finally {
  await chmod(tempDir, 0o700).catch(() => undefined);
  await rm(tempDir, { recursive: true, force: true });
}
