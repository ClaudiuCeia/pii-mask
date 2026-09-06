import { chmod, copyFile, lstat, mkdir, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const operation = process.argv[2];
if (operation !== "install" && operation !== "uninstall") {
  throw new Error("Usage: bun run scripts/hooks.ts <install|uninstall>");
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const hooksConfig = Bun.spawn(["git", "config", "--get", "core.hooksPath"], {
  cwd: repoRoot,
  stdout: "pipe",
  stderr: "inherit",
});
const configuredHooksPath = (await new Response(hooksConfig.stdout).text()).trim();
const hooksConfigExitCode = await hooksConfig.exited;
if (hooksConfigExitCode === 0) {
  throw new Error(
    `Refusing to manage hooks while core.hooksPath is configured: ${configuredHooksPath || "(empty)"}`,
  );
}
if (hooksConfigExitCode !== 0 && hooksConfigExitCode !== 1) {
  throw new Error("Unable to inspect core.hooksPath");
}

const child = Bun.spawn(["git", "rev-parse", "--git-path", "hooks"], {
  cwd: repoRoot,
  stdout: "pipe",
  stderr: "inherit",
});
const hooksPath = (await new Response(child.stdout).text()).trim();
if ((await child.exited) !== 0 || hooksPath.length === 0) {
  throw new Error("Unable to resolve the Git hooks directory");
}

const hooksDir = isAbsolute(hooksPath) ? hooksPath : resolve(repoRoot, hooksPath);
const source = resolve(repoRoot, "scripts/pre-commit");
const destination = resolve(hooksDir, "pre-commit");
const temporary = resolve(hooksDir, `.pre-commit-${process.pid}-${Date.now()}`);
const destinationExists = await lstat(destination).then(
  () => true,
  (error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return false;
    throw error;
  },
);

if (operation === "install") {
  const expected = await Bun.file(source).text();
  if (destinationExists) {
    const current = await Bun.file(destination).text();
    if (current !== expected) {
      throw new Error(`Refusing to replace an existing hook: ${destination}`);
    }
  }
  await mkdir(hooksDir, { recursive: true });
  try {
    await copyFile(source, temporary);
    await chmod(temporary, 0o755);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
  console.log(`Installed pre-commit hook at ${destination}`);
} else {
  if (destinationExists) {
    const [current, expected] = await Promise.all([
      Bun.file(destination).text(),
      Bun.file(source).text(),
    ]);
    if (current !== expected) {
      throw new Error(`Refusing to remove an unmanaged hook: ${destination}`);
    }
  }
  await rm(destination, { force: true });
  console.log(`Removed pre-commit hook at ${destination}`);
}
