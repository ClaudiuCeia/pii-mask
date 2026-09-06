const environment = Object.fromEntries(
  Object.entries(process.env).filter(([name]) => name.toLowerCase() !== "npm_config_dry_run"),
);

for (const script of ["check", "package:check"]) {
  const child = Bun.spawn(["bun", "run", script], {
    env: environment,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });

  const exitCode = await child.exited;
  if (exitCode !== 0) process.exit(exitCode);
}
