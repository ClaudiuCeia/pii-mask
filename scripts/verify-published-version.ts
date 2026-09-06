import { appendFile } from "node:fs/promises";

const [registry, version, expectedCommit, expectedRef, mode] = process.argv.slice(2);
if (
  (registry !== "jsr" && registry !== "npm") ||
  version === undefined ||
  expectedCommit === undefined ||
  expectedRef === undefined ||
  (mode !== undefined && mode !== "--require")
) {
  throw new Error(
    "Usage: bun scripts/verify-published-version.ts <jsr|npm> <version> <commit> <ref> [--require]",
  );
}

const repository = "https://github.com/ClaudiuCeia/pii-mask";
const workflowPath = ".github/workflows/publish-npm.yml";

interface ProvenanceStatement {
  predicate?: {
    buildDefinition?: {
      externalParameters?: {
        workflow?: { path?: string; ref?: string; repository?: string };
      };
      resolvedDependencies?: { digest?: { gitCommit?: string }; uri?: string }[];
    };
  };
}

const verifyStatement = (statement: ProvenanceStatement): void => {
  const build = statement.predicate?.buildDefinition;
  const workflow = build?.externalParameters?.workflow;
  const source = build?.resolvedDependencies?.find(({ uri }) =>
    uri?.startsWith(`git+${repository}@`),
  );

  if (source?.digest?.gitCommit !== expectedCommit) {
    throw new Error(
      `${registry} ${version} provenance points to commit '${source?.digest?.gitCommit ?? "unknown"}', expected '${expectedCommit}'`,
    );
  }
  const expectedSource = `git+${repository}@${expectedRef}`;
  if (source.uri !== expectedSource) {
    throw new Error(
      `${registry} ${version} provenance source is '${source.uri ?? "unknown"}', expected '${expectedSource}'`,
    );
  }
  if (
    workflow?.repository !== repository ||
    workflow.path !== workflowPath ||
    workflow.ref !== expectedRef
  ) {
    throw new Error(
      `${registry} ${version} was not published by ${workflowPath} at ${expectedRef}`,
    );
  }
};

const getJsrStatement = async (): Promise<ProvenanceStatement | undefined> => {
  const response = await fetch(
    `https://api.jsr.io/scopes/claudiu-ceia/packages/pii-mask/versions/${version}`,
  );
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`JSR metadata request failed with HTTP ${response.status}`);

  const metadata = (await response.json()) as { rekorLogId?: string };
  if (metadata.rekorLogId === undefined) {
    throw new Error(`JSR ${version} has no trusted-publishing provenance`);
  }

  const rekorResponse = await fetch(
    `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${metadata.rekorLogId}`,
  );
  if (!rekorResponse.ok) {
    throw new Error(`Rekor request failed with HTTP ${rekorResponse.status}`);
  }
  const entries = Object.values(
    (await rekorResponse.json()) as Record<string, { attestation?: { data?: string } }>,
  );
  const encodedStatement = entries[0]?.attestation?.data;
  if (encodedStatement === undefined) {
    throw new Error(`JSR ${version} provenance statement is missing`);
  }
  return JSON.parse(Buffer.from(encodedStatement, "base64").toString("utf8"));
};

const getNpmStatement = async (): Promise<ProvenanceStatement | undefined> => {
  const metadataResponse = await fetch(
    `https://registry.npmjs.org/@claudiu-ceia%2Fpii-mask/${version}`,
  );
  if (metadataResponse.status === 404) return undefined;
  if (!metadataResponse.ok) {
    throw new Error(`npm metadata request failed with HTTP ${metadataResponse.status}`);
  }

  const metadata = (await metadataResponse.json()) as { gitHead?: string };
  if (metadata.gitHead !== expectedCommit) {
    throw new Error(
      `npm ${version} gitHead is '${metadata.gitHead ?? "unknown"}', expected '${expectedCommit}'`,
    );
  }

  const attestationResponse = await fetch(
    `https://registry.npmjs.org/-/npm/v1/attestations/@claudiu-ceia%2fpii-mask@${version}`,
  );
  if (!attestationResponse.ok) {
    throw new Error(`npm attestation request failed with HTTP ${attestationResponse.status}`);
  }
  const payload = (
    (await attestationResponse.json()) as {
      attestations?: {
        bundle?: { dsseEnvelope?: { payload?: string } };
        predicateType?: string;
      }[];
    }
  ).attestations?.find(({ predicateType }) => predicateType === "https://slsa.dev/provenance/v1")
    ?.bundle?.dsseEnvelope?.payload;
  if (payload === undefined) throw new Error(`npm ${version} SLSA provenance is missing`);
  return JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
};

const statement = registry === "jsr" ? await getJsrStatement() : await getNpmStatement();
const exists = statement !== undefined;
if (statement !== undefined) verifyStatement(statement);
if (!exists && mode === "--require") {
  throw new Error(`${registry} ${version} is not published`);
}

const output = `exists=${exists}\n`;
if (process.env.GITHUB_OUTPUT === undefined) {
  process.stdout.write(output);
} else {
  await appendFile(process.env.GITHUB_OUTPUT, output);
}
