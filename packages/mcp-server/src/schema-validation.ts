import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

export type ContractSchemaName =
  | "claim"
  | "claim-verification-request"
  | "claim-verification-response"
  | "document-ingestion-request"
  | "document-ingestion-response"
  | "document-ingestion-status-request"
  | "document-ingestion-status-response"
  | "document-input"
  | "evidence"
  | "evidence-retrieval-request"
  | "evidence-retrieval-response"
  | "policy-evaluation-request"
  | "policy-evaluation-response"
  | "repo-checks-run-request"
  | "verdict"
  | "tool-call-envelope"
  | "tool-validation-response"
  | "sandbox-run"
  | "verification-run-request"
  | "verification-run";

const schemaNames: readonly ContractSchemaName[] = [
  "claim",
  "claim-verification-request",
  "claim-verification-response",
  "document-ingestion-request",
  "document-ingestion-response",
  "document-ingestion-status-request",
  "document-ingestion-status-response",
  "document-input",
  "evidence",
  "evidence-retrieval-request",
  "evidence-retrieval-response",
  "policy-evaluation-request",
  "policy-evaluation-response",
  "repo-checks-run-request",
  "verdict",
  "tool-call-envelope",
  "tool-validation-response",
  "sandbox-run",
  "verification-run-request",
  "verification-run"
];

const schemaDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../contracts/schemas"
);
const require = createRequire(import.meta.url);
const addFormats = require("ajv-formats") as (validator: Ajv2020) => Ajv2020;

export function createContractSchemaValidator(): Ajv2020 {
  const validator = new Ajv2020({
    allErrors: true,
    allowUnionTypes: true,
    strict: true
  });
  addFormats(validator);
  validator.addKeyword({
    keyword: "x-contract-version",
    schemaType: "string",
    valid: true
  });
  return validator;
}

const ajv = createContractSchemaValidator();
const contractSchemas = new Map<ContractSchemaName, Readonly<Record<string, unknown>>>();

for (const name of schemaNames) {
  const schema = JSON.parse(
    readFileSync(path.join(schemaDir, `${name}.schema.json`), "utf8")
  ) as Readonly<Record<string, unknown>>;
  contractSchemas.set(name, schema);
  ajv.addSchema(schema);
}

const validators = new Map<ContractSchemaName, ValidateFunction>();

export class ContractValidationError extends Error {
  readonly code = "CONTRACT_VALIDATION_ERROR" as const;

  constructor(
    readonly schemaName: ContractSchemaName,
    readonly context: string,
    errors: readonly ErrorObject[] | null | undefined
  ) {
    super(`${context} failed ${schemaName} schema validation: ${formatErrors(errors)}`);
    this.name = "ContractValidationError";
  }
}

export function validateContract<T>(
  schemaName: ContractSchemaName,
  value: unknown,
  context: string
): T {
  const validator = validatorFor(schemaName);
  if (!validator(value)) {
    throw new ContractValidationError(schemaName, context, validator.errors);
  }
  return value as T;
}

export function validateContractArray<T>(
  schemaName: ContractSchemaName,
  values: readonly unknown[],
  context: string
): readonly T[] {
  return values.map((value, index) =>
    validateContract<T>(schemaName, value, `${context}[${index}]`)
  );
}

/**
 * Return a self-contained public contract for MCP tool discovery.
 *
 * Public schemas reference sibling contract files. MCP clients receive a single
 * schema object over `tools/list`, so those references must be bundled instead
 * of pointing at the repository-local schema directory.
 */
export function bundledContractSchema(
  schemaName: ContractSchemaName
): Readonly<Record<string, unknown>> {
  const root = contractSchema(schemaName);
  const dependencyNames = collectSchemaDependencies(root);
  const bundledRoot = rewriteSchemaReferences(root, true);
  if (dependencyNames.size === 0) {
    return bundledRoot;
  }
  return {
    ...bundledRoot,
    $defs: Object.fromEntries(
      [...dependencyNames]
        .sort()
        .map((name) => [name, rewriteSchemaReferences(contractSchema(name), true)])
    )
  };
}

function validatorFor(schemaName: ContractSchemaName): ValidateFunction {
  const cached = validators.get(schemaName);
  if (cached !== undefined) {
    return cached;
  }

  const validator = ajv.getSchema(`https://hallu-defense.local/schemas/${schemaName}.schema.json`);
  if (validator === undefined) {
    throw new Error(`Missing JSON Schema validator for ${schemaName}`);
  }
  validators.set(schemaName, validator);
  return validator;
}

function contractSchema(
  schemaName: ContractSchemaName
): Readonly<Record<string, unknown>> {
  const schema = contractSchemas.get(schemaName);
  if (schema === undefined) {
    throw new Error(`Missing JSON Schema for ${schemaName}`);
  }
  return schema;
}

function collectSchemaDependencies(
  root: Readonly<Record<string, unknown>>
): Set<ContractSchemaName> {
  const dependencies = new Set<ContractSchemaName>();
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item);
      }
      return;
    }
    if (!isRecord(value)) {
      return;
    }
    const referencedName = schemaNameFromReference(value.$ref);
    if (referencedName !== undefined && !dependencies.has(referencedName)) {
      dependencies.add(referencedName);
      visit(contractSchema(referencedName));
    }
    for (const [key, child] of Object.entries(value)) {
      if (key !== "$ref") {
        visit(child);
      }
    }
  };
  visit(root);
  return dependencies;
}

function rewriteSchemaReferences(
  value: Readonly<Record<string, unknown>>,
  stripIdentifier: boolean
): Readonly<Record<string, unknown>> {
  const rewritten: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (stripIdentifier && key === "$id") {
      continue;
    }
    if (key === "$ref") {
      const referencedName = schemaNameFromReference(child);
      rewritten[key] =
        referencedName === undefined ? child : `#/$defs/${referencedName}`;
      continue;
    }
    if (Array.isArray(child)) {
      rewritten[key] = child.map((item) => rewriteSchemaValue(item, stripIdentifier));
    } else {
      rewritten[key] = rewriteSchemaValue(child, stripIdentifier);
    }
  }
  return rewritten;
}

function rewriteSchemaValue(value: unknown, stripIdentifier: boolean): unknown {
  return isRecord(value)
    ? rewriteSchemaReferences(value, stripIdentifier)
    : value;
}

function schemaNameFromReference(value: unknown): ContractSchemaName | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const match = /(?:^|\/)([a-z0-9-]+)\.schema\.json$/u.exec(value);
  if (match === null) {
    return undefined;
  }
  const candidate = match[1];
  return schemaNames.includes(candidate as ContractSchemaName)
    ? (candidate as ContractSchemaName)
    : undefined;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatErrors(errors: readonly ErrorObject[] | null | undefined): string {
  if (errors === undefined || errors === null || errors.length === 0) {
    return "unknown validation error";
  }
  return errors
    .slice(0, 5)
    .map((error) => {
      const location = error.instancePath.length > 0 ? error.instancePath : "/";
      if (error.keyword === "required" && "missingProperty" in error.params) {
        return `${location} missing required property '${String(error.params.missingProperty)}'`;
      }
      return `${location} ${error.message ?? error.keyword}`;
    })
    .join("; ");
}
