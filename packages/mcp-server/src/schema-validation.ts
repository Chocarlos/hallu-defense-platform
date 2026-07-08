import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

export type ContractSchemaName =
  | "claim"
  | "document-ingestion-request"
  | "document-ingestion-response"
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
  "document-ingestion-request",
  "document-ingestion-response",
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

const ajv = new Ajv2020({
  allErrors: true,
  allowUnionTypes: true
});
addFormats(ajv);

for (const name of schemaNames) {
  const schema = JSON.parse(
    readFileSync(path.join(schemaDir, `${name}.schema.json`), "utf8")
  ) as object;
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
