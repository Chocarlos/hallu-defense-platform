import { describe, expect, it } from "vitest";

import { createContractSchemaValidator } from "../src/schema-validation.js";

describe("contract schema metadata keyword", () => {
  it("accepts x-contract-version without weakening payload validation", () => {
    const validator = createContractSchemaValidator().compile({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      "x-contract-version": "1.0",
      required: ["name"],
      properties: {
        name: { type: "string" }
      },
      additionalProperties: false
    });

    expect(validator({ name: "valid" })).toBe(true);
    expect(validator({})).toBe(false);
    expect(validator.errors?.[0]?.keyword).toBe("required");
  });

  it("keeps strict mode fail-closed for unknown keyword typos", () => {
    const ajv = createContractSchemaValidator();

    expect(() =>
      ajv.compile({
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        "x-contract-versoin": "1.0"
      })
    ).toThrow(/unknown keyword/u);
  });
});
