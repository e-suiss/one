/** T-38 (2): every case of the one-core case file through the WASM module, byte for byte equal to the Rust output. */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { OPERATIONS, OneCore, OneCoreError } from "../src/index.ts";
import { packageRoot, targetDir } from "../scripts/build-wasm.ts";

interface Case {
  readonly name: string;
  readonly op: string;
  readonly input: string;
  readonly output: string;
}

function isCase(value: unknown): value is Case {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const c = value as Record<string, unknown>;
  return ["name", "op", "input", "output"].every((k) => typeof c[k] === "string");
}

function load(): { operations: unknown; cases: Case[] } {
  const path =
    process.env["ONE_CORE_CASES"] ?? join(targetDir(), "tmp", "one-core-differential.json");
  const file: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (typeof file !== "object" || file === null) {
    throw new TypeError(`${path}: not a case file`);
  }
  const { operations, cases } = file as Record<string, unknown>;
  if (!Array.isArray(cases) || !cases.every(isCase)) {
    throw new TypeError(`${path}: malformed cases`);
  }
  return { operations, cases };
}

const core = await OneCore.instantiate(readFileSync(join(packageRoot, "dist", "one_core.wasm")));
const { operations, cases } = load();
const encoder = new TextEncoder();

await test("t_38_wasm_output_is_byte_equal_to_rust_for_every_case", (t) => {
  assert.ok(cases.length > 0);
  const differing = cases
    .filter((c) => {
      const got = core.invoke(c.op, encoder.encode(c.input));
      return Buffer.compare(got, encoder.encode(c.output)) !== 0;
    })
    .map((c) => c.name);
  assert.deepEqual(differing, []);
  t.diagnostic(`wasm: ${String(cases.length)}/${String(cases.length)} cases byte-equal`);
});

await test("t_29_wrapper_operation_list_matches_the_module", () => {
  assert.deepEqual(core.operations(), operations);
  assert.deepEqual(core.operations(), [...OPERATIONS]);
});

await test("t_29_typed_call_returns_the_output_and_throws_the_stable_code", () => {
  assert.deepEqual(core.provenanceAccessMapping({ label: "user.direct" }), {
    provenance: "user",
  });
  assert.throws(
    () => core.provenanceJoin({ inputs: 3 }),
    (e: unknown) =>
      e instanceof OneCoreError && e.code === "invalid_input" && e.detail === "inputs",
  );
});
