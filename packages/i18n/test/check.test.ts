import { expect, test } from "vitest";

import { fileURLToPath } from "node:url";

import { checkCatalogs, icuArguments, loadCatalogs } from "../scripts/check.ts";

test("t_29_missing_key_is_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { "app.name": "One", "app.title": "Title" }],
      ["tr", { "app.name": "One" }],
    ]),
  );
  expect(errors).toEqual(['tr: missing key "app.title"']);
});

test("t_29_missing_language_is_rejected", () => {
  const errors = checkCatalogs(new Map<string, unknown>([["en", { "app.name": "One" }]]));
  expect(errors).toEqual(["tr: catalog is missing"]);
});

test("t_29_empty_value_is_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { "app.name": "One" }],
      ["tr", { "app.name": " " }],
    ]),
  );
  expect(errors).toEqual(['tr: "app.name" is empty']);
});

test("t_29_unsorted_keys_are_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { b: "B", a: "A" }],
      ["tr", { a: "A", b: "B" }],
    ]),
  );
  expect(errors).toEqual(["en: keys are not sorted"]);
});

test("t_29_placeholder_mismatch_is_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { "inbox.count": "{count, plural, one {# item} other {# items}}" }],
      ["tr", { "inbox.count": "{total, plural, other {# öğe}}" }],
    ]),
  );
  expect(errors).toHaveLength(1);
  expect(errors[0]).toMatch(/ICU arguments differ/);
});

test("t_29_icu_arguments_are_collected", () => {
  expect(
    [...icuArguments("Hi {name}, '{literal}' {n, plural, other {{n, number} by {who}}}")].sort(),
  ).toEqual(["n:number", "n:plural", "name:", "who:"]);
  expect(() => icuArguments("{n, plural, one {x}}")).toThrow();
  expect(() => icuArguments("unbalanced }")).toThrow();
});

test("t_29_non_string_value_is_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { "app.name": "One" }],
      ["tr", { "app.name": { nested: "One" } }],
    ]),
  );
  expect(errors).toEqual(['tr: "app.name" must be a string']);
});

test("t_29_invalid_icu_is_rejected", () => {
  const errors = checkCatalogs(
    new Map<string, unknown>([
      ["en", { "app.name": "{n, plural, one {x}}" }],
      ["tr", { "app.name": "{n, plural, one {x}}" }],
    ]),
  );
  expect(errors).toHaveLength(2);
});

test("t_29_shipped_catalogs_are_consistent", () => {
  const directory = fileURLToPath(new URL("../messages", import.meta.url));
  expect(checkCatalogs(loadCatalogs(directory))).toEqual([]);
});
