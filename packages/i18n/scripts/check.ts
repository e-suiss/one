/** T-29 (6) checker: every language catalog is one flat JSON object of sorted dotted keys to non-empty ICU MessageFormat strings, and all catalogs share the same keys and the same ICU arguments per key. */
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REQUIRED_LANGUAGES = ["en", "tr"] as const;
const REFERENCE_LANGUAGE = "en";
const KEY_PATTERN = /^[a-z][a-zA-Z0-9]*(?:[._][a-zA-Z0-9]+)*$/;
const SELECT_TYPES = new Set(["plural", "selectordinal", "select"]);

class IcuSyntaxError extends Error {}

/** Collects ICU arguments of a message as "name:type" (type "" for simple arguments). */
export function icuArguments(message: string): Set<string> {
  const found = new Set<string>();
  const end = parseMessage(message, 0, false, found);
  if (end !== message.length) {
    throw new IcuSyntaxError(`unexpected "}" at offset ${String(end)}`);
  }
  return found;
}

function parseMessage(s: string, start: number, nested: boolean, found: Set<string>): number {
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") {
      const next = s[i + 1];
      if (next === "'") {
        i += 2;
      } else if (next === "{" || next === "}" || (nested && next === "#")) {
        const close = s.indexOf("'", i + 1);
        if (close === -1) {
          throw new IcuSyntaxError("unterminated quoted literal");
        }
        i = close + 1;
      } else {
        i += 1;
      }
    } else if (c === "{") {
      i = parseArgument(s, i + 1, found);
    } else if (c === "}") {
      return i;
    } else {
      i += 1;
    }
  }
  return i;
}

function readToken(s: string, start: number): { token: string; end: number } {
  let i = start;
  while (i < s.length && s[i] !== "," && s[i] !== "{" && s[i] !== "}") {
    i += 1;
  }
  return { token: s.slice(start, i).trim(), end: i };
}

function parseArgument(s: string, start: number, found: Set<string>): number {
  const name = readToken(s, start);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name.token)) {
    throw new IcuSyntaxError(`invalid argument name "${name.token}"`);
  }
  if (s[name.end] === "}") {
    found.add(`${name.token}:`);
    return name.end + 1;
  }
  if (s[name.end] !== ",") {
    throw new IcuSyntaxError(`malformed argument "${name.token}"`);
  }
  const type = readToken(s, name.end + 1);
  found.add(`${name.token}:${type.token}`);
  if (s[type.end] === "}") {
    return type.end + 1;
  }
  if (s[type.end] !== ",") {
    throw new IcuSyntaxError(`malformed argument "${name.token}"`);
  }
  if (!SELECT_TYPES.has(type.token)) {
    const close = s.indexOf("}", type.end + 1);
    if (close === -1) {
      throw new IcuSyntaxError(`unterminated argument "${name.token}"`);
    }
    return close + 1;
  }
  let i = type.end + 1;
  let hasOther = false;
  for (;;) {
    while (i < s.length && /\s/.test(s[i] ?? "")) {
      i += 1;
    }
    if (s[i] === "}") {
      if (!hasOther) {
        throw new IcuSyntaxError(`argument "${name.token}" has no "other" case`);
      }
      return i + 1;
    }
    const selector = readToken(s, i);
    if (selector.token === "" || s[selector.end] !== "{") {
      throw new IcuSyntaxError(`malformed case in argument "${name.token}"`);
    }
    if (selector.token.startsWith("offset:")) {
      throw new IcuSyntaxError(`offset must precede a case in argument "${name.token}"`);
    }
    const selectorName = selector.token.split(/\s+/).at(-1) ?? "";
    if (selectorName === "other") {
      hasOther = true;
    }
    const caseEnd = parseMessage(s, selector.end + 1, true, found);
    if (s[caseEnd] !== "}") {
      throw new IcuSyntaxError(`unterminated case in argument "${name.token}"`);
    }
    i = caseEnd + 1;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns every violation across the given catalogs (language -> parsed JSON). */
export function checkCatalogs(catalogs: ReadonlyMap<string, unknown>): string[] {
  const errors: string[] = [];
  const argumentsByLanguage = new Map<string, Map<string, Set<string>>>();

  for (const language of REQUIRED_LANGUAGES) {
    if (!catalogs.has(language)) {
      errors.push(`${language}: catalog is missing`);
    }
  }

  for (const [language, catalog] of catalogs) {
    if (!isRecord(catalog)) {
      errors.push(`${language}: catalog must be a flat JSON object`);
      continue;
    }
    const keys = Object.keys(catalog);
    const sorted = [...keys].sort();
    if (keys.some((key, index) => key !== sorted[index])) {
      errors.push(`${language}: keys are not sorted`);
    }
    const parsed = new Map<string, Set<string>>();
    for (const key of keys) {
      const value = catalog[key];
      if (!KEY_PATTERN.test(key)) {
        errors.push(`${language}: invalid key "${key}"`);
      }
      if (typeof value !== "string") {
        errors.push(`${language}: "${key}" must be a string`);
        continue;
      }
      if (value.trim() === "") {
        errors.push(`${language}: "${key}" is empty`);
        continue;
      }
      try {
        parsed.set(key, icuArguments(value));
      } catch (error: unknown) {
        if (!(error instanceof IcuSyntaxError)) {
          throw error;
        }
        errors.push(`${language}: "${key}" is not valid ICU MessageFormat: ${error.message}`);
      }
    }
    argumentsByLanguage.set(language, parsed);
  }

  const allKeys = new Set<string>();
  for (const catalog of catalogs.values()) {
    if (isRecord(catalog)) {
      for (const key of Object.keys(catalog)) {
        allKeys.add(key);
      }
    }
  }
  const reference = argumentsByLanguage.get(REFERENCE_LANGUAGE);
  for (const [language, catalog] of catalogs) {
    if (!isRecord(catalog)) {
      continue;
    }
    for (const key of [...allKeys].sort()) {
      if (!Object.hasOwn(catalog, key)) {
        errors.push(`${language}: missing key "${key}"`);
      }
    }
    const own = argumentsByLanguage.get(language);
    if (language === REFERENCE_LANGUAGE || reference === undefined || own === undefined) {
      continue;
    }
    for (const [key, expected] of reference) {
      const actual = own.get(key);
      if (actual === undefined) {
        continue;
      }
      const a = [...expected].sort().join(", ");
      const b = [...actual].sort().join(", ");
      if (a !== b) {
        errors.push(
          `${language}: "${key}" ICU arguments differ from ${REFERENCE_LANGUAGE} ([${b}] vs [${a}])`,
        );
      }
    }
  }
  return errors;
}

/** Loads every messages/<language>.json catalog from `directory`. */
export function loadCatalogs(directory: string): Map<string, unknown> {
  const catalogs = new Map<string, unknown>();
  for (const file of readdirSync(directory).sort()) {
    if (file.endsWith(".json")) {
      const text = readFileSync(join(directory, file), "utf8");
      catalogs.set(file.slice(0, -".json".length), JSON.parse(text) as unknown);
    }
  }
  return catalogs;
}

function main(): void {
  const directory = resolve(fileURLToPath(new URL("../messages", import.meta.url)));
  const errors = checkCatalogs(loadCatalogs(directory));
  if (errors.length > 0) {
    for (const error of errors) {
      process.stderr.write(`i18n: ${error}\n`);
    }
    process.exitCode = 1;
    return;
  }
  process.stdout.write("i18n: catalogs are complete and consistent\n");
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
