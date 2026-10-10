/** The one shared ESLint flat configuration for every One TypeScript package; packages re-export it without overriding rules. */
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import jsxA11y from "eslint-plugin-jsx-a11y";
import globals from "globals";
import tseslint from "typescript-eslint";

const RAW_HTML = "T-29 (3): raw HTML injection is banned.";
const BROWSER_STORAGE = "T-29 (3): browser storage is banned; session tokens never go there.";

const storageGlobals = ["localStorage", "sessionStorage", "indexedDB"];
const storageOwners = ["window", "globalThis", "self"];

export default defineConfig(
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/node_modules/**", "**/generated/**"],
  },
  {
    linterOptions: {
      reportUnusedDisableDirectives: "error",
    },
  },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
      },
      globals: { ...globals.es2024 },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": [
        "error",
        { fixToUnknown: false, ignoreRestArgs: false },
      ],
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "@typescript-eslint/no-implied-eval": "error",
      "no-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-restricted-globals": [
        "error",
        ...storageGlobals.map((name) => ({ name, message: BROWSER_STORAGE })),
      ],
      "no-restricted-properties": [
        "error",
        ...storageOwners.flatMap((object) =>
          storageGlobals.map((property) => ({ object, property, message: BROWSER_STORAGE })),
        ),
        { object: "document", property: "write", message: RAW_HTML },
        { object: "document", property: "writeln", message: RAW_HTML },
        { property: "innerHTML", message: RAW_HTML },
        { property: "outerHTML", message: RAW_HTML },
        { property: "insertAdjacentHTML", message: RAW_HTML },
        { property: "createContextualFragment", message: RAW_HTML },
      ],
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: RAW_HTML },
        { selector: "Property[key.name='dangerouslySetInnerHTML']", message: RAW_HTML },
      ],
    },
  },
  {
    files: ["**/*.jsx", "**/*.tsx"],
    extends: [jsxA11y.flatConfigs.strict],
    languageOptions: {
      globals: { ...globals.browser },
    },
  },
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
