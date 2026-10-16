/** T-42 (6): builds the one-core WASM module with the pinned toolchain and copies it into `dist/`. */
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const TARGET = "wasm32-unknown-unknown";

export const packageRoot = fileURLToPath(new URL("..", import.meta.url));
export const repositoryRoot = join(packageRoot, "..", "..");

/** The Cargo target directory: `CARGO_TARGET_DIR` or the workspace `target/`. */
export function targetDir(): string {
  return process.env["CARGO_TARGET_DIR"] ?? join(repositoryRoot, "target");
}

/** Builds the release module and returns the path of the copy in `dist/`. */
export function buildWasm(): string {
  execFileSync(
    "cargo",
    ["build", "--locked", "--release", "-p", "one-core-wasm", "--target", TARGET],
    { cwd: repositoryRoot, stdio: "inherit" },
  );
  const out = join(packageRoot, "dist");
  mkdirSync(out, { recursive: true });
  const copy = join(out, "one_core.wasm");
  copyFileSync(join(targetDir(), TARGET, "release", "one_core_wasm.wasm"), copy);
  return copy;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  buildWasm();
}
