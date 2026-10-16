/** T-16 (1), T-29 (1): the TypeScript face of one-core; every rule runs in the WASM module and this wrapper only moves bytes. */

/** Every facade operation name, in the order of `one_core::Operation::ALL`. */
export const OPERATIONS = [
  "provenance.join",
  "provenance.transform",
  "provenance.open",
  "provenance.access_mapping",
  "task.derive",
  "task.project",
  "interaction.resolve_kind",
  "interaction.project",
  "interaction.process_responses",
  "capability.parse_name",
  "capability.parse_version",
  "capability.negotiate",
  "memory.trust_v1",
  "memory.text_view",
  "attention.decide",
  "attention.relay_mapping",
] as const;

/** A facade operation name. */
export type Operation = (typeof OPERATIONS)[number];

/** A JSON value as the facade reads and writes it. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** The stable error codes of `one_core::CoreError`. */
export type CoreErrorCode = "unknown_operation" | "invalid_json" | "invalid_input";

/** The facade could not run an operation. */
export class OneCoreError extends Error {
  /** The stable code. */
  readonly code: CoreErrorCode;
  /** The part of the input that did not match, for `invalid_input`. */
  readonly detail: string | undefined;

  constructor(code: CoreErrorCode, detail: string | undefined) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = "OneCoreError";
    this.code = code;
    this.detail = detail;
  }
}

interface Exports {
  readonly memory: WebAssembly.Memory;
  one_alloc(len: number): number;
  one_dealloc(ptr: number, len: number): void;
  one_call(opPtr: number, opLen: number, inPtr: number, inLen: number): bigint;
  one_operations(): bigint;
}

function exportsOf(instance: WebAssembly.Instance): Exports {
  const e = instance.exports;
  const memory = e["memory"];
  const fns = ["one_alloc", "one_dealloc", "one_call", "one_operations"] as const;
  if (!(memory instanceof WebAssembly.Memory) || fns.some((n) => typeof e[n] !== "function")) {
    throw new TypeError("not the one-core WASM module");
  }
  return e as unknown as Exports;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCode(value: unknown): value is CoreErrorCode {
  return value === "unknown_operation" || value === "invalid_json" || value === "invalid_input";
}

/** One instantiated one-core module. */
export class OneCore {
  readonly #exports: Exports;

  private constructor(exports: Exports) {
    this.#exports = exports;
  }

  /** Instantiates the module from its bytes or a compiled module; the module has no imports. */
  static async instantiate(source: BufferSource | WebAssembly.Module): Promise<OneCore> {
    const instance =
      source instanceof WebAssembly.Module
        ? await WebAssembly.instantiate(source, {})
        : (await WebAssembly.instantiate(source, {})).instance;
    return new OneCore(exportsOf(instance));
  }

  #write(bytes: Uint8Array): number {
    if (bytes.length === 0) {
      return 0;
    }
    const ptr = this.#exports.one_alloc(bytes.length) >>> 0;
    new Uint8Array(this.#exports.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  #take(packed: bigint): Uint8Array {
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xffff_ffffn);
    if (ptr === 0) {
      throw new RangeError("one-core result does not fit the 32-bit packing");
    }
    const out = new Uint8Array(this.#exports.memory.buffer, ptr, len).slice();
    this.#exports.one_dealloc(ptr, len);
    return out;
  }

  /** Runs `operation` on the JSON bytes `input` and returns the canonical envelope bytes `{"ok": …}` or `{"error": …}`; the bytes the differential tests compare (T-38 (2)). */
  invoke(operation: string, input: Uint8Array): Uint8Array {
    const op = encoder.encode(operation);
    const opPtr = this.#write(op);
    const inPtr = this.#write(input);
    try {
      return this.#take(this.#exports.one_call(opPtr, op.length, inPtr, input.length));
    } finally {
      this.#exports.one_dealloc(opPtr, op.length);
      this.#exports.one_dealloc(inPtr, input.length);
    }
  }

  /** Runs `operation` on `input` and returns its output; throws {@link OneCoreError}. */
  call(operation: Operation, input: Json): Json {
    const envelope: unknown = JSON.parse(
      decoder.decode(this.invoke(operation, encoder.encode(JSON.stringify(input)))),
    );
    if (isRecord(envelope) && "ok" in envelope) {
      return envelope["ok"] as Json;
    }
    const error = isRecord(envelope) ? envelope["error"] : undefined;
    if (isRecord(error) && isCode(error["code"])) {
      const detail = error["detail"];
      throw new OneCoreError(error["code"], typeof detail === "string" ? detail : undefined);
    }
    throw new TypeError("malformed one-core envelope");
  }

  /** The operation names the module knows, in its order. */
  operations(): string[] {
    const names: unknown = JSON.parse(decoder.decode(this.#take(this.#exports.one_operations())));
    if (!Array.isArray(names) || !names.every((n) => typeof n === "string")) {
      throw new TypeError("malformed one-core operation list");
    }
    return names;
  }

  /** `provenance.join` (SEC-14 (1)). */
  provenanceJoin(input: Json): Json {
    return this.call("provenance.join", input);
  }

  /** `provenance.transform` (SEC-14 (1), T-36 (3)). */
  provenanceTransform(input: Json): Json {
    return this.call("provenance.transform", input);
  }

  /** `provenance.open` (T-36 (4)). */
  provenanceOpen(input: Json): Json {
    return this.call("provenance.open", input);
  }

  /** `provenance.access_mapping` (T-36 (5)). */
  provenanceAccessMapping(input: Json): Json {
    return this.call("provenance.access_mapping", input);
  }

  /** `task.derive` (CP-3, INV-30). */
  taskDerive(input: Json): Json {
    return this.call("task.derive", input);
  }

  /** `task.project` (CP-3, C-27). */
  taskProject(input: Json): Json {
    return this.call("task.project", input);
  }

  /** `interaction.resolve_kind` (X-12, C-7). */
  interactionResolveKind(input: Json): Json {
    return this.call("interaction.resolve_kind", input);
  }

  /** `interaction.project` (X-13). */
  interactionProject(input: Json): Json {
    return this.call("interaction.project", input);
  }

  /** `interaction.process_responses` (X-22, C-26). */
  interactionProcessResponses(input: Json): Json {
    return this.call("interaction.process_responses", input);
  }

  /** `capability.parse_name` (CP-15). */
  capabilityParseName(input: Json): Json {
    return this.call("capability.parse_name", input);
  }

  /** `capability.parse_version` (CP-15). */
  capabilityParseVersion(input: Json): Json {
    return this.call("capability.parse_version", input);
  }

  /** `capability.negotiate` (CP-15). */
  capabilityNegotiate(input: Json): Json {
    return this.call("capability.negotiate", input);
  }

  /** `memory.trust_v1` (M-13). */
  memoryTrustV1(input: Json): Json {
    return this.call("memory.trust_v1", input);
  }

  /** `memory.text_view` (M-6, INV-14). */
  memoryTextView(input: Json): Json {
    return this.call("memory.text_view", input);
  }

  /** `attention.decide` (AT-1). */
  attentionDecide(input: Json): Json {
    return this.call("attention.decide", input);
  }

  /** `attention.relay_mapping` (AT-42). */
  attentionRelayMapping(input: Json): Json {
    return this.call("attention.relay_mapping", input);
  }
}
