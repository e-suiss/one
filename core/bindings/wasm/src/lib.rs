//! The raw C-ABI of one-core for `wasm32-unknown-unknown`: the host allocates input buffers with `one_alloc`, calls `one_call` and reads the packed result `(pointer << 32) | length`, and frees every buffer with `one_dealloc` (T-16 (1), T-28 (3)).

use core::{ptr, slice};

fn pack(output: Vec<u8>) -> u64 {
    let len = output.len();
    let raw = Box::into_raw(output.into_boxed_slice());
    let addr = raw.cast::<u8>().expose_provenance();
    if let (Ok(addr), Ok(len)) = (u32::try_from(addr), u32::try_from(len)) {
        u64::from(addr).wrapping_shl(32) | u64::from(len)
    } else {
        // SAFETY: `raw` was produced by `Box::into_raw` above and is not shared.
        drop(unsafe { Box::from_raw(raw) });
        0
    }
}

/// # Safety
/// `data` is null or points to `len` readable bytes that stay valid for `'a`.
unsafe fn bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at the non-null `data`.
        unsafe { slice::from_raw_parts(data, len) }
    }
}

/// Allocates `len` zeroed bytes for the host to write an operation name or an input into; null for zero bytes.
// SAFETY: `one_alloc` is the only symbol with this name in the module.
#[unsafe(no_mangle)]
pub extern "C" fn one_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return ptr::null_mut();
    }
    let data = Box::into_raw(vec![0_u8; len].into_boxed_slice()).cast::<u8>();
    let _ = data.expose_provenance();
    data
}

/// Frees a buffer from [`one_alloc`] or a result of [`one_call`] or [`one_operations`].
///
/// # Safety
/// `data` and `len` describe one live buffer this module handed out, and it is freed once.
// SAFETY: `one_dealloc` is the only symbol with this name in the module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn one_dealloc(data: *mut u8, len: usize) {
    if data.is_null() || len == 0 {
        return;
    }
    let data = ptr::with_exposed_provenance_mut::<u8>(data.addr());
    // SAFETY: the caller passes the pointer and length of one live boxed slice of this module.
    drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(data, len)) });
}

/// Runs the operation named by the UTF-8 bytes at `op` on the JSON bytes at `input` and returns the packed canonical envelope of [`one_core::invoke`]; 0 only when the result does not fit the packing.
///
/// # Safety
/// `op` and `input` are null or point to `op_len` and `input_len` readable bytes.
// SAFETY: `one_call` is the only symbol with this name in the module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn one_call(
    op: *const u8,
    op_len: usize,
    input: *const u8,
    input_len: usize,
) -> u64 {
    // SAFETY: the caller guarantees `op_len` readable bytes at `op`.
    let op = unsafe { bytes(op, op_len) };
    // SAFETY: the caller guarantees `input_len` readable bytes at `input`.
    let input = unsafe { bytes(input, input_len) };
    let name = core::str::from_utf8(op).unwrap_or_default();
    pack(one_core::invoke(name, input))
}

/// Returns the packed canonical JSON array of every operation name.
// SAFETY: `one_operations` is the only symbol with this name in the module.
#[unsafe(no_mangle)]
pub extern "C" fn one_operations() -> u64 {
    pack(one_core::operations_json())
}
