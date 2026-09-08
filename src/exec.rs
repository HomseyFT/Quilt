//! Marshalling argv and envp for `execve`.
//!
//! Both entry paths build these arrays before the point of no return, while
//! allocation is still safe, and hand the raw pointers to `execve`.

use std::ffi::CString;

use crate::error::{Error, Result};

pub fn cstrings(values: &[String]) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|v| {
            CString::new(v.as_str())
                .map_err(|_| Error::msg(format!("argument {v:?} contains a NUL byte")))
        })
        .collect()
}

/// The NULL-terminated pointer array `execve` wants. The `CString`s must
/// outlive it.
pub fn pointer_array(values: &[CString]) -> Vec<*const u8> {
    let mut ptrs: Vec<*const u8> = values.iter().map(|c| c.as_ptr().cast()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}
