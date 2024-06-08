use rune::{ContextError, Module};

/// Construct the `ret2api::crypto` module.
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
  let module = Module::with_crate("ret2api::crypto")?;
  Ok(module)
}