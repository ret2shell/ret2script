use rune::{ContextError, Module};

/// Construct the `ret2api::utils` module.
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
  let module = Module::with_crate("ret2api::utils")?;
  Ok(module)
}