use rune::{ContextError, Module};

/// Construct the `ret2api::crypto` module.
#[rune::module(::ret2api::crypto)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let module = Module::from_meta(self::module_meta)?;
    Ok(module)
}
