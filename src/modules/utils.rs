use rune::{ContextError, Module};

/// Construct the `ret2api::utils` module.
#[rune::module(::ret2api::utils)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let module = Module::from_meta(self::module_meta)?;
    Ok(module)
}

