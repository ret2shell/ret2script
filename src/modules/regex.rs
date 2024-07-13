use std::io;

use regex::Regex;
use rune::{ContextError, Module};

#[rune::module(::ret2api::regex)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let mut module = Module::from_meta(self::module_meta)?;
    module.function_meta(test)?;
    Ok(module)
}

#[rune::function]
pub fn test(pattern: &str, payload: &str) -> Result<bool, io::Error> {
    let re =
        Regex::new(pattern).map_err(|_| io::Error::other("failed to compile regex pattern"))?;
    Ok(re.is_match(payload))
}
