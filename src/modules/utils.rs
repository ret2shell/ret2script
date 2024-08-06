use std::{io, str::FromStr};

use rune::{Any, ContextError, Module};

/// Construct the `ret2api::utils` module.
///
/// ## Usage
///
/// ```rust
///     let mut context = Context::with_default_modules()?;
///     context.install(ret2script::modules::utils::module(true)?)?;
/// ```
#[rune::module(::ret2api::utils)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let mut module = Module::from_meta(self::module_meta)?;
    module.ty::<Flag>()?;
    module.function_meta(Flag::new)?;
    module.function_meta(Flag::parse)?;
    module.function_meta(Flag::with_prefix)?;
    module.function_meta(Flag::prefix)?;
    module.function_meta(Flag::with_content)?;
    module.function_meta(Flag::content)?;
    module.function_meta(Flag::to_string)?;

    module.function_meta(lower)?;
    module.function_meta(upper)?;

    Ok(module)
}

/// Flag construction utils.
#[derive(Any, Debug, Clone)]
#[rune(item = ::ret2api::utils)]
pub struct Flag {
    prefix: String,
    content: String,
}

impl Flag {
    /// construct a new flag instance.
    ///
    /// ```rust
    /// // flag{hello_world}
    /// let flag = Flag::new().with_prefix("flag").with_content("hello_world").to_string();
    /// ```
    #[rune::function(path = Self::new)]
    pub fn new() -> Self {
        Self {
            prefix: "".to_owned(),
            content: "".to_owned(),
        }
    }

    /// parse a flag instance from string.
    ///
    /// ```rust
    /// let flag = Flag::parse("flag{hello_world}");
    /// flag.prefix();  // "flag"
    /// flag.content(); // "hello_world"
    /// ```
    #[rune::function(path = Self::parse)]
    pub fn parse(f: &str) -> Result<Self, io::Error> {
        let f = f.trim();
        let prefix_end = f
            .find('{')
            .ok_or(io::Error::other("flag format is incorrect"))?;
        let prefix: String = f.chars().into_iter().take(prefix_end).collect();
        let content = f.to_owned().replace(&prefix, "");
        if !(content.starts_with("{") && content.ends_with("}")) {
            return Err(io::Error::other("flag format is incorrect"))?;
        }
        let content = String::from_str(&content[1..(content.len() - 1)])
            .map_err(|_| io::Error::other("failed to extract flag content"))?;
        Ok(Self { prefix, content })
    }

    /// get current prefix in flag instance.
    #[rune::function]
    pub fn prefix(&self) -> String {
        self.prefix.clone()
    }

    /// get current content in flag instance.
    #[rune::function]
    pub fn content(&self) -> String {
        self.content.clone()
    }

    /// set prefix in flag instance.
    ///
    /// This function will take original ownership.
    #[rune::function]
    pub fn with_prefix(self, p: &str) -> Self {
        Self {
            prefix: p.to_owned(),
            ..self
        }
    }

    /// set content in flag instance.
    ///
    /// This function will take original ownership.
    #[rune::function]
    pub fn with_content(self, c: &str) -> Self {
        Self {
            content: c.to_owned(),
            ..self
        }
    }

    /// serialize to flag string.
    #[rune::function]
    pub fn to_string(&self) -> String {
        format!("{}{{{}}}", self.prefix, self.content)
    }
}

#[rune::function]
pub fn lower(s: &str) -> String {
    s.to_string().to_lowercase()
}

#[rune::function]
pub fn upper(s: &str) -> String {
    s.to_string().to_uppercase()
}
