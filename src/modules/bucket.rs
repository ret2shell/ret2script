use std::{
    fs::{read_dir, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use rune::{Any, ContextError, Module};

/// Construct the `ret2api::bucket` module.
#[rune::module(::ret2api::bucket)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let mut module = Module::from_meta(self::module_meta)?;
    module.ty::<Ret2Bucket>()?;
    module.ty::<Ret2File>()?;
    module.function_meta(Ret2Bucket::open)?;
    module.function_meta(Ret2Bucket::list)?;
    module.function_meta(Ret2File::get_bytes)?;
    module.function_meta(Ret2File::get_str)?;
    Ok(module)
}

#[derive(Clone, Debug, Any)]
#[rune(item = ::ret2api::bucket)]
pub struct Ret2Bucket {
    root: PathBuf,
}

#[derive(Debug, Any)]
#[rune(item = ::ret2api::bucket)]
pub struct Ret2File {
    file: File,
}

impl Ret2Bucket {
    pub fn try_new(path: impl AsRef<Path>) -> Result<Self, io::Error> {
        Ok(Self {
            root: path.as_ref().to_owned().canonicalize()?,
        })
    }

    #[rune::function]
    pub fn open(&self, rel_path: &str) -> Result<Ret2File, io::Error> {
        let path = self.root.join(rel_path).to_owned().canonicalize()?;
        if !path.starts_with(&self.root) {
            return Err(io::Error::other("path traversal detected"));
        }
        Ok(Ret2File {
            file: File::open(path)?,
        })
    }

    #[rune::function]
    pub fn list(&self, rel_path: &str) -> Result<Vec<String>, io::Error> {
        let path = self.root.join(rel_path).to_owned().canonicalize()?;
        if !path.starts_with(&self.root) {
            return Err(io::Error::other("path traversal detected"));
        }
        read_dir(path)?
            .map(|res| res.map(|e| e.path().to_string_lossy().to_string()))
            .collect::<Result<Vec<_>, io::Error>>()
    }
}

impl Ret2File {
    #[rune::function]
    pub fn get_bytes(&mut self) -> Result<(Vec<u8>, i64), io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        let size = self.file.read(&mut buf)?;
        Ok((buf, size.try_into().unwrap()))
    }
    #[rune::function]
    pub fn get_str(&mut self) -> Result<(String, i64), io::Error> {
        let mut buf: String = String::new();
        let size = self.file.read_to_string(&mut buf)?;
        Ok((buf, size.try_into().unwrap()))
    }
}
