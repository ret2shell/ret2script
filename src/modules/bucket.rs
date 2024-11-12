use std::{
  fs::{read_dir, File as StdFile},
  io::{self, Read},
  path::{Path, PathBuf},
};

use rune::{Any, ContextError, Module};

/// Construct the `ret2api::bucket` module.
///
/// ## Usage
///
/// ```rust
///     let mut context = Context::with_default_modules()?;
///     context.install(ret2script::modules::bucket::module(true)?)?;
/// ```
///
/// ## Examples
///
/// ```rust
/// pub fn check(bucket, ...) {
///   let files = bucket.list(".")?; // get current directory files.
///   let file = bucket.open("flag.txt")?; // get a file object.
///   let (flag, flag_len) = file.get_str()?; // get file content as string.
///   let (bin, bin_len) = bucket.open("flag.png")?.get_bytes()?; // get file content as bytes
/// }
///
/// ## Limitations
///
/// Bucket instance could not constructed from rune script, it must be constructed in Rust and
/// passed to rune functions.
///
/// For security reasons, bucket has builtin path traversal detections, any read operation that
/// exlude bucket root will be treated as error.
/// ```
#[rune::module(::ret2api::bucket)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
  let mut module = Module::from_meta(self::module_meta)?;
  module.ty::<Bucket>()?;
  module.ty::<File>()?;
  module.function_meta(Bucket::open)?;
  module.function_meta(Bucket::list)?;
  module.function_meta(Bucket::mapped)?;
  module.function_meta(File::get_bytes)?;
  module.function_meta(File::get_str)?;
  Ok(module)
}

/// the bucket instance.
#[derive(Clone, Debug, Any)]
#[rune(item = ::ret2api::bucket)]
pub struct Bucket {
  root: PathBuf,
}

/// the file instance.
#[derive(Debug, Any)]
#[rune(item = ::ret2api::bucket)]
pub struct File {
  name: String,
  file: StdFile,
}

impl Bucket {
  /// init a new bucket instance, the path in args defines bucket root, any file
  /// operation in this bucket must under the root path.
  pub fn try_new(path: impl AsRef<Path>) -> Result<Self, io::Error> {
    Ok(Self {
      root: path.as_ref().to_owned().canonicalize()?,
    })
  }

  /// open a file in bucket, returns file object.
  #[rune::function]
  pub fn open(&self, rel_path: &str) -> Result<File, io::Error> {
    let path = self.root.join(rel_path).to_owned().canonicalize()?;
    if !path.starts_with(&self.root) {
      return Err(io::Error::other("path traversal detected"));
    }
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    Ok(File {
      name,
      file: StdFile::open(path)?,
    })
  }

  fn _list(&self, rel_path: &str) -> Result<Vec<String>, io::Error> {
    let path = self.root.join(rel_path).to_owned().canonicalize()?;
    if !path.starts_with(&self.root) {
      return Err(io::Error::other("path traversal detected"));
    }
    let mut result = read_dir(path)?
      .map(|res| res.map(|e| e.path().to_string_lossy().to_string()))
      .collect::<Result<Vec<_>, io::Error>>()?;
    result.sort();
    Ok(result)
  }

  /// list files and folders in subfolder.
  #[rune::function]
  pub fn list(&self, rel_path: &str) -> Result<Vec<String>, io::Error> {
    self._list(rel_path)
  }

  #[rune::function]
  pub fn mapped(&self, rel_path: &str, request_id: i64) -> Result<String, io::Error> {
    let path = self.root.join(rel_path).to_owned().canonicalize()?;
    if !path.starts_with(&self.root) {
      return Err(io::Error::other("path traversal detected"));
    }
    let mut result = read_dir(path)?
      .map(|res| res.map(|e| e.file_name().to_string_lossy().to_string()))
      .collect::<Result<Vec<_>, io::Error>>()?;
    result.sort();
    let mapped_id = request_id as usize % result.len();
    Ok(result[mapped_id].clone())
  }
}

impl File {
  /// read a file into bytes, returns file content and file length in bytes.
  #[rune::function]
  pub fn get_bytes(&mut self) -> Result<(Vec<u8>, i64), io::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let size = self.file.read(&mut buf)?;
    Ok((buf, size.try_into().unwrap()))
  }

  /// read a file into string, returns file content and content length.
  #[rune::function]
  pub fn get_str(&mut self) -> Result<(String, i64), io::Error> {
    let mut buf: String = String::new();
    let size = self.file.read_to_string(&mut buf)?;
    Ok((buf, size.try_into().unwrap()))
  }

  /// get file name.
  #[rune::function]
  pub fn name(&self) -> Result<String, io::Error> {
    Ok(self.name.clone())
  }

  /// get file size.
  #[rune::function]
  pub fn size(&self) -> Result<i64, io::Error> {
    Ok(self.file.metadata()?.len().try_into().unwrap())
  }
}
