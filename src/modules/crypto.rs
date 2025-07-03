use std::{f64, io};

use ring::{
  aead::NONCE_LEN,
  digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA512},
  rand::{self, SecureRandom},
};
use rune::{Any, ContextError, Module};

/// Construct the `ret2api::crypto` module.
///
/// ## Usage
///
/// ```rust
///     let mut context = Context::with_default_modules()?;
///     context.install(ret2script::modules::crypto::module(true)?)?;
/// ```
#[rune::module(::ret2api::crypto)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
  let mut module = Module::from_meta(self::module_meta)?;
  module.ty::<Rng>()?;
  module.function_meta(Rng::rand)?;
  module.function_meta(Rng::rand_int)?;
  module.function_meta(Rng::rand_bytes)?;
  module.ty::<Uuid>()?;
  module.function_meta(Uuid::new)?;
  module.ty::<Nanoid>()?;
  module.function_meta(Nanoid::new)?;
  module.ty::<Hash>()?;
  module.function_meta(Hash::sha512sum)?;
  module.function_meta(Hash::sha512sum_str)?;
  module.function_meta(Hash::sha1sum)?;
  module.function_meta(Hash::sha1sum_str)?;
  module.function_meta(Hash::sha256sum)?;
  module.function_meta(Hash::sha256sum_str)?;
  module.ty::<Hmac>()?;
  module.function_meta(Hmac::hmac_sha256_sign)?;
  module.function_meta(Hmac::hmac_sha256_verify)?;
  module.function_meta(Hmac::hmac_sha512_sign)?;
  module.function_meta(Hmac::hmac_sha512_verify)?;
  module.ty::<AesGcm>()?;
  module.function_meta(AesGcm::encrypt_128)?;
  module.function_meta(AesGcm::decrypt_128)?;
  module.function_meta(AesGcm::encrypt_256)?;
  module.function_meta(AesGcm::decrypt_256)?;

  Ok(module)
}

/// Pesudo-random numbers generator.
#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Rng;

impl Rng {
  /// get a float64 random numbers in range.
  #[rune::function(path = Self::rand)]
  pub fn rand(min: f64, max: f64) -> Result<f64, io::Error> {
    if max <= min {
      return Err(io::Error::other("max is less than min"));
    }
    let rng = rand::SystemRandom::new();
    let mut buffer = [0u8; 8];
    rng
      .fill(&mut buffer)
      .map_err(|_| io::Error::other("generate random number failed"))?;
    let mut result = f64::from_ne_bytes(buffer);
    let step = max - min;
    if result < min {
      result += ((min - result) / step).ceil() * step;
    }
    if result > max {
      result -= ((result - max) / step).ceil() * step;
    }
    Ok(result)
  }

  /// get a int64 random numbers in range.
  #[rune::function(path = Self::rand_int)]
  pub fn rand_int(min: i64, max: i64) -> Result<i64, io::Error> {
    if max <= min {
      return Err(io::Error::other("max is less than min"));
    }
    let rng = rand::SystemRandom::new();
    let mut buffer = [0u8; 8];
    rng
      .fill(&mut buffer)
      .map_err(|_| io::Error::other("generate random number failed"))?;
    let mut result = i64::from_ne_bytes(buffer);
    let step = max - min;
    if result < min {
      result += ((min - result) as f64 / (step as f64)).ceil() as i64 * step;
    }
    if result > max {
      result -= ((result - max) as f64 / (step as f64)).ceil() as i64 * step;
    }
    Ok(result)
  }

  #[rune::function(path = Self::rand_bytes)]
  pub fn rand_bytes(len: usize) -> Result<Vec<u8>, io::Error> {
    if len == 0 {
      return Err(io::Error::other("length must be greater than 0"));
    }
    let rng = rand::SystemRandom::new();
    let mut buffer = vec![0u8; len];
    rng
      .fill(&mut buffer)
      .map_err(|_| io::Error::other("generate random bytes failed"))?;
    Ok(buffer)
  }
}

/// Uuid generator.
///
/// For legacy use only, please use nanoid for better experience.
#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Uuid;

impl Uuid {
  /// get a new uuid v4 string.
  #[rune::function(path = Self::new)]
  pub fn new() -> String {
    uuid::Uuid::new_v4().to_string()
  }
}

/// Nanoid generator.
#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Nanoid;

impl Nanoid {
  /// get a new nanoid string.
  #[rune::function(path = Self::new)]
  pub fn new() -> String {
    nanoid::nanoid!()
  }
}

/// Hash functions
///
/// functions here wraps the SHA* module in `ring` crate.
#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Hash;

impl Hash {
  /// get sha256 sum hex string for message.
  #[rune::function(path = Self::sha256sum)]
  pub fn sha256sum(message: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(message);
    hex::encode(context.finish().as_ref())
  }

  /// get sha256 sum hex string for message.
  #[rune::function(path = Self::sha256sum_str)]
  pub fn sha256sum_str(message: &str) -> String {
    let mut context = Context::new(&SHA256);
    context.update(message.as_bytes());
    hex::encode(context.finish().as_ref())
  }

  /// get sha512 sum hex string for message.
  #[rune::function(path = Self::sha512sum)]
  pub fn sha512sum(message: &[u8]) -> String {
    let mut context = Context::new(&SHA512);
    context.update(message);
    hex::encode(context.finish().as_ref())
  }

  /// get sha512 sum hex string for message.
  #[rune::function(path = Self::sha512sum_str)]
  pub fn sha512sum_str(message: &str) -> String {
    let mut context = Context::new(&SHA512);
    context.update(message.as_bytes());
    hex::encode(context.finish().as_ref())
  }

  /// get sha1 sum hex string for message, for legacy use only, please use
  /// sha256 instead.
  #[rune::function(path = Self::sha1sum)]
  pub fn sha1sum(message: &[u8]) -> String {
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(message);
    hex::encode(context.finish().as_ref())
  }

  /// get sha1 sum hex string for message, for legacy use only, please use
  /// sha256 instead.
  #[rune::function(path = Self::sha1sum_str)]
  pub fn sha1sum_str(message: &str) -> String {
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(message.as_bytes());
    hex::encode(context.finish().as_ref())
  }
}

/// Hmac functions
///
/// functions here wraps the hmac module in `ring` crate.
#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Hmac;

impl Hmac {
  // Hmac functions can be added here in the future.
  // Currently, we do not provide hmac functions in ret2api.
  // If you need hmac functions, please use `ring::hmac` directly.
  #[rune::function(path = Self::hmac_sha256_sign)]
  pub fn hmac_sha256_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let signature = ring::hmac::sign(&key, message);
    signature.as_ref().to_vec()
  }

  #[rune::function(path = Self::hmac_sha256_verify)]
  pub fn hmac_sha256_verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::verify(&key, message, signature).is_ok()
  }

  #[rune::function(path = Self::hmac_sha512_sign)]
  pub fn hmac_sha512_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
    let signature = ring::hmac::sign(&key, message);
    signature.as_ref().to_vec()
  }

  #[rune::function(path = Self::hmac_sha512_verify)]
  pub fn hmac_sha512_verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
    ring::hmac::verify(&key, message, signature).is_ok()
  }
}

#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct AesGcm;

impl AesGcm {
  // AES functions can be added here in the future.
  // Currently, we do not provide AES functions in ret2api.
  // If you need AES functions, please use `ring::aead` or `ring::aes` directly.
  #[rune::function(path = Self::encrypt_128)]
  pub fn encrypt_128(key: &[u8], data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, io::Error> {
    if key.len() != ring::aead::AES_128_GCM.key_len() {
      return Err(io::Error::other(format!(
        "key length must be {} bytes",
        ring::aead::AES_128_GCM.key_len()
      )));
    }
    if data.is_empty() {
      return Err(io::Error::other("data cannot be empty"));
    }

    // Create a new AES-128 cipher
    let cipher = ring::aead::LessSafeKey::new(
      ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key)
        .map_err(|_| io::Error::other("failed to create AES-128 cipher"))?,
    );

    let nonce: [u8; NONCE_LEN] = nonce
      .get(..NONCE_LEN)
      .and_then(|slice| slice.try_into().ok())
      .ok_or_else(|| io::Error::other(format!("nonce must be {NONCE_LEN} bytes").as_str()))?;
    let mut encrypted_data = data.to_vec();
    let aad = ring::aead::Aad::empty();
    cipher
      .seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(nonce),
        aad,
        &mut encrypted_data,
      )
      .map_err(|_| io::Error::other("encryption failed"))?;

    Ok(encrypted_data)
  }

  #[rune::function(path = Self::decrypt_128)]
  pub fn decrypt_128(key: &[u8], data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, io::Error> {
    if key.len() != ring::aead::AES_128_GCM.key_len() {
      return Err(io::Error::other(format!(
        "key length must be {} bytes",
        ring::aead::AES_128_GCM.key_len()
      )));
    }
    if data.is_empty() {
      return Err(io::Error::other("data cannot be empty"));
    }

    // Create a new AES-128 cipher
    let cipher = ring::aead::LessSafeKey::new(
      ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key)
        .map_err(|_| io::Error::other("failed to create AES-128 cipher"))?,
    );
    let mut decrypted_data = data.to_vec();
    let aad = ring::aead::Aad::empty();
    let nonce: [u8; NONCE_LEN] = nonce
      .get(..NONCE_LEN)
      .and_then(|slice| slice.try_into().ok())
      .ok_or_else(|| io::Error::other(format!("nonce must be {NONCE_LEN} bytes").as_str()))?;
    cipher
      .open_in_place(
        ring::aead::Nonce::assume_unique_for_key(nonce),
        aad,
        &mut decrypted_data,
      )
      .map_err(|_| io::Error::other("decryption failed"))?;
    let tag_len = cipher.algorithm().tag_len();
    let plaintext_len = decrypted_data.len() - tag_len;
    decrypted_data.truncate(plaintext_len);
    Ok(decrypted_data)
  }

  #[rune::function(path = Self::encrypt_256)]
  pub fn encrypt_256(key: &[u8], data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, io::Error> {
    if key.len() != ring::aead::AES_256_GCM.key_len() {
      return Err(io::Error::other(format!(
        "key length must be {} bytes",
        ring::aead::AES_256_GCM.key_len()
      )));
    }
    if data.is_empty() {
      return Err(io::Error::other("data cannot be empty"));
    }

    // Create a new AES-256 cipher
    let cipher = ring::aead::LessSafeKey::new(
      ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| io::Error::other("failed to create AES-256 cipher"))?,
    );

    let nonce: [u8; NONCE_LEN] = nonce
      .get(..NONCE_LEN)
      .and_then(|slice| slice.try_into().ok())
      .ok_or_else(|| io::Error::other(format!("nonce must be {NONCE_LEN} bytes").as_str()))?;

    let mut encrypted_data = data.to_vec();

    let aad = ring::aead::Aad::empty();
    cipher
      .seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(nonce),
        aad,
        &mut encrypted_data,
      )
      .map_err(|_| io::Error::other("encryption failed"))?;

    Ok(encrypted_data)
  }

  #[rune::function(path = Self::decrypt_256)]
  pub fn decrypt_256(key: &[u8], data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, io::Error> {
    if key.len() != ring::aead::AES_256_GCM.key_len() {
      return Err(io::Error::other(
        format!(
          "key length must be {} bytes",
          ring::aead::AES_256_GCM.key_len(),
        )
        .as_str(),
      ));
    }

    if data.is_empty() {
      return Err(io::Error::other("data cannot be empty"));
    }
    // Create a new AES-256 cipher
    let cipher = ring::aead::LessSafeKey::new(
      ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
        .map_err(|_| io::Error::other("failed to create AES-256 cipher"))?,
    );
    let mut decrypted_data = data.to_vec();
    let aad = ring::aead::Aad::empty();
    let nonce: [u8; NONCE_LEN] = nonce
      .get(..NONCE_LEN)
      .and_then(|slice| slice.try_into().ok())
      .ok_or_else(|| io::Error::other(format!("nonce must be {NONCE_LEN} bytes").as_str()))?;
    cipher
      .open_in_place(
        ring::aead::Nonce::assume_unique_for_key(nonce),
        aad,
        &mut decrypted_data,
      )
      .map_err(|_| io::Error::other("decryption failed"))?;
    let tag_len = cipher.algorithm().tag_len();
    let plaintext_len = decrypted_data.len() - tag_len;
    decrypted_data.truncate(plaintext_len);
    Ok(decrypted_data)
  }
}
