use std::{collections::HashMap, io};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use once_cell::sync::Lazy;
use ring::{
  digest,
  rand::{SecureRandom, SystemRandom},
};
use rune::{ContextError, Module};

static LEET_CHAR_TABLE: Lazy<HashMap<u8, Vec<u8>>> = Lazy::new(|| {
  let mut map = HashMap::new();
  map.insert(b'0', vec![b'0', b'O']);
  map.insert(b'1', vec![b'1', b'l', b'I']);
  map.insert(b'2', vec![b'2', b'Z']);
  map.insert(b'3', vec![b'3']);
  map.insert(b'4', vec![b'4', b'A']);
  map.insert(b'5', vec![b'5', b'S']);
  map.insert(b'6', vec![b'6', b'b']);
  map.insert(b'7', vec![b'7']);
  map.insert(b'8', vec![b'8', b'B']);
  map.insert(b'9', vec![b'9']);
  map.insert(b'a', vec![b'a', b'A', b'@', b'4']);
  map.insert(b'b', vec![b'b', b'B', b'6']);
  map.insert(b'c', vec![b'c', b'C']);
  map.insert(b'd', vec![b'd', b'D']);
  map.insert(b'e', vec![b'e', b'E', b'3']);
  map.insert(b'f', vec![b'f', b'F']);
  map.insert(b'g', vec![b'g', b'G']);
  map.insert(b'h', vec![b'h', b'H']);
  map.insert(b'i', vec![b'i', b'I', b'1', b'l']);
  map.insert(b'j', vec![b'j', b'J']);
  map.insert(b'k', vec![b'k', b'K']);
  map.insert(b'l', vec![b'l', b'L', b'1', b'I']);
  map.insert(b'm', vec![b'm', b'M']);
  map.insert(b'n', vec![b'n', b'N']);
  map.insert(b'o', vec![b'o', b'O', b'0']);
  map.insert(b'p', vec![b'p', b'P']);
  map.insert(b'q', vec![b'q', b'Q']);
  map.insert(b'r', vec![b'r', b'R']);
  map.insert(b's', vec![b's', b'S', b'5']);
  map.insert(b't', vec![b't', b'T']);
  map.insert(b'u', vec![b'u', b'U']);
  map.insert(b'v', vec![b'v', b'V']);
  map.insert(b'w', vec![b'w', b'W']);
  map.insert(b'x', vec![b'x', b'X']);
  map.insert(b'y', vec![b'y', b'Y']);
  map.insert(b'z', vec![b'z', b'Z', b'2']);
  map.insert(b'A', vec![b'A', b'a', b'@', b'4']);
  map.insert(b'B', vec![b'B', b'b', b'8']);
  map.insert(b'C', vec![b'C', b'c']);
  map.insert(b'D', vec![b'D', b'd']);
  map.insert(b'E', vec![b'E', b'e', b'3']);
  map.insert(b'F', vec![b'F', b'f']);
  map.insert(b'G', vec![b'G', b'g']);
  map.insert(b'H', vec![b'H', b'h']);
  map.insert(b'I', vec![b'I', b'i', b'1', b'l']);
  map.insert(b'J', vec![b'J', b'j']);
  map.insert(b'K', vec![b'K', b'k']);
  map.insert(b'L', vec![b'L', b'l', b'1', b'I']);
  map.insert(b'M', vec![b'M', b'm']);
  map.insert(b'N', vec![b'N', b'n']);
  map.insert(b'O', vec![b'O', b'o', b'0']);
  map.insert(b'P', vec![b'P', b'p']);
  map.insert(b'Q', vec![b'Q', b'q']);
  map.insert(b'R', vec![b'R', b'r']);
  map.insert(b'S', vec![b'S', b's', b'5']);
  map.insert(b'T', vec![b'T', b't']);
  map.insert(b'U', vec![b'U', b'u']);
  map.insert(b'V', vec![b'V', b'v']);
  map.insert(b'W', vec![b'W', b'w']);
  map.insert(b'X', vec![b'X', b'x']);
  map.insert(b'Y', vec![b'Y', b'y']);
  map.insert(b'Z', vec![b'Z', b'z', b'2']);
  map.insert(b'_', vec![b'_', b'-']);
  map.insert(b'-', vec![b'-', b'_']);
  map.insert(b'!', vec![b'!', b'1', b'l']);

  map
});

const DELTA: u32 = 0x9E3779B9;

fn to_bytes(v: &[u32], include_length: bool) -> Vec<u8> {
  let length: u32 = v.len() as u32;
  let mut n: u32 = length << 2;
  if include_length {
    let m: u32 = v[length as usize - 1];
    n -= 4;
    assert!(!((m < n - 3) || (m > n)));
    n = m;
  }
  let mut bytes: Vec<u8> = vec![0; n as usize];
  for i in 0..n {
    bytes[i as usize] = (v[(i >> 2) as usize] >> ((i & 3) << 3)) as u8;
  }
  bytes
}

fn to_u32(bytes: &[u8], include_length: bool) -> Vec<u32> {
  let length: u32 = bytes.len() as u32;
  let mut n: u32 = length >> 2;
  if length & 3 != 0 {
    n += 1;
  }
  let mut v;
  if include_length {
    v = vec![0; n as usize + 1];
    v[n as usize] = length;
  } else {
    v = vec![0; n as usize];
  }
  for i in 0..length {
    v[(i >> 2) as usize] |= (bytes[i as usize] as u32) << ((i & 3) << 3);
  }
  v
}

fn mx(sum: u32, y: u32, z: u32, p: u32, e: u32, k: &[u32]) -> u32 {
  ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
    ^ ((sum ^ y).wrapping_add(k[(p & 3 ^ e) as usize] ^ z))
}

fn fixk(k: &[u32]) -> Vec<u32> {
  let mut key = k.to_owned();
  if key.len() < 4 {
    let length = key.len();
    for _ in length..4 {
      key.push(0)
    }
  }
  key
}

fn encrypt_(v: &mut [u32], k: &[u32]) -> Vec<u32> {
  let length: u32 = v.len() as u32;
  let n: u32 = length - 1;
  let key: Vec<u32> = fixk(k);
  let mut e: u32;
  let mut y: u32;
  let mut z = v[n as usize];
  let mut sum: u32 = 0;
  let mut q: u32 = 6 + 52 / length;
  while q > 0 {
    sum = sum.wrapping_add(DELTA);
    e = sum >> 2 & 3;
    for p in 0..n {
      y = v[(p as usize) + 1];
      v[p as usize] = v[p as usize].wrapping_add(mx(sum, y, z, p, e, &key));
      z = v[p as usize];
    }
    y = v[0];
    v[n as usize] = v[n as usize].wrapping_add(mx(sum, y, z, n, e, &key));
    z = v[n as usize];
    q -= 1;
  }
  v.to_owned()
}

fn decrypt_(v: &mut [u32], k: &[u32]) -> Vec<u32> {
  let length: u32 = v.len() as u32;
  let n: u32 = length - 1;
  let key: Vec<u32> = fixk(k);
  let mut e: u32;
  let mut y: u32 = v[0];
  let mut z;
  let q: u32 = 6 + 52 / length;
  let mut sum: u32 = q.wrapping_mul(DELTA);
  while sum != 0 {
    e = sum >> 2 & 3;
    let mut p: usize = n as usize;
    while p > 0 {
      z = v[p - 1];
      v[p] = v[p].wrapping_sub(mx(sum, y, z, p as u32, e, &key));
      y = v[p];
      p -= 1;
    }
    z = v[n as usize];
    v[0] = v[0].wrapping_sub(mx(sum, y, z, 0, e, &key));
    y = v[0];
    sum = sum.wrapping_sub(DELTA);
  }
  v.to_owned()
}

/// Encrypt a u8 vector with XXTEA
///
/// *Note:* XXTEA works on 32 bit words. If input is not evenly dividable by
/// four, it will be padded with zeroes. Padding information is lost after the
/// encryption and this needs to be taken into consideration when decrypting
/// messages.
///
/// # Arguments
///
/// * `data` - The data to be encrypted
/// * `key` - encryption key
///
/// # Example
///
/// ```
/// let key : &str = "SecretKey";
/// let data : [u8; 5] = [11, 13, 0, 14, 15];
///
/// let encrypted_data = xxtea::encrypt_raw(&data.to_vec(), &key);
/// // encrypted data will be 8 bytes (3 zeroes appended to the end)
/// println!("Encrypted data: {:?}", encrypted_data);
/// ```
pub fn encrypt_raw(data: &[u8], key: &str) -> Vec<u8> {
  let key = key.as_bytes();
  to_bytes(
    &encrypt_(&mut to_u32(data, false), &to_u32(key, false)),
    false,
  )
}

/// Decrypt a u8 vector with XXTEA
///
/// The output isn't verified for correctness, thus additional checks needs to
/// be performed on the output.
///
/// # Arguments
///
/// * `data` - The data to be decrypted
/// * `key` - encryption key
///
/// # Example
///
/// ```
/// let key : &str = "SecretKey";
/// let data : [u8; 5] = [11, 13, 0, 14, 15];
///
/// let decrypted_data = xxtea::decrypt_raw(&data.to_vec(), &key);
/// println!("Decrypted data: {:?}", decrypted_data);
/// ```
pub fn decrypt_raw(data: &[u8], key: &str) -> Vec<u8> {
  let key = key.as_bytes();
  to_bytes(
    &decrypt_(&mut to_u32(data, false), &to_u32(key, false)),
    false,
  )
}

/// Generate AES key and IV from a string
///
/// The function calculates the SHA-256 hash of the input string, and extracts
/// two 16-bytes long data from the hash, treated as the AES key and IV.
///
/// # Arguments
/// * `str` - The string to generate
///
/// # Example
/// ```
/// let (key, iv) = generate_aes_pair("some data");
/// println!("Key: {:?}, IV: {:?}", key, iv);
/// ```
pub fn generate_aes_pair(str: &str) -> ([u8; 16], [u8; 16]) {
  let hash = ring::digest::digest(&ring::digest::SHA256, str.as_bytes());
  let key = hash.as_ref()[0..16].try_into().unwrap();
  let iv = hash.as_ref()[16..32].try_into().unwrap();
  (key, iv)
}

#[derive(Debug, Clone)]
pub struct FlagStego {
  pub key: String,
}

#[derive(Debug, Clone)]
pub struct UUIDStego {
  pub with_hyphen: bool,
  pub key: String,
}

impl FlagStego {
  /// Construct a FlagStego instance.
  ///
  /// ## Examples
  ///
  /// ```rust
  /// let flag_stego = FlagStego::new("some_key");
  ///
  /// let flag = "hello_world";
  /// let encrypted_flag = flag_stego.leet(flag, 114514); // -> encrypted flag
  /// ```
  pub fn new(key: &str) -> Self {
    Self {
      key: key.to_string(),
    }
  }

  /// hide a number in flag string with key encrypted.
  pub fn leet(&self, template: &str, data: i64) -> String {
    let encrypted = encrypt_raw(&data.to_le_bytes(), &self.key);
    // turn the encrypted data into a i64
    let mut encrypted_slice = [0; 8];
    encrypted_slice.copy_from_slice(&encrypted);
    let mut e = u64::from_le_bytes(encrypted_slice);
    // println!("e: {e}");
    let mut result = String::new();
    for c in template.chars() {
      if let Some(replace) = LEET_CHAR_TABLE.get(&(c as u8)) {
        let modular = e % replace.len() as u64;
        let ec = replace[modular as usize] as char;
        result.push(ec);
        e /= replace.len() as u64;
        // println!("e: {e}, c: {c}, modular: {modular}, ec: {ec}");
      } else {
        result.push(c);
      }
    }
    // append the remaining encrypted data as hex string
    result.push_str(&format!("{:x}", e));
    result
  }

  /// extract the number hidding in the flag string
  pub fn unleet(&self, template: &str, data: &str) -> Result<i64, io::Error> {
    // split the data into encrypted data and hex string using template's length
    let template_len = template.len();
    if template_len >= data.len() {
      return Err(io::Error::other("flag length mispatch"));
    }
    let (e_data, e_hex) = data
      .split_at_checked(template_len)
      .ok_or(io::Error::other("flag length mispatch"))?;
    let mut e_data = e_data.chars().rev();
    let mut e = u64::from_str_radix(e_hex, 16).map_err(|_| io::Error::other("flag data broken"))?;
    for c in template.chars().rev() {
      let ec = e_data
        .next()
        .ok_or(io::Error::other("flag length mispatch"))?;
      if let Some(replace) = LEET_CHAR_TABLE.get(&(c as u8)) {
        // println!("c: {c}, replace: {replace:?}, e: {e}, ec: {ec}");
        let char_t_index = replace
          .iter()
          .position(|&x| x == ec as u8)
          .ok_or(io::Error::other("flag data broken"))?;
        // println!("e: {e}, c: {c}, ec: {ec}, e_index: {char_t_index}");
        e = e
          .checked_mul(replace.len() as u64)
          .ok_or(io::Error::other("flag data broken"))?
          .checked_add(char_t_index as u64)
          .ok_or(io::Error::other("flag data broken"))?;
      }
    }
    // println!("e: {e}");
    let decrypted = decrypt_raw(&e.to_le_bytes(), &self.key);
    let mut decrypted_slice = [0; 8];
    decrypted_slice.copy_from_slice(&decrypted);
    Ok(i64::from_le_bytes(decrypted_slice))
  }
}

impl UUIDStego {
  /// Construct a UUIDStego instance.
  ///
  /// ## Examples
  ///
  /// ```rust
  /// let uuid_stego = UUIDStego::new("some_key");
  ///
  /// let template = "hello_world";
  /// let encrypted_flag = uuid_stego.leet(template, 114514); // -> encrypted flag
  /// ```
  pub fn new(key: &str, with_hyphen: bool) -> Self {
    Self {
      with_hyphen,
      key: key.to_string(),
    }
  }

  /// hide a number in a uuid with key encrypted.
  pub fn leet(&self, template: &str, data: i64) -> String {
    let (aes_key, _) = generate_aes_pair(&self.key);
    // dump template into 16 bytes hash
    let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, template.as_bytes());
    let mut hash_slice = [0u8; 16];
    hash_slice.copy_from_slice(&digest.as_ref()[2..18]);

    // xor
    let encrypted = encrypt_raw(&data.to_le_bytes(), &self.key);
    // turn the encrypted data into a i64
    let mut encrypted_slice = [0u8; 8];
    encrypted_slice.copy_from_slice(&encrypted);
    // generate random bytes (salt)
    let rng = SystemRandom::new();
    let mut rand_bytes = [0u8; 4];
    rng.fill(&mut rand_bytes).unwrap();
    for i in 0..8 {
      if i % 2 == 0 {
        // we will reserve 4 bytes in order to check whether the
        // flag is broken
        hash_slice[i * 2] ^= rand_bytes[i / 2];
      }
      hash_slice[i * 2 + 1] ^= encrypted_slice[i];
    }
    // println!("hash: {:?}", hash_slice);

    // aes ecb
    let cipher = aes::Aes128::new_from_slice(&aes_key).unwrap();
    let mut block = aes::Block::default();
    block.copy_from_slice(&hash_slice);
    cipher.encrypt_block(&mut block);

    let mut result = String::new();
    for i in 0..16 {
      result.push_str(&format!("{:02x}", block[i]));
      if self.with_hyphen && (i == 3 || i == 5 || i == 7 || i == 9) {
        result.push('-');
      }
    }
    // println!("result: {:?}", result);
    result
  }

  pub fn unleet(&self, template: &str, data: &str) -> Result<i64, io::Error> {
    let re = if self.with_hyphen {
      regex::Regex::new(
        r"([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})",
      )
      .unwrap()
    } else {
      regex::Regex::new(r"([0-9a-fA-F]{32})").unwrap()
    };
    let _ = re
      .captures(data)
      .ok_or(io::Error::other("uuid format mismatch"))?;
    let mut input_data = String::new();
    for c in data.chars() {
      if c != '-' {
        input_data.push(c);
      }
    }
    // println!("data: {:?}", data);
    let data_slice =
      hex::decode(input_data).map_err(|_| io::Error::other("uuid format mismatch"))?;

    let (aes_key, _) = generate_aes_pair(&self.key);
    // aes ecb
    let cipher = aes::Aes128::new_from_slice(&aes_key).unwrap();
    let mut block = aes::Block::default();
    block.copy_from_slice(&data_slice);
    cipher.decrypt_block(&mut block);

    // dump template into 16 bytes hash
    let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, template.as_bytes());
    let mut hash_slice = [0u8; 16];
    hash_slice.copy_from_slice(&digest.as_ref()[2..18]);

    let mut dec = [0u8; 8];
    for i in 0..8 {
      if i % 2 != 0 {
        // check whether the flag is broken
        if hash_slice[i * 2] != (block[i * 2]) {
          return Err(io::Error::other("flag data broken"));
        }
      }
      dec[i] = hash_slice[i * 2 + 1] ^ block[i * 2 + 1];
    }

    let decrypted = decrypt_raw(&dec, &self.key);
    let mut decrypted_slice = [0u8; 8];
    decrypted_slice.copy_from_slice(&decrypted);
    Ok(i64::from_le_bytes(decrypted_slice))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_flag_transform() {
    let flag_stego = FlagStego::new("f80f9a197163");
    let template = "yes_you_are_right_but_you_should_play_genshin_impact";
    println!("Template  : {}", template);
    let data = 1919810;
    println!("User ID   : {}", data);
    let encrypted = flag_stego.leet(template, data);
    println!("Encrypted : {}", encrypted);
    let decrypted = flag_stego.unleet(template, &encrypted);
    println!("Decrypted : {:?}", decrypted);
    assert_eq!(decrypted.unwrap(), data);
  }

  #[test]
  fn test_uuid_transform() {
    let uuid_stego = UUIDStego::new("uuid_example_key", true);
    let template = "Yes you are right but you should watch BanG Dream! It's MyGO!!!!!";
    println!("Template  : {}", template);
    let data = 1919810;
    println!("User ID   : {}", data);
    let encrypted = uuid_stego.leet(template, data);
    println!("Encrypted : {}", encrypted);
    let decrypted = uuid_stego.unleet(template, &encrypted);
    println!("Decrypted : {:?}", decrypted);
    assert_eq!(decrypted.unwrap(), data);
  }
}

/// Construct the `ret2api::audit` module.
///
/// ## Usage
///
/// ```rust
///     let mut context = Context::with_default_modules()?;
///     context.install(ret2script::modules::audit::module(true)?)?;
/// ```
#[rune::module(::ret2api::audit)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
  let mut module = Module::from_meta(self::module_meta)?;
  module.function_meta(encode)?;
  module.function_meta(decode)?;
  module.function_meta(encode_uuid)?;
  module.function_meta(decode_uuid)?;
  Ok(module)
}

/// encode the flag template with custom key.
///
/// In rune script:
///
/// ```rust
/// use ret2api::audit;
///
/// pub fn environ(bucket, user, team) {
///   Ok(#{
///     FLAG: `flag{${audit::encode("you_said_right_but_you_should_play_genshin_impact", "some_key", user.id)}}`
///   })
/// }
/// ```
#[rune::function]
pub fn encode(template: &str, key: &str, id: i64) -> String {
  let flag_stego = FlagStego::new(key);
  flag_stego.leet(template, id)
}

/// Decrypt the data from flag.
///
/// In rune script:
///
/// ```rust
/// use ret2api::audit;
///
/// pub fn check(bucket, user, team, submission) {
///   ...
///   let decrypted_team_id = audit::decode("you_said_right_but_you_should_play_genshin_impact", "some_key", "Y0U_5aiD_RigHt-but_yOU_5HOULD_P1ay-G3NSh1N_ImP@Ct1");
///   ...
/// }
/// ```
#[rune::function]
pub fn decode(template: &str, key: &str, flag: &str) -> Result<i64, io::Error> {
  let flag_stego = FlagStego::new(key);
  flag_stego.unleet(template, flag)
}

/// encode the flag template and get the UUID with custom key.
///
/// In rune script:
///
/// ```rust
/// use ret2api::audit;
///
/// pub fn environ(bucket, user, team) {
///   Ok(#{
///     FLAG: `flag{${audit::encode_uuid("bangdreamitsmygo", "some_key", user.id, true)}}`
///   })
/// }
/// ```
#[rune::function]
pub fn encode_uuid(template: &str, key: &str, id: i64, with_hyphen: bool) -> String {
  let uuid_stego = UUIDStego::new(key, with_hyphen);
  uuid_stego.leet(template, id)
}

/// Decrypt the data from flag (UUID format).
///
/// In rune script:
///
/// ```rust
/// use ret2api::audit;
///
/// pub fn check(bucket, user, team, submission) {
///   ...
///   let decrypted_team_id = audit::decode_uuid("bangdreamitsmygo", "some_key", "6f262cae-24f9-f1ea-1dab-ba561ee38e57", true);
///   ...
/// }
/// ```
#[rune::function]
pub fn decode_uuid(
  template: &str, key: &str, flag: &str, with_hyphen: bool,
) -> Result<i64, io::Error> {
  let uuid_stego = UUIDStego::new(key, with_hyphen);
  uuid_stego.unleet(template, flag)
}
