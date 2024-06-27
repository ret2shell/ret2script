use std::{f64, io};

use ring::{
    digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA512},
    rand::{self, SecureRandom},
};
use rune::{Any, ContextError, Module};

/// Construct the `ret2api::crypto` module.
#[rune::module(::ret2api::crypto)]
pub fn module(_stdio: bool) -> Result<Module, ContextError> {
    let mut module = Module::from_meta(self::module_meta)?;
    module.ty::<Rng>()?;
    module.function_meta(Rng::rand)?;
    module.function_meta(Rng::rand_int)?;
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

    Ok(module)
}

#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Rng;

impl Rng {
    #[rune::function(path = Self::rand)]
    pub fn rand(min: f64, max: f64) -> Result<f64, io::Error> {
        if max <= min {
            return Err(io::Error::other("max is less than min"));
        }
        let rng = rand::SystemRandom::new();
        let mut buffer = [0u8; 8];
        rng.fill(&mut buffer)
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

    #[rune::function(path = Self::rand_int)]
    pub fn rand_int(min: i64, max: i64) -> Result<i64, io::Error> {
        if max <= min {
            return Err(io::Error::other("max is less than min"));
        }
        let rng = rand::SystemRandom::new();
        let mut buffer = [0u8; 8];
        rng.fill(&mut buffer)
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
}

#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Uuid;

impl Uuid {
    #[rune::function(path = Self::new)]
    pub fn new() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Nanoid;

impl Nanoid {
    #[rune::function(path = Self::new)]
    pub fn new() -> String {
        nanoid::nanoid!()
    }
}

#[derive(Any, Debug)]
#[rune(item = ::ret2api::crypto)]
pub struct Hash;

impl Hash {
    #[rune::function(path = Self::sha256sum)]
    pub fn sha256sum(message: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(message);
        hex::encode(context.finish().as_ref())
    }

    #[rune::function(path = Self::sha256sum_str)]
    pub fn sha256sum_str(message: &str) -> String {
        let mut context = Context::new(&SHA256);
        context.update(message.as_bytes());
        hex::encode(context.finish().as_ref())
    }

    #[rune::function(path = Self::sha512sum)]
    pub fn sha512sum(message: &[u8]) -> String {
        let mut context = Context::new(&SHA512);
        context.update(message);
        hex::encode(context.finish().as_ref())
    }

    #[rune::function(path = Self::sha512sum_str)]
    pub fn sha512sum_str(message: &str) -> String {
        let mut context = Context::new(&SHA512);
        context.update(message.as_bytes());
        hex::encode(context.finish().as_ref())
    }

    #[rune::function(path = Self::sha1sum)]
    pub fn sha1sum(message: &[u8]) -> String {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(message);
        hex::encode(context.finish().as_ref())
    }

    #[rune::function(path = Self::sha1sum_str)]
    pub fn sha1sum_str(message: &str) -> String {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(message.as_bytes());
        hex::encode(context.finish().as_ref())
    }
}
