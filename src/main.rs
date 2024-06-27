use std::{collections::HashMap, env::current_dir, path::Path, sync::Arc};

use clap::Parser;
use ret2script::modules::bucket::Ret2Bucket;
use rune::{alloc, runtime::Object, Source, Sources, Vm};

#[derive(Parser, Debug)]
#[command(name = "ret2script")]
#[command(bin_name = "ret2script")]
#[command(
    author = "Reverier-Xu <reverier.xu@woooo.tech>",
    version,
    about = "Script checker for Ret 2 Shell Challenge API Platform",
    long_about = r#"
Script checker for Ret 2 Shell Challenge API Platform

THE CONTENTS OF THIS PROJECT ARE PROPRIETARY AND CONFIDENTIAL.
UNAUTHORIZED COPYING, TRANSFERRING OR REPRODUCTION OF THE CONTENTS OF THIS PROJECT,
VIA ANY MEDIUM IS STRICTLY PROHIBITED.

If you have any problems, please contact tech support <support@ret.sh.cn>.
"#
)]
enum Commands {
    /// run `check()` function in your script.
    Check {
        /// script path
        script: String,
        #[clap(short, long)]
        flag: String,
    },
    /// run `environ()` function in your script.
    Environ {
        /// script path
        script: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Commands::parse();
    match args {
        Commands::Check { script, flag } => check(&script, &flag).await.expect("error encountered"),
        Commands::Environ { script } => environ(&script).await.expect("error encountered"),
    }
}

async fn check(script: impl AsRef<Path>, flag: impl AsRef<str>) -> anyhow::Result<()> {
    let cwd = current_dir()?;
    let mut context = rune_modules::default_context()?;
    context.install(rune_modules::http::module(true)?)?;
    context.install(rune_modules::json::module(true)?)?;
    context.install(rune_modules::toml::module(true)?)?;
    context.install(rune_modules::process::module(true)?)?;
    context.install(ret2script::modules::crypto::module(true)?)?;
    context.install(ret2script::modules::bucket::module(true)?)?;
    context.install(ret2script::modules::audit::module(true)?)?;

    let mut sources = Sources::new();
    sources.insert(Source::from_path(script.as_ref())?)?;
    let unit = rune::prepare(&mut sources).with_context(&context).build()?;
    let runtime = context.runtime()?;
    let mut vm = Vm::new(Arc::new(runtime), Arc::new(unit));
    let mut user = Object::new();
    user.insert(alloc::String::try_from("id")?, rune::to_value(3307)?)?;
    user.insert(
        alloc::String::try_from("account")?,
        rune::to_value("p1ay3r")?,
    )?;
    user.insert(
        alloc::String::try_from("institute_id")?,
        rune::to_value(1106)?,
    )?;
    println!("User: {user:?}");
    let mut team = Object::new();
    team.insert(alloc::String::try_from("id")?, rune::to_value(114)?)?;
    team.insert(alloc::String::try_from("name")?, rune::to_value("te4m")?)?;
    team.insert(
        alloc::String::try_from("institute_id")?,
        rune::to_value(514)?,
    )?;
    println!("Team: {team:?}");
    let mut submission = Object::new();
    submission.insert(alloc::String::try_from("id")?, rune::to_value(1919)?)?;
    submission.insert(alloc::String::try_from("user_id")?, rune::to_value(3307)?)?;
    submission.insert(alloc::String::try_from("team_id")?, rune::to_value(114)?)?;
    submission.insert(
        alloc::String::try_from("challenge_id")?,
        rune::to_value(810)?,
    )?;
    submission.insert(
        alloc::String::try_from("content")?,
        rune::to_value(flag.as_ref())?,
    )?;
    println!("Submission: {submission:?}");
    let bucket = Ret2Bucket::try_new(&cwd)?;
    let output = vm
        .async_call(["check"], (bucket, user, team, submission))
        .await?;
    let (result, message, audit): (bool, String, Option<(Option<i64>, String)>) =
        rune::from_value(output)?;
    println!("Check result: \n\tresult:\t{result}\n\tmessage:\t{message}\n\taudit:\t{audit:?}");

    Ok(())
}

async fn environ(script: impl AsRef<Path>) -> anyhow::Result<()> {
    let cwd = current_dir()?;
    let mut context = rune_modules::default_context()?;
    context.install(rune_modules::http::module(true)?)?;
    context.install(rune_modules::json::module(true)?)?;
    context.install(rune_modules::toml::module(true)?)?;
    context.install(rune_modules::process::module(true)?)?;
    context.install(ret2script::modules::crypto::module(true)?)?;
    context.install(ret2script::modules::bucket::module(true)?)?;
    context.install(ret2script::modules::audit::module(true)?)?;

    let mut sources = Sources::new();
    sources.insert(Source::from_path(script.as_ref())?)?;
    let unit = rune::prepare(&mut sources).with_context(&context).build()?;
    let runtime = context.runtime()?;
    let mut vm = Vm::new(Arc::new(runtime), Arc::new(unit));
    let mut user = Object::new();
    user.insert(alloc::String::try_from("id")?, rune::to_value(3307)?)?;
    user.insert(
        alloc::String::try_from("account")?,
        rune::to_value("p1ay3r")?,
    )?;
    user.insert(
        alloc::String::try_from("institute_id")?,
        rune::to_value(1106)?,
    )?;
    println!("User: {user:?}");
    let mut team = Object::new();
    team.insert(alloc::String::try_from("id")?, rune::to_value(114)?)?;
    team.insert(alloc::String::try_from("name")?, rune::to_value("te4m")?)?;
    team.insert(
        alloc::String::try_from("institute_id")?,
        rune::to_value(514)?,
    )?;
    println!("Team: {team:?}");
    let bucket = Ret2Bucket::try_new(&cwd)?;
    let output = vm.async_call(["environ"], (bucket, user, team)).await?;
    let object: Object = rune::from_value(output)?;
    let mut environ = HashMap::new();
    for (key, value) in object.iter() {
        environ.insert(key.to_string(), rune::from_value(value.clone())?);
    }
    println!("Environ: {environ:?}");
    Ok(())
}
