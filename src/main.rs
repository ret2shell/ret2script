use std::{collections::HashMap, env::current_dir, path::Path, sync::Arc};

use clap::Parser;
use colored::Colorize;
use ret2script::modules::bucket::Bucket;
use rune::{
  runtime::Object,
  termcolor::{ColorChoice, StandardStream},
  Any, Context, ContextError, Diagnostics, Module, Source, Sources, Value, Vm,
};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditMessage {
  pub peer_team: i64,
  pub reason: String,
}

#[derive(Clone, Debug, Any)]
#[rune(item = ::ret2shell::checker)]
pub struct RuneUser {
  #[rune(get)]
  pub id: i64,
  #[rune(get)]
  pub account: String,
  #[rune(get)]
  pub institute_id: Option<i64>,
}

#[derive(Clone, Debug, Any, Default)]
#[rune(item = ::ret2shell::checker)]
pub struct RuneTeam {
  #[rune(get)]
  pub id: Option<i64>,
  #[rune(get)]
  pub name: Option<String>,
  #[rune(get)]
  pub institute_id: Option<i64>,
  #[rune(get)]
  pub token: Option<String>,
}

#[derive(Clone, Debug, Any)]
#[rune(item = ::ret2shell::checker)]
pub struct RuneSubmission {
  #[rune(get)]
  pub id: i64,
  #[rune(get)]
  pub user_id: i64,
  #[rune(get)]
  pub team_id: Option<i64>,
  #[rune(get)]
  pub challenge_id: i64,
  #[rune(get)]
  pub content: String,
}

#[rune::module(::ret2shell::checker)]
fn module(_stdio: bool) -> Result<Module, ContextError> {
  let mut module = Module::from_meta(self::module_meta)?;
  module.ty::<RuneUser>()?;
  module.ty::<RuneTeam>()?;
  module.ty::<RuneSubmission>()?;
  Ok(module)
}

#[tokio::main]
async fn main() {
  let args = Commands::parse();
  match args {
    Commands::Check { script, flag } => check(&script, &flag).await.expect("error encountered"),
    Commands::Environ { script } => environ(&script).await.expect("error encountered"),
  }
}

fn compile_source(script: impl AsRef<Path>) -> anyhow::Result<Vm> {
  let mut context = Context::with_default_modules()?;
  context.install(rune_modules::http::module(true)?)?;
  context.install(rune_modules::json::module(true)?)?;
  context.install(rune_modules::toml::module(true)?)?;
  context.install(rune_modules::process::module(true)?)?;
  context.install(ret2script::modules::crypto::module(true)?)?;
  context.install(ret2script::modules::bucket::module(true)?)?;
  context.install(ret2script::modules::audit::module(true)?)?;
  context.install(ret2script::modules::utils::module(true)?)?;
  context.install(ret2script::modules::regex::module(true)?)?;
  context.install(module(true)?)?;

  let mut sources = Sources::new();
  let mut diagnostics = Diagnostics::new();
  sources.insert(Source::from_path(script.as_ref())?)?;
  let unit = rune::prepare(&mut sources)
    .with_context(&context)
    .with_diagnostics(&mut diagnostics)
    .build();
  if !diagnostics.is_empty() {
    let mut writer = StandardStream::stderr(ColorChoice::Always);
    diagnostics.emit(&mut writer, &sources)?;
  }
  let unit = unit?;
  let runtime = context.runtime()?;
  Ok(Vm::new(Arc::new(runtime), Arc::new(unit)))
}

async fn check(script: impl AsRef<Path>, flag: impl AsRef<str>) -> anyhow::Result<()> {
  let cwd = current_dir()?;
  let mut vm = compile_source(script)?;
  // let mut user = Object::new();
  // user.insert(alloc::String::try_from("id")?, rune::to_value(3307)?)?;
  // user.insert(
  //   alloc::String::try_from("account")?,
  //   rune::to_value("p1ay3r")?,
  // )?;
  // user.insert(
  //   alloc::String::try_from("institute_id")?,
  //   rune::to_value(1106)?,
  // )?;
  let user = RuneUser {
    id: 3307,
    account: "p1ay3r".to_string(),
    institute_id: Some(1106),
  };
  println!("{}\t\t= {user:?}", "User".blue());
  // let mut team = Object::new();
  // team.insert(alloc::String::try_from("id")?, rune::to_value(114514)?)?;
  // team.insert(alloc::String::try_from("name")?, rune::to_value("te4m")?)?;
  // team.insert(
  //   alloc::String::try_from("institute_id")?,
  //   rune::to_value(1106)?,
  // )?;
  let team = RuneTeam {
    id: Some(114514),
    name: Some("te4m".to_string()),
    institute_id: Some(1106),
    token: Some("V1StGXR8_Z5jdHi6B-myT".to_string()),
  };
  println!("{}\t\t= {team:?}", "Team".green());
  // let mut submission = Object::new();
  // submission.insert(alloc::String::try_from("id")?, rune::to_value(1919)?)?;
  // submission.insert(alloc::String::try_from("user_id")?,
  // rune::to_value(3307)?)?; submission.insert(alloc::String::try_from("
  // team_id")?, rune::to_value(114)?)?; submission.insert(
  //   alloc::String::try_from("challenge_id")?,
  //   rune::to_value(810)?,
  // )?;
  // submission.insert(
  //   alloc::String::try_from("content")?,
  //   rune::to_value(flag.as_ref())?,
  // )?;
  let submission = RuneSubmission {
    id: 1919,
    user_id: 3307,
    team_id: Some(114),
    challenge_id: 810,
    content: flag.as_ref().to_string(),
  };
  println!("{}\t= {submission:?}", "Submission".yellow());
  let bucket = Bucket::try_new(&cwd)?;
  let output = vm.call(["check"], (bucket, user, team, submission));
  if output.is_err() {
    println!(
      "{}: {output:?}",
      "Script ended with runtime error".red().bold()
    );
    return Ok(());
  }
  let output = output?;
  println!(
    "{}",
    "---------------------------------------------".dimmed()
  );
  let output: Result<(bool, String, Option<Object>), Value> = rune::from_value(output)?;
  if let Ok((result, message, audit)) = output {
    println!(
      "{}\n\t{}\t\t= {result}\n\t{}\t\t= {message}\n\t{}\t\t= {audit:?}",
      "Result".green(),
      "Correct".blue(),
      "Message".blue(),
      "Audit".blue()
    );
  } else {
    println!(
      "{}",
      "Script returned early from '?' operators.".red().bold()
    );
  }
  Ok(())
}

async fn environ(script: impl AsRef<Path>) -> anyhow::Result<()> {
  let cwd = current_dir()?;
  let mut vm = compile_source(script)?;
  // let mut user = Object::new();
  // user.insert(alloc::String::try_from("id")?, rune::to_value(3307)?)?;
  // user.insert(
  //   alloc::String::try_from("account")?,
  //   rune::to_value("p1ay3r")?,
  // )?;
  // user.insert(
  //   alloc::String::try_from("institute_id")?,
  //   rune::to_value(1106)?,
  // )?;
  let user = RuneUser {
    id: 3307,
    account: "p1ay3r".to_string(),
    institute_id: Some(1106),
  };
  println!("{}\t\t= {user:?}", "User".blue());
  // let mut team = Object::new();
  // team.insert(alloc::String::try_from("id")?, rune::to_value(114514)?)?;
  // team.insert(alloc::String::try_from("name")?, rune::to_value("te4m")?)?;
  // team.insert(
  //   alloc::String::try_from("institute_id")?,
  //   rune::to_value(1106)?,
  // )?;
  let team = RuneTeam {
    id: Some(114514),
    name: Some("te4m".to_string()),
    institute_id: Some(1106),
    token: Some("V1StGXR8_Z5jdHi6B-myT".to_string()),
  };
  println!("{}\t\t= {team:?}", "Team".green());

  println!(
    "{}",
    "---------------------------------------------".dimmed()
  );

  let bucket = Bucket::try_new(&cwd)?;
  let output = vm.call(["environ"], (bucket, user, team))?;
  let object: Result<Object, Value> = rune::from_value(output)?;
  if let Ok(object) = object {
    let mut environ: HashMap<String, String> = HashMap::new();
    for (key, value) in object.iter() {
      environ.insert(key.to_string(), rune::from_value(value.clone())?);
    }
    println!("{}: {environ:?}", "Result".green());
  } else {
    println!("Error occured during env generation");
  }
  Ok(())
}
