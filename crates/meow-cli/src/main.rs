//! `meow-cli`: control a running meow over its REST API.
//!
//! Every command is one or a few requests to the daemon's
//! `external-controller`; nothing here links the engine. `--json` prints
//! what the API answered, for scripts and agents; the text output puts
//! names last so wide characters cannot break its columns.

mod client;
mod connections;
mod controller;
mod dns;
mod engine;
mod events;
mod format;
mod providers;
mod proxies;

use std::io::Write as _;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::client::Client;

/// The agent skill, also installable from `crates/meow-cli/skills/`.
const SKILL: &str = include_str!("../skills/meow-cli/SKILL.md");

#[derive(Parser)]
#[command(
    name = "meow-cli",
    version,
    about = "Control a running meow over its REST API",
    after_help = "Environment: MEOW_CONTROLLER (host:port), MEOW_CONFIG (config file), \
                  MEOW_SECRET (API secret)."
)]
struct Cli {
    #[command(flatten)]
    target: controller::Target,

    /// Print the API's JSON instead of text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Version, mode, log level, ports and traffic totals
    Status,
    /// Show the routing mode, or switch it
    Mode { mode: Option<Mode> },
    /// Show the log level, or change it
    LogLevel { level: Option<LogLevel> },
    /// Show whether the TUN inbound runs, or turn it on or off
    Tun { state: Option<Switch> },
    /// Proxy groups and the member each routes through
    #[command(subcommand)]
    Group(GroupCommand),
    /// Proxies, proxy-provider members included
    #[command(subcommand)]
    Proxy(ProxyCommand),
    /// Routing rules
    #[command(subcommand)]
    Rule(RuleCommand),
    /// Active connections
    #[command(subcommand, visible_alias = "connections")]
    Conn(ConnCommand),
    /// Lookups through meow's resolver, and its caches
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Proxy and rule providers
    #[command(subcommand)]
    Provider(ProviderCommand),
    /// Config subscriptions
    #[command(subcommand, visible_alias = "sub")]
    Subscription(SubscriptionCommand),
    /// Notable engine events, newest first: reloads, provider updates,
    /// failures (the logbook)
    Logbook(LogbookArgs),
    /// Follow the daemon's log
    Log {
        /// Lowest level to show
        #[arg(long, value_enum, default_value_t = LogLevel::Info)]
        level: LogLevel,
        /// Stop after this many lines
        #[arg(long)]
        count: Option<NonZeroUsize>,
    },
    /// Follow upload and download rates, once a second
    Traffic {
        /// Stop after this many samples
        #[arg(long)]
        count: Option<NonZeroUsize>,
    },
    /// Bytes each proxy carried since meow started
    Stats,
    /// Configured named listeners
    Listeners,
    /// Reload the config from a file
    Reload {
        /// Config to load [default: --config, else the one the running meow
        /// loaded]
        path: Option<PathBuf>,
        /// Apply the config even when its strict checks, TUN, listeners or
        /// DNS fail
        #[arg(long)]
        force: bool,
    },
    /// Print the agent skill (SKILL.md) that teaches meow-cli
    Skill,
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Every group with the member it routes through
    List,
    /// A group's members with their last delay
    Show { group: String },
    /// Route a group through one member; a url-test group keeps it as a pin
    /// until `unfix`, a fallback group while the member is up
    Select { group: String, member: String },
    /// Return a url-test or fallback group to its automatic choice
    Unfix { group: String },
    /// Delay-test every member; clears a url-test or fallback pin
    Test {
        group: String,
        #[command(flatten)]
        probe: Probe,
    },
}

#[derive(Subcommand)]
enum ProxyCommand {
    /// Every proxy with its type and last delay
    List {
        /// Only names, types or providers containing this text
        #[arg(long)]
        filter: Option<String>,
    },
    /// One proxy, with its delay history
    Show { name: String },
    /// Delay-test one proxy
    Test {
        name: String,
        #[command(flatten)]
        probe: Probe,
    },
}

#[derive(Args)]
struct Probe {
    /// URL to fetch through the proxy
    #[arg(long, default_value = "https://www.gstatic.com/generate_204")]
    url: String,
    /// Milliseconds before a member counts as failed, up to 65535
    #[arg(
        long,
        default_value_t = 5000,
        value_name = "MS",
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    probe_timeout: u16,
}

#[derive(Subcommand)]
enum RuleCommand {
    /// The rules in match order
    List {
        /// Only rules whose type, payload or target contains this text
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConnCommand {
    /// Open connections, oldest first
    List {
        /// Only connections whose host, address, process, rule or proxy
        /// contains this text
        #[arg(long)]
        filter: Option<String>,
    },
    /// One connection with its notes; open ones take an id prefix
    Show { id: String },
    /// Close connections by id (or a unique id prefix), or all of them
    Close {
        /// Ids, or unique starts of ids
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        ids: Vec<String>,
        /// Close every connection
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum DnsCommand {
    /// Resolve a name through meow's resolver
    Query {
        name: String,
        /// Record type: A, AAAA, CNAME, TXT, MX, HTTPS, …
        #[arg(short = 't', long = "type", default_value = "A")]
        qtype: String,
    },
    /// Cached answers
    Cache {
        /// Only names containing this text
        #[arg(long)]
        search: Option<String>,
        /// Answers to show
        #[arg(long, default_value_t = 256)]
        limit: usize,
    },
    /// Empty the DNS cache
    Flush,
    /// Drop every fake-IP mapping
    FlushFakeip,
}

#[derive(Subcommand)]
enum ProviderCommand {
    /// Proxy and rule providers
    List,
    /// Fetch a provider again
    Update {
        name: String,
        /// Which provider, when a proxy and a rule provider share the name
        #[arg(long, value_enum)]
        kind: Option<ProviderKind>,
    },
    /// Health-check a proxy provider's members
    Check { name: String },
}

#[derive(Subcommand)]
enum SubscriptionCommand {
    /// Subscriptions and what they contribute
    List,
    /// Fetch a subscription again and apply it
    Update { name: String },
}

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
struct LogbookArgs {
    #[command(subcommand)]
    action: Option<LogbookAction>,
    #[command(flatten)]
    query: LogbookQuery,
}

#[derive(Subcommand)]
enum LogbookAction {
    /// Delete every entry
    Clear,
}

const LOGBOOK_LIMIT: usize = 50;

#[derive(Args)]
struct LogbookQuery {
    /// Entries to show
    #[arg(long, default_value_t = LOGBOOK_LIMIT)]
    limit: usize,
    /// Lowest level to show
    #[arg(long, value_enum)]
    level: Option<EventLevel>,
    /// An event kind, or its area: `config` matches `config.reload`
    #[arg(long)]
    kind: Option<String>,
    /// What the event is about: a group, provider or listener name
    #[arg(long)]
    subject: Option<String>,
    /// Entries older than this id, to page back
    #[arg(long, value_name = "ID")]
    before: Option<u64>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Rule,
    Global,
    Direct,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

#[derive(Clone, Copy, ValueEnum)]
enum Switch {
    On,
    Off,
}

#[derive(Clone, Copy, ValueEnum)]
enum EventLevel {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProviderKind {
    Proxy,
    Rule,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Silent => "silent",
        }
    }
}

impl EventLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// What a command needs: the client and how to print.
pub struct Ctx {
    pub client: Client,
    pub json: bool,
}

impl Ctx {
    /// Prints `value` as JSON under `--json`, else as `render` reads it.
    pub fn show<T: DeserializeOwned>(
        &self,
        value: Value,
        render: impl FnOnce(T) -> anyhow::Result<String>,
    ) -> anyhow::Result<()> {
        if self.json {
            return print_json(&value);
        }
        let parsed = serde_json::from_value(value).context("meow answered in an unknown shape")?;
        print(&render(parsed)?)
    }

    /// Confirms an action in text mode; `--json` relies on the exit code.
    pub fn done(&self, message: &str) -> anyhow::Result<()> {
        if self.json {
            return Ok(());
        }
        print(&format!("{message}\n"))
    }
}

/// Writes to stdout; a reader that went away (`| head`) ends the program
/// quietly instead of with a panic.
pub fn print(text: &str) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        result => result.context("cannot write to stdout"),
    }
}

pub fn print_json(value: &Value) -> anyhow::Result<()> {
    print(&format!("{}\n", serde_json::to_string_pretty(value)?))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = if matches!(cli.command, Command::Skill) {
        print(SKILL)
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot start the async runtime")
            .and_then(|runtime| runtime.block_on(run(cli)))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("meow-cli: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let endpoint = cli.target.resolve()?;
    let config = endpoint.config.clone();
    let ctx = Ctx {
        client: Client::new(endpoint, Duration::from_secs(cli.target.timeout.max(1))),
        json: cli.json,
    };
    match cli.command {
        Command::Status => engine::status(&ctx).await,
        Command::Mode { mode } => engine::mode(&ctx, mode).await,
        Command::LogLevel { level } => engine::log_level(&ctx, level).await,
        Command::Tun { state } => engine::tun(&ctx, state).await,
        Command::Group(command) => match command {
            GroupCommand::List => proxies::group_list(&ctx).await,
            GroupCommand::Show { group } => proxies::group_show(&ctx, &group).await,
            GroupCommand::Select { group, member } => {
                proxies::group_select(&ctx, &group, &member).await
            }
            GroupCommand::Unfix { group } => proxies::group_unfix(&ctx, &group).await,
            GroupCommand::Test { group, probe } => proxies::group_test(&ctx, &group, &probe).await,
        },
        Command::Proxy(command) => match command {
            ProxyCommand::List { filter } => proxies::proxy_list(&ctx, filter.as_deref()).await,
            ProxyCommand::Show { name } => proxies::proxy_show(&ctx, &name).await,
            ProxyCommand::Test { name, probe } => proxies::proxy_test(&ctx, &name, &probe).await,
        },
        Command::Rule(RuleCommand::List { filter }) => engine::rules(&ctx, filter.as_deref()).await,
        Command::Conn(command) => match command {
            ConnCommand::List { filter } => connections::list(&ctx, filter.as_deref()).await,
            ConnCommand::Show { id } => connections::show(&ctx, &id).await,
            ConnCommand::Close { ids, all } => connections::close(&ctx, &ids, all).await,
        },
        Command::Dns(command) => match command {
            DnsCommand::Query { name, qtype } => dns::query(&ctx, &name, &qtype).await,
            DnsCommand::Cache { search, limit } => dns::cache(&ctx, search.as_deref(), limit).await,
            DnsCommand::Flush => dns::flush(&ctx, false).await,
            DnsCommand::FlushFakeip => dns::flush(&ctx, true).await,
        },
        Command::Provider(command) => match command {
            ProviderCommand::List => providers::list(&ctx).await,
            ProviderCommand::Update { name, kind } => providers::update(&ctx, &name, kind).await,
            ProviderCommand::Check { name } => providers::check(&ctx, &name).await,
        },
        Command::Subscription(command) => match command {
            SubscriptionCommand::List => providers::subscription_list(&ctx).await,
            SubscriptionCommand::Update { name } => {
                providers::subscription_update(&ctx, &name).await
            }
        },
        Command::Logbook(args) => match args.action {
            Some(LogbookAction::Clear) => events::logbook_clear(&ctx).await,
            None => events::logbook(&ctx, &args.query).await,
        },
        Command::Log { level, count } => events::log(&ctx, level, count).await,
        Command::Traffic { count } => events::traffic(&ctx, count).await,
        Command::Stats => events::stats(&ctx).await,
        Command::Listeners => engine::listeners(&ctx).await,
        Command::Reload { path, force } => {
            let path = path
                .or(config)
                .context("name the config to load: meow-cli reload <PATH>, or pass --config")?;
            engine::reload(&ctx, &path, force).await
        }
        Command::Skill => unreachable!("printed before the runtime starts"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::parser::ValueSource;
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// The skill keeps to the Agent Skills format (agentskills.io/specification):
    /// frontmatter with only the spec's fields, a `name` that matches its
    /// directory, a bounded `description`, and a body small enough to load
    /// whole.
    #[test]
    fn the_skill_follows_the_agent_skills_format() {
        const FIELDS: [&str; 6] = [
            "name",
            "description",
            "license",
            "compatibility",
            "metadata",
            "allowed-tools",
        ];
        // A Windows checkout may turn the newlines into CRLF.
        let text = SKILL.replace("\r\n", "\n");
        let (front, _body) = text
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .expect("SKILL.md opens with a `---` frontmatter block");
        let front: serde_yaml::Mapping = serde_yaml::from_str(front).unwrap();
        for key in front.keys() {
            let key = key.as_str().unwrap_or_default();
            assert!(
                FIELDS.contains(&key),
                "`{key}` is not an Agent Skills field"
            );
        }
        let field = |key: &str| front.get(key).and_then(serde_yaml::Value::as_str);

        // The directory: crates/meow-cli/skills/meow-cli/.
        assert_eq!(field("name"), Some("meow-cli"));
        let description = field("description").unwrap_or_default();
        assert!((1..=1024).contains(&description.chars().count()));
        let compatibility = field("compatibility").unwrap_or("x");
        assert!((1..=500).contains(&compatibility.chars().count()));
        assert!(text.lines().count() < 500, "keep SKILL.md under 500 lines");
    }

    /// Every `meow-cli …` line in the skill's code blocks must parse, so the
    /// skill cannot teach an agent a command that does not exist.
    #[test]
    fn every_skill_example_parses() {
        let examples = skill_examples();
        for words in &examples {
            if let Err(e) = Cli::try_parse_from(words) {
                panic!("skill example does not parse: {}\n{e}", words.join(" "));
            }
        }
        assert!(
            examples.len() >= 20,
            "only {} examples in SKILL.md",
            examples.len()
        );
    }

    /// Every command and every option shows up in an example, so an agent
    /// that reads only the skill knows all of meow-cli.
    #[test]
    fn the_skill_teaches_every_command_and_option() {
        let mut taught = BTreeSet::new();
        for words in skill_examples() {
            let matches = Cli::command()
                .try_get_matches_from(&words)
                .unwrap_or_else(|e| panic!("{}: {e}", words.join(" ")));
            let mut level = &matches;
            let mut path = Vec::new();
            loop {
                for id in level.ids() {
                    if level.value_source(id.as_str()) == Some(ValueSource::CommandLine) {
                        taught.insert(format!("--{id}"));
                        taught.insert(format!("{} --{id}", path.join(" ")));
                    }
                }
                let Some((name, sub)) = level.subcommand() else {
                    break;
                };
                path.push(name);
                level = sub;
            }
            taught.insert(path.join(" "));
        }
        let mut missing = Vec::new();
        untaught(&Cli::command(), "", &taught, &mut missing);
        assert!(
            missing.is_empty(),
            "SKILL.md has no example of: {missing:?}"
        );
    }

    /// What `taught` lacks of `command` and its subcommands: the command
    /// itself when it runs on its own, and each of its options.
    fn untaught(
        command: &clap::Command,
        path: &str,
        taught: &BTreeSet<String>,
        missing: &mut Vec<String>,
    ) {
        let runs_alone = !command.has_subcommands() || !command.is_subcommand_required_set();
        if !path.is_empty() && runs_alone && !taught.contains(path) {
            missing.push(path.to_string());
        }
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            // A global option counts wherever an example gives it.
            let key = if arg.is_global_set() {
                format!("--{id}")
            } else {
                format!("{path} --{id}")
            };
            if !taught.contains(&key) {
                let name = arg
                    .get_long()
                    .map_or_else(|| format!("<{id}>"), |long| format!("--{long}"));
                missing.push(format!("{path} {name}").trim().to_string());
            }
        }
        for sub in command.get_subcommands() {
            let sub_path = format!("{path} {}", sub.get_name());
            untaught(sub, sub_path.trim(), taught, missing);
        }
    }

    /// The `meow-cli` invocations in the skill's code blocks.
    fn skill_examples() -> Vec<Vec<String>> {
        let mut examples = Vec::new();
        let mut in_code = false;
        for line in SKILL.lines() {
            if line.trim_start().starts_with("```") {
                in_code = !in_code;
            } else if in_code {
                examples.extend(commands_in(line));
            }
        }
        examples
    }

    /// The `meow-cli` invocations on a shell line: split into words, with
    /// quotes, and cut at pipes, redirections and comments.
    fn commands_in(line: &str) -> Vec<Vec<String>> {
        let mut commands = Vec::new();
        let mut words = Vec::new();
        let mut word: Option<String> = None;
        let mut quote = None;
        for c in line.trim().chars() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (None, '"' | '\'') => {
                    quote = Some(c);
                    word.get_or_insert_default();
                }
                (None, ' ') => words.extend(word.take()),
                (None, '|' | ';' | '&') => {
                    words.extend(word.take());
                    take_command(&mut words, &mut commands);
                }
                // A redirection target or a comment: no command follows.
                (None, '>' | '<' | '#') => {
                    words.extend(word.take());
                    take_command(&mut words, &mut commands);
                    return commands;
                }
                // Any other character, quoted or not.
                (_, c) => word.get_or_insert_default().push(c),
            }
        }
        words.extend(word.take());
        take_command(&mut words, &mut commands);
        commands
    }

    /// Moves a finished command into `commands` when it runs meow-cli,
    /// past any `VAR=value` prefixes.
    fn take_command(words: &mut Vec<String>, commands: &mut Vec<Vec<String>>) {
        if let Some(start) = words.iter().position(|word| !word.contains('=')) {
            if words[start] == "meow-cli" {
                commands.push(words.split_off(start));
            }
        }
        words.clear();
    }
}
