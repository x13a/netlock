use std::collections::HashSet;
use std::env::args;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::slice::Iter;
use std::str::FromStr;

use netlock::pf;

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 64;

mod flag {
    pub const HELP: &str = "h";
    pub const VERSION: &str = "V";
    pub const VERBOSE: &str = "v";
    pub const SKIPASS_LOOPBACK: &str = "0";
    pub const BLOCK_IPV6: &str = "6";
    pub const NO_LAN: &str = "l";
    pub const USE_ROUTING: &str = "r";
    pub const CONFIG: &str = "c";
    pub const ANCHOR: &str = "a";
    pub const TTL: &str = "t";
    pub const SKIP: &str = "s";
    pub const PASS: &str = "p";
    pub const OWNER: &str = "O";
    pub const BLOCK: &str = "b";
    pub const IN: &str = "i";
    pub const OUT: &str = "o";
    pub const FILE: &str = "f";
    pub const PRINT: &str = "P";
    pub const ENABLE: &str = "E";
    pub const DISABLE: &str = "D";
    pub const LOAD: &str = "L";
    pub const STATUS: &str = "S";
}

mod metavar {
    pub const CONFIG_DIR: &str = "CONFIG_DIR";
    pub const ANCHOR: &str = "ANCHOR";
    pub const TTL: &str = "TTL";
    pub const INTERFACE: &str = "INTERFACE";
    pub const OWNER: &str = "OWNER";
    pub const DESTINATION: &str = "DESTINATION";
    pub const PATH: &str = "PATH";
}

#[derive(Clone, Copy)]
enum Command {
    Print,
    Enable,
    Disable,
    Load,
    Status,
}

impl Command {
    fn iter() -> Iter<'static, Self> {
        static COMMAND: [Command; 5] = [
            Command::Print,
            Command::Enable,
            Command::Disable,
            Command::Load,
            Command::Status,
        ];
        COMMAND.iter()
    }
}

impl FromStr for Command {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            flag::PRINT => Ok(Self::Print),
            flag::ENABLE => Ok(Self::Enable),
            flag::DISABLE => Ok(Self::Disable),
            flag::LOAD => Ok(Self::Load),
            flag::STATUS => Ok(Self::Status),
            _ => Err(format!("Invalid command: `{}`", s)),
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Print => write!(f, "{}", flag::PRINT),
            Self::Enable => write!(f, "{}", flag::ENABLE),
            Self::Disable => write!(f, "{}", flag::DISABLE),
            Self::Load => write!(f, "{}", flag::LOAD),
            Self::Status => write!(f, "{}", flag::STATUS),
        }
    }
}

fn get_prog_name() -> String {
    let prog_name = "PROG_NAME";
    Path::new(match &args().next() {
        Some(s) => s,
        None => return prog_name.into(),
    })
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or(prog_name)
    .into()
}

fn to_choices_string<T, V>(it: T) -> String
where
    T: Iterator<Item = V>,
    V: ToString,
{
    it.map(|v| v.to_string()).collect::<Vec<_>>().join(" | ")
}

enum PrintDestination {
    Stdout,
    Stderr,
}

fn print_usage(to: PrintDestination) {
    let usage = format!(
        "{} [-{h}{V}] [-{v}{v}] [-{Q}{r}{q}{l}] [-{c} <{C}>] [-{a} <{A}>] [-{t} <{T}>]\n\
         \t[.. -{s} <{I}>] [.. -{p} <{I}>] [.. -{O} <{W}>]\n\
         \t[.. -{b} <{D}>] [.. -{i} <{D}>] [.. -{o} <{D}>]\n\
         \t[.. -{f} <{P}>]\n\
         \t-{{ {} }}\n\n\
         [-{h}] * Print help and exit\n\
         [-{V}] * Print version and exit\n\n\
         [-{v}] * Verbose level (2 - enable firewall logging)\n\
         [-{Q}] * Skipass on loopback\n\
         [-{r}] * Extend outgoing <{I}> and <{D}> from routing table\n\
         [-{q}] * Block IPv6\n\
         [-{l}] * No lan\n\
         [-{c}] * Path to <{C}> (default: {})\n\
         [-{a}] * Use <{A}> (`{}` will be replaced with `{}`)\n\
         [-{t}] * Minimum outgoing <{T}>\n\
         [-{s}] * Skip on <{I}>\n\
         [-{p}] * Pass on <{I}>\n\
         [-{O}] * Pass owned by <{W}> ( {U} | {}{U} | {}GROUP )\n\
         [-{b}] * Block <{D}>\n\
         [-{i}] * Pass in from <{D}>\n\
         [-{o}] * Pass out to <{D}>\n\
         [-{f}] * Extend outgoing <{D}> from configuration <{P}>\n\n\
         [-{}] * Print rules and exit\n\
         [-{}] * Enable lock\n\
         [-{}] * Disable lock\n\
         [-{}] * Load lock\n\
         [-{}] * Show status\n\n\
         {I}:\n\
         \r  ( {N} | {}{N} | {}{N} ) direction only on pass\n\n\
         {D}:\n\
         \r  ( ip | host | file )\n\n\
         {P}:\n\
         \r  ( dir | file ) only .ovpn is supported, dir scan not recursive",
        &get_prog_name(),
        &to_choices_string(Command::iter()),
        &pf::DEFAULT_CONF_DIR,
        &pf::Manager::ANCHOR_REPLACE_FROM,
        &pf::Manager::ANCHOR_REPLACE_TO,
        &pf::Owner::USER,
        &pf::Owner::GROUP,
        &Command::Print,
        &Command::Enable,
        &Command::Disable,
        &Command::Load,
        &Command::Status,
        &pf::Direction::IN,
        &pf::Direction::OUT,
        h = flag::HELP,
        V = flag::VERSION,
        v = flag::VERBOSE,
        Q = flag::SKIPASS_LOOPBACK,
        r = flag::USE_ROUTING,
        q = flag::BLOCK_IPV6,
        l = flag::NO_LAN,
        c = flag::CONFIG,
        a = flag::ANCHOR,
        t = flag::TTL,
        s = flag::SKIP,
        p = flag::PASS,
        O = flag::OWNER,
        b = flag::BLOCK,
        i = flag::IN,
        o = flag::OUT,
        f = flag::FILE,
        C = metavar::CONFIG_DIR,
        A = metavar::ANCHOR,
        T = metavar::TTL,
        I = metavar::INTERFACE,
        W = metavar::OWNER,
        D = metavar::DESTINATION,
        P = metavar::PATH,
        U = "USER",
        N = "NAME",
    );
    match to {
        PrintDestination::Stdout => println!("{}", &usage),
        PrintDestination::Stderr => eprintln!("{}", &usage),
    }
}

pub enum Color<'a> {
    Red(&'a str),
    Green(&'a str),
}

impl<'a> Color<'_> {
    const ENDC: &'a str = "\x1b[0m";
    const RED: &'a str = "\x1b[31m";
    const GREEN: &'a str = "\x1b[32m";
}

impl Display for Color<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Red(s) => write!(f, "{}{}{}", Self::RED, s, Self::ENDC),
            Self::Green(s) => write!(f, "{}{}{}", Self::GREEN, s, Self::ENDC),
        }
    }
}

fn process_status(status: &pf::Status, is_verbose: bool) -> Result<(), Box<dyn Error>> {
    let display_state = |v: bool| {
        if v {
            Color::Green("ENABLED")
        } else {
            Color::Red("DISABLED")
        }
    };
    let firewall = "firewall";
    let netlock = "netlock";
    let firewall_state = status.firewall_state();
    let netlock_state = status.netlock_state();
    println!(
        "\n\
         {:width$} {}\n\
         {:width$} {}*\n",
        &firewall.to_uppercase(),
        &display_state(firewall_state),
        &netlock.to_uppercase(),
        &display_state(netlock_state),
        width = firewall.chars().count().max(netlock.chars().count()),
    );
    if is_verbose {
        let rules = status.rules();
        if !rules.is_empty() {
            let max_len = rules
                .iter()
                .map(|(k, v)| {
                    (if k.is_empty() {
                        0
                    } else {
                        k.chars().count() + 2
                    })
                    .max(v.lines().map(|s| s.chars().count()).max().unwrap_or(0))
                })
                .max()
                .unwrap_or(0);
            let print_sep = || println!("{}", "-".repeat(max_len));
            print_sep();
            for (k, v) in rules {
                if !k.is_empty() {
                    println!("[{}]\n", k);
                }
                print!("{}", v);
                print_sep();
            }
            println!();
        }
    }
    if !firewall_state || !netlock_state {
        return Err(format!(
            "{}: `{}`, {}: `{}`",
            firewall, firewall_state, netlock, netlock_state,
        )
        .into());
    }
    Ok(())
}

#[derive(Default)]
struct Opts {
    verbose: u8,
    is_skipass_loopback: bool,
    is_use_routing: bool,
    is_block_ipv6: bool,
    is_no_lan: bool,
    conf_dir: Option<PathBuf>,
    anchor: Option<String>,
    ttl: u8,
    command: Option<Command>,
    skip: HashSet<String>,
    pass: HashSet<pf::Direction>,
    owners: HashSet<pf::Owner>,
    block: HashSet<String>,
    destinations: HashSet<pf::Direction>,
    files: HashSet<PathBuf>,
}

fn parse_args() -> Result<Opts, Box<dyn Error>> {
    let mut argv = args().skip(1);
    if argv.len() == 0 {
        print_usage(PrintDestination::Stderr);
        return Err("Not enough arguments".into());
    }
    let mut opts = Opts::default();
    let err_missing_arg = |s: &str| Err(format!("Missing argument: {}", s).into());
    loop {
        let arg = match argv.next() {
            Some(s) => s,
            None => break,
        };
        if !arg.starts_with('-') {
            return Err(format!("Invalid argument: `{}`", arg).into());
        }
        for sub_arg in arg.chars().skip(1).map(|c| c.to_string()) {
            match sub_arg.as_str() {
                flag::HELP => {
                    print_usage(PrintDestination::Stdout);
                    exit(EX_OK);
                }
                flag::VERSION => {
                    println!("{}", env!("CARGO_PKG_VERSION"));
                    exit(EX_OK);
                }
                flag::VERBOSE => opts.verbose += 1,
                flag::SKIPASS_LOOPBACK => opts.is_skipass_loopback = true,
                flag::USE_ROUTING => opts.is_use_routing = true,
                flag::BLOCK_IPV6 => opts.is_block_ipv6 = true,
                flag::NO_LAN => opts.is_no_lan = true,
                flag::CONFIG => match argv.next() {
                    Some(s) => opts.conf_dir = Some(s.into()),
                    None => return err_missing_arg(metavar::CONFIG_DIR),
                },
                flag::ANCHOR => match argv.next() {
                    Some(s) => opts.anchor = s.into(),
                    None => return err_missing_arg(metavar::ANCHOR),
                },
                flag::TTL => match argv.next() {
                    Some(s) => opts.ttl = s.parse()?,
                    None => return err_missing_arg(metavar::TTL),
                },
                flag::SKIP => match argv.next() {
                    Some(s) => {
                        opts.skip.insert(s);
                    }
                    None => return err_missing_arg(metavar::INTERFACE),
                },
                flag::PASS => match argv.next() {
                    Some(s) => {
                        opts.pass.insert(s.into());
                    }
                    None => return err_missing_arg(metavar::INTERFACE),
                },
                flag::OWNER => match argv.next() {
                    Some(s) => {
                        opts.owners.insert(s.into());
                    }
                    None => return err_missing_arg(metavar::OWNER),
                },
                flag::BLOCK => match argv.next() {
                    Some(s) => {
                        opts.block.insert(s);
                    }
                    None => return err_missing_arg(metavar::DESTINATION),
                },
                flag::IN => match argv.next() {
                    Some(s) => {
                        opts.destinations.insert(pf::Direction::new(s).to_in());
                    }
                    None => return err_missing_arg(metavar::DESTINATION),
                },
                flag::OUT => match argv.next() {
                    Some(s) => {
                        opts.destinations.insert(pf::Direction::new(s).to_out());
                    }
                    None => return err_missing_arg(metavar::DESTINATION),
                },
                flag::FILE => match argv.next() {
                    Some(s) => {
                        opts.files.insert(s.into());
                    }
                    None => return err_missing_arg(metavar::PATH),
                },
                s => match Command::from_str(s) {
                    Ok(cmd) => opts.command = cmd.into(),
                    err => {
                        err?;
                    }
                },
            }
        }
    }
    if opts.command.is_some() {
        return Ok(opts);
    }
    err_missing_arg(&format!("-{{ {} }}", &to_choices_string(Command::iter())))
}

type MainResult = Result<(), Box<dyn Error>>;

fn update_rules(loader: &mut pf::Loader, opts: &Opts) -> MainResult {
    let manager = loader.manager();
    manager.is_log = opts.verbose > 0;
    if opts.is_skipass_loopback {
        if let Some(anchor) = &opts.anchor {
            manager.set_anchor(anchor);
        }
        manager.set_skipass_loopback()?;
    }
    if opts.is_use_routing {
        manager.extend_rules_from_routing_table()?;
    }
    let rules = manager.rules();
    rules.min_ttl = opts.ttl;
    rules.is_enable_log = opts.verbose > 1;
    rules.is_block_ipv6 = opts.is_block_ipv6;
    if opts.is_no_lan {
        rules.lan = None;
    }
    rules.skip_interfaces.extend(opts.skip.iter().cloned());
    rules.pass_interfaces.extend(opts.pass.iter().cloned());
    rules.pass_owners = opts.owners.clone();
    rules.block_destinations = opts.block.clone();
    rules
        .pass_destinations
        .extend(opts.destinations.iter().cloned());
    manager.extend_rules_from_configuration_files(&opts.files.iter().collect::<Vec<_>>())?;
    Ok(())
}

fn main() -> MainResult {
    let opts = match parse_args() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("{}", err.to_string());
            exit(EX_USAGE);
        }
    };
    let mut loader = match &opts.conf_dir {
        Some(path) => pf::Loader::new(path, Default::default()),
        None => Default::default(),
    };
    let print_ok = || println!("OK");
    match opts.command.expect("opts.command is None") {
        Command::Print => {
            update_rules(&mut loader, &opts)?;
            print!("{}", &loader.manager().rules().build());
        }
        Command::Enable => {
            update_rules(&mut loader, &opts)?;
            loader.enable(opts.anchor)?;
            print_ok();
        }
        Command::Disable => {
            loader.disable()?;
            print_ok();
        }
        Command::Load => {
            loader.load(opts.anchor)?;
            print_ok();
        }
        Command::Status => {
            process_status(&loader.get_status()?, opts.verbose > 0)?;
        }
    }
    Ok(())
}
