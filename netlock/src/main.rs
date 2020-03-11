use std::env::args;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::ParseIntError;
use std::path::Path;
use std::slice::Iter;
use std::str::FromStr;

use netlock::pf;

mod flag {
    pub const HELP: &str = "h";
    pub const VERSION: &str = "V";
    pub const VERBOSE: &str = "v";
    pub const SKIPASS_LOOPBACK: &str = "0";
    pub const BLOCK_IPV6: &str = "6";
    pub const NO_LAN: &str = "l";
    pub const USE_ROUTING: &str = "r";
    pub const ANCHOR: &str = "a";
    pub const MINIMUM_TTL: &str = "t";
    pub const BLOCK: &str = "b";
    pub const SKIP: &str = "s";
    pub const PASS: &str = "p";
    pub const IN: &str = "i";
    pub const OUT: &str = "o";
    pub const PRINT: &str = "P";
    pub const ENABLE: &str = "E";
    pub const DISABLE: &str = "D";
    pub const LOAD: &str = "L";
    pub const STATUS: &str = "S";
}

mod metavar {
    pub const ANCHOR: &str = "ANCHOR";
    pub const TTL: &str = "TTL";
    pub const INTERFACE: &str = "INTERFACE";
    pub const DESTINATION: &str = "DESTINATION";
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
            _ => Err(format!("Invalid command value: `{}`", s)),
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
    Path::new(&args().next().unwrap_or_else(|| prog_name.into()))
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(prog_name)
        .into()
}

fn collect_to_string<T, V>(it: T) -> String
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
    let destination_help = "( ip | hostname | filepath )";
    let pass_help_interface = "tun0";
    let usage = format!(
        "{} [-{h}{V}{v}{O}{r}{q}{l}] [-{a} <{A}>] [-{t} <{T}>]\n\
         \t[.. -{s} <{I}>] [.. -{p} <{I}>]\n\
         \t[.. -{b} <{D}>] [.. -{i} <{D}>] [.. -{o} <{D}>]\n\
         \t-{{ {} }}\n\n\
         [-{h}] * Print help and exit\n\
         [-{V}] * Print version and exit\n\n\
         [-{v}] * Enable firewall logging\n\
         [-{O}] * Skipass on loopback\n\
         [-{r}] * Extend interface and destination from routing table\n\
         [-{q}] * Block IPv6\n\
         [-{l}] * No lan\n\
         [-{a}] * Use <{A}> (`{}` will be replaced with `{}`)\n\
         [-{t}] * Minimum <{T}>\n\
         [-{s}] * Skip on <{I}>\n\
         [-{p}] * Pass on <{I}> (can specify direction: `<{PH}` - in, `>{PH}` - out)\n\
         [-{b}] * Block <{D}> {DH}\n\
         [-{i}] * Pass in from <{D}> {DH}\n\
         [-{o}] * Pass out to <{D}> {DH}\n\n\
         [-{}] * Print rules and exit\n\
         [-{}] * Enable lock\n\
         [-{}] * Disable lock\n\
         [-{}] * Load lock\n\
         [-{}] * Show status",
        &get_prog_name(),
        &collect_to_string(Command::iter()),
        &pf::Manager::ANCHOR_REPLACE_FROM,
        &pf::Manager::ANCHOR_REPLACE_TO,
        &Command::Print.to_string(),
        &Command::Enable.to_string(),
        &Command::Disable.to_string(),
        &Command::Load.to_string(),
        &Command::Status.to_string(),
        h = flag::HELP,
        V = flag::VERSION,
        v = flag::VERBOSE,
        O = flag::SKIPASS_LOOPBACK,
        r = flag::USE_ROUTING,
        q = flag::BLOCK_IPV6,
        l = flag::NO_LAN,
        a = flag::ANCHOR,
        t = flag::MINIMUM_TTL,
        s = flag::SKIP,
        p = flag::PASS,
        b = flag::BLOCK,
        i = flag::IN,
        o = flag::OUT,
        A = metavar::ANCHOR,
        T = metavar::TTL,
        I = metavar::INTERFACE,
        D = metavar::DESTINATION,
        PH = pass_help_interface,
        DH = destination_help,
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

fn process_status(status: &pf::Status) -> Result<(), String> {
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
    let rules = status.rules();
    if !rules.is_empty() {
        let max_len = rules
            .iter()
            .flat_map(|s| s.lines())
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(0);
        let print_sep = || println!("{}", "-".repeat(max_len));
        print_sep();
        for rule in rules {
            print!("{}", rule);
            print_sep();
        }
        println!();
    }
    if !firewall_state || !netlock_state {
        return Err(format!(
            "{}: `{}`, {}: `{}`",
            firewall, firewall_state, netlock, netlock_state,
        ));
    }
    Ok(())
}

#[derive(Default)]
struct NSArgs {
    is_help: bool,
    is_version: bool,
    is_verbose: bool,
    is_skipass_loopback: bool,
    is_use_routing: bool,
    is_block_ipv6: bool,
    is_no_lan: bool,
    anchor: Option<String>,
    min_ttl: u8,
    command: Option<Command>,
    skip: Vec<String>,
    pass: Vec<pf::PassInterface>,
    block: Vec<String>,
    in_d: Vec<String>,
    out_d: Vec<String>,
}

fn parse_args() -> Result<NSArgs, String> {
    let argv = args().collect::<Vec<_>>();
    let argc = argv.len();
    if argc < 2 {
        print_usage(PrintDestination::Stderr);
        return Err("Not enough arguments".into());
    }
    let mut nsargs = NSArgs::default();
    let mut idx = 1;
    let err_missing_arg = |s: &str| Err(format!("Missing argument: {}", s));
    while idx < argc {
        let arg = &argv[idx];
        if !arg.starts_with('-') {
            return Err(format!("Invalid argument: `{}`", arg));
        }
        idx += 1;
        for sub_arg in arg.chars().skip(1).map(|c| c.to_string()) {
            match sub_arg.as_str() {
                flag::HELP => {
                    nsargs.is_help = true;
                    return Ok(nsargs);
                }
                flag::VERSION => {
                    nsargs.is_version = true;
                    return Ok(nsargs);
                }
                flag::VERBOSE => nsargs.is_verbose = true,
                flag::SKIPASS_LOOPBACK => nsargs.is_skipass_loopback = true,
                flag::USE_ROUTING => nsargs.is_use_routing = true,
                flag::BLOCK_IPV6 => nsargs.is_block_ipv6 = true,
                flag::NO_LAN => nsargs.is_no_lan = true,
                flag::ANCHOR => match argv.get(idx) {
                    Some(s) => {
                        nsargs.anchor = Some(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::ANCHOR),
                },
                flag::MINIMUM_TTL => match argv.get(idx) {
                    Some(s) => {
                        nsargs.min_ttl = s.parse().map_err(|e: ParseIntError| e.to_string())?;
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::TTL),
                },
                flag::SKIP => match argv.get(idx) {
                    Some(s) => {
                        nsargs.skip.push(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::INTERFACE),
                },
                flag::PASS => match argv.get(idx) {
                    Some(s) => {
                        nsargs.pass.push(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::INTERFACE),
                },
                flag::BLOCK => match argv.get(idx) {
                    Some(s) => {
                        nsargs.block.push(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::DESTINATION),
                },
                flag::IN => match argv.get(idx) {
                    Some(s) => {
                        nsargs.in_d.push(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::DESTINATION),
                },
                flag::OUT => match argv.get(idx) {
                    Some(s) => {
                        nsargs.out_d.push(s.into());
                        idx += 1;
                    }
                    _ => return err_missing_arg(metavar::DESTINATION),
                },
                s => match Command::from_str(s) {
                    Ok(cmd) => {
                        nsargs.command = Some(cmd);
                        match cmd {
                            Command::Disable | Command::Status => return Ok(nsargs),
                            _ => {}
                        }
                    }
                    _ => return Err(format!("Invalid argument: `{}`", arg)),
                },
            }
        }
    }
    if nsargs.command.is_some() {
        return Ok(nsargs);
    }
    err_missing_arg(&collect_to_string(Command::iter()))
}

type MainResult = Result<(), Box<dyn Error>>;

fn main() -> MainResult {
    let nsargs = parse_args()?;
    if nsargs.is_help {
        print_usage(PrintDestination::Stdout);
        return Ok(());
    }
    if nsargs.is_version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut loader = pf::Loader::default();
    let mut update_rules = || -> MainResult {
        let manager = loader.manager();
        if nsargs.is_skipass_loopback {
            if let Some(anchor) = &nsargs.anchor {
                manager.set_anchor(anchor);
            }
            manager.set_skipass_loopback()?;
        }
        if nsargs.is_use_routing {
            manager.extend_rules_from_routing_table()?;
        }
        let rules = manager.rules();
        rules.min_ttl = nsargs.min_ttl;
        rules.is_enable_log = nsargs.is_verbose;
        rules.is_block_ipv6 = nsargs.is_block_ipv6;
        if nsargs.is_no_lan {
            rules.lan = None;
        }
        rules.skip_interfaces.extend_from_slice(&nsargs.skip);
        rules.pass_interfaces.extend_from_slice(&nsargs.pass);
        rules.block_destinations.extend_from_slice(&nsargs.block);
        rules.in_destinations.extend_from_slice(&nsargs.in_d);
        rules.out_destinations.extend_from_slice(&nsargs.out_d);
        Ok(())
    };
    let print_ok = || println!("OK");
    match nsargs.command.expect("nsargs.command is None") {
        Command::Print => {
            update_rules()?;
            print!("{}", &loader.manager().rules().build());
        }
        Command::Enable => {
            update_rules()?;
            loader.enable(nsargs.anchor)?;
            print_ok();
        }
        Command::Disable => {
            loader.disable()?;
            print_ok();
        }
        Command::Load => {
            loader.load(nsargs.anchor)?;
            print_ok();
        }
        Command::Status => {
            process_status(&loader.get_status()?)?;
        }
    }
    Ok(())
}
