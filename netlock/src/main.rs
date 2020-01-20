use std::env::args;
use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::slice::Iter;
use std::str::FromStr;

use netlock::pf;

mod flag {
    pub const HELP: &str = "-h";
    pub const VERSION: &str = "-V";
    pub const SKIP: &str = "-s";
    pub const PASS: &str = "-p";
    pub const IN: &str = "-i";
    pub const OUT: &str = "-o";
    pub const PRINT: &str = "-P";
    pub const ENABLE: &str = "-e";
    pub const DISABLE: &str = "-d";
    pub const LOAD: &str = "-l";
}

mod metavar {
    pub const INTERFACE: &str = "INTERFACE";
    pub const DESTINATION: &str = "DESTINATION";
}

#[derive(Clone, Copy)]
enum Command {
    Print,
    Enable,
    Disable,
    Load,
}

impl Command {
    fn iter() -> Iter<'static, Self> {
        static COMMAND: [Command; 4] = [
            Command::Print,
            Command::Enable,
            Command::Disable,
            Command::Load,
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
    let usage = format!(
        "{} [{h}] [{v}] [.. {s} <{I}>] [.. {p} <{I}>] [.. {i} <{D}>] [.. {o} <{D}>]\n\
         \t{{ {} }}\n\n\
         [{h}] * Print help and exit\n\
         [{v}] * Print version and exit\n\n\
         [{s}] * Skip on <{I}>\n\
         [{p}] * Pass on <{I}>\n\
         [{i}] * Pass in from <{D}> (can be filepath)\n\
         [{o}] * Pass out to <{D}> (can be filepath)\n\n\
         [{}] * Print rules and exit\n\
         [{}] * Enable lock\n\
         [{}] * Disable lock\n\
         [{}] * Load lock",
        &get_prog_name(),
        &collect_to_string(Command::iter()),
        &Command::Print.to_string(),
        &Command::Enable.to_string(),
        &Command::Disable.to_string(),
        &Command::Load.to_string(),
        h = flag::HELP,
        v = flag::VERSION,
        s = flag::SKIP,
        p = flag::PASS,
        i = flag::IN,
        o = flag::OUT,
        I = metavar::INTERFACE,
        D = metavar::DESTINATION,
    );
    match to {
        PrintDestination::Stdout => println!("{}", &usage),
        PrintDestination::Stderr => eprintln!("{}", &usage),
    }
}

#[derive(Default)]
struct NSArgs {
    is_help: bool,
    is_version: bool,
    command: Option<Command>,
    skip: Vec<String>,
    pass: Vec<String>,
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
        let arg = argv[idx].as_str();
        idx += 1;
        match arg {
            flag::HELP => {
                nsargs.is_help = true;
                return Ok(nsargs);
            }
            flag::VERSION => {
                nsargs.is_version = true;
                return Ok(nsargs);
            }
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
                    if nsargs.command.is_some() {
                        return Err(format!(
                            "Command is already set: `{}`",
                            nsargs.command.expect("nsargs.command is None"),
                        ));
                    }
                    nsargs.command = Some(cmd);
                    match cmd {
                        Command::Disable | Command::Load => return Ok(nsargs),
                        _ => {}
                    }
                }
                _ => return Err(format!("Invalid argument: `{}`", arg)),
            },
        }
    }
    if nsargs.command.is_some() {
        return Ok(nsargs);
    }
    err_missing_arg(&collect_to_string(Command::iter()))
}

fn main() -> Result<(), String> {
    let nsargs = parse_args()?;
    if nsargs.is_help {
        print_usage(PrintDestination::Stdout);
        return Ok(());
    }
    if nsargs.is_version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut m = pf::Manager::default();
    m.opts.pass_interfaces.extend_from_slice(&nsargs.pass);
    m.opts.skip_interfaces.extend_from_slice(&nsargs.skip);
    m.opts.in_destinations.extend_from_slice(&nsargs.in_d);
    m.opts.out_destinations.extend_from_slice(&nsargs.out_d);
    let str_ok = "OK";
    match nsargs.command.expect("nsargs.command is None") {
        Command::Print => print!("{}", &m.opts.build()),
        Command::Enable => {
            m.enable().map_err(|e| e.to_string())?;
            println!("{}", str_ok);
        }
        Command::Disable => {
            m.disable().map_err(|e| e.to_string())?;
            println!("{}", str_ok);
        }
        Command::Load => {
            m.load().map_err(|e| e.to_string())?;
            println!("{}", str_ok);
        }
    }
    Ok(())
}
