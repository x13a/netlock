use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{create_dir_all, write, File};
use std::io::{self, LineWriter, Result as IoResult, Write as IoWrite};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::gvars;
use crate::tools::{get_destinations_from_configuration_files, get_useful_routing_table_info};
use crate::utils::{exec, exec_stdin, read_lines, time, ExecResult, ExpandUser, IsExecutable};

pub use crate::gvars::DEFAULT_CONF_DIR;
pub use crate::tools::{Direction, Owner};

pub struct Loader {
    conf_dir: PathBuf,
    manager: Manager,
}

impl<'a> Loader {
    const SETTINGS_SEP: char = ':';
    const SETTINGS_MANAGER_STATE: &'a str = "MANAGER_STATE";
    const SETTINGS_MANAGER_ANCHOR: &'a str = "MANAGER_ANCHOR";
    #[cfg(not(target_os = "macos"))]
    const SETTINGS_CTL_STATE: &'a str = "CTL_STATE";
    #[cfg(target_os = "macos")]
    const SETTINGS_CTL_TOKEN: &'a str = "CTL_TOKEN";

    pub fn new(conf_dir: impl Into<PathBuf>, manager: Manager) -> Self {
        let conf_dir = conf_dir.into().expanduser();
        assert!(!conf_dir.starts_with("~"));
        Self { conf_dir, manager }
    }

    pub fn enable(&mut self, anchor: Option<impl AsRef<str>>) -> ExecResult<()> {
        let _ = self.load_settings_conf();
        let rules = &self.manager.rules.build();
        self.manager.load(LoadFile::Stdin(rules), anchor)?;
        self.make_firewall_conf(Some(rules))?;
        self.make_settings_conf()?;
        Ok(())
    }

    pub fn disable(&mut self) -> ExecResult<()> {
        self.load_settings_conf()?;
        self.manager.disable()?;
        self.make_settings_conf()?;
        Ok(())
    }

    pub fn load(&mut self, anchor: Option<impl AsRef<str>>) -> ExecResult<()> {
        self.load_settings_conf()?;
        self.manager
            .load(LoadFile::Path(&self.get_firewall_conf_path()), anchor)?;
        self.make_settings_conf()?;
        Ok(())
    }

    pub fn get_status(&mut self) -> ExecResult<Status> {
        let _ = self.load_settings_conf();
        self.manager.get_status()
    }

    pub fn manager(&mut self) -> &mut Manager {
        &mut self.manager
    }

    fn make_firewall_conf(&self, content: Option<&str>) -> io::Result<()> {
        create_dir_all(&self.conf_dir)?;
        let conf_path = &self.get_firewall_conf_path();
        match content {
            Some(rules) => write(conf_path, rules),
            None => write(conf_path, &self.manager.rules.build()),
        }
    }

    fn make_settings_conf(&self) -> io::Result<()> {
        create_dir_all(&self.conf_dir)?;
        let conf_path = &self.get_settings_conf_path();
        let mut file = LineWriter::new(File::create(conf_path)?);
        for (k, v) in &[
            (
                Self::SETTINGS_MANAGER_STATE,
                &self.manager.state.to_string(),
            ),
            (Self::SETTINGS_MANAGER_ANCHOR, &self.manager.anchor),
            #[cfg(not(target_os = "macos"))]
            (
                Self::SETTINGS_CTL_STATE,
                &self.manager.ctl.state.to_string(),
            ),
            #[cfg(target_os = "macos")]
            (Self::SETTINGS_CTL_TOKEN, &self.manager.ctl.token),
        ] {
            writeln!(&mut file, "{}{}{}", k, Self::SETTINGS_SEP, v)?;
        }
        Ok(())
    }

    fn load_settings_conf(&mut self) -> io::Result<()> {
        for line in read_lines(&self.get_settings_conf_path())? {
            let line = line?;
            if line.starts_with('#') {
                continue;
            }
            let option = line.split(Self::SETTINGS_SEP).collect::<Vec<_>>();
            if option.len() != 2 {
                continue;
            }
            match option[0] {
                Self::SETTINGS_MANAGER_STATE => {
                    self.manager.state = option[1].parse().unwrap_or(self.manager.state)
                }
                Self::SETTINGS_MANAGER_ANCHOR => self.manager.anchor = option[1].into(),
                #[cfg(not(target_os = "macos"))]
                Self::SETTINGS_CTL_STATE => {
                    self.manager.ctl.state = option[1].parse().unwrap_or(self.manager.ctl.state);
                }
                #[cfg(target_os = "macos")]
                Self::SETTINGS_CTL_TOKEN => self.manager.ctl.token = option[1].into(),
                _ => {}
            }
        }
        Ok(())
    }

    fn get_firewall_conf_path(&self) -> PathBuf {
        self.conf_dir.join(gvars::FIREWALL_CONF_FILE_NAME)
    }

    fn get_settings_conf_path(&self) -> PathBuf {
        self.conf_dir.join(gvars::SETTINGS_CONF_FILE_NAME)
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new(gvars::DEFAULT_CONF_DIR, Default::default())
    }
}

pub struct Status {
    firewall_state: bool,
    netlock_state: bool,
    rules: HashMap<String, String>,
}

impl Status {
    pub fn firewall_state(&self) -> bool {
        self.firewall_state
    }

    pub fn netlock_state(&self) -> bool {
        self.netlock_state
    }

    pub fn rules(&self) -> &HashMap<String, String> {
        &self.rules
    }
}

pub struct Manager {
    state: bool,
    anchor: String,
    pub is_log: bool,
    ctl: Ctl,
    rules: Rules,
}

impl<'a> Manager {
    pub const ANCHOR_REPLACE_FROM: &'a str = "$";
    pub const ANCHOR_REPLACE_TO: &'a str = "248.netlock";

    pub fn new(ctl: Ctl, rules: Rules) -> Self {
        Self {
            state: false,
            anchor: "".into(),
            is_log: false,
            ctl,
            rules,
        }
    }

    pub fn enable(&mut self, new_anchor: Option<impl AsRef<str>>) -> ExecResult<()> {
        self.load(LoadFile::Stdin(&self.rules.build()), new_anchor)
    }

    pub fn disable(&mut self) -> ExecResult<()> {
        self.disable_firewall()?;
        self.reset(&self.anchor)?;
        self.state = false;
        Ok(())
    }

    pub fn get_status(&self) -> ExecResult<Status> {
        let mut netlock_state = self.state;
        let mut rules = HashMap::new();
        let main_ruleset = self.ctl.show(ShowModifier::Rules, "", false)?;
        if !main_ruleset.is_empty() {
            let mr_anchor = "";
            rules.insert(mr_anchor.to_string(), main_ruleset);
            if self.anchor.is_empty() {
                if netlock_state {
                    let mut has_block_table = false;
                    let mut has_in_table = false;
                    let mut has_out_table = false;
                    let to_table_pat = |s: &str| format!("<{}>", s);
                    let block_table_pat = &to_table_pat(&self.rules.block_table_name);
                    let in_table_pat = &to_table_pat(&self.rules.in_table_name);
                    let out_table_pat = &to_table_pat(&self.rules.out_table_name);
                    for line in rules[mr_anchor].lines() {
                        if !has_block_table && line.contains(block_table_pat) {
                            has_block_table = true;
                        } else if !has_in_table && line.contains(in_table_pat) {
                            has_in_table = true;
                        } else if !has_out_table && line.contains(out_table_pat) {
                            has_out_table = true;
                        }
                        if has_block_table && has_in_table && has_out_table {
                            break;
                        }
                    }
                    netlock_state &= has_block_table && has_in_table && has_out_table;
                }
                if netlock_state {
                    let mut has_block_table = false;
                    let mut has_in_table = false;
                    let mut has_out_table = false;
                    for table in self
                        .ctl
                        .show(ShowModifier::Tables, mr_anchor, false)?
                        .split_whitespace()
                    {
                        if !has_block_table && table == self.rules.block_table_name {
                            has_block_table = true;
                        } else if !has_in_table && table == self.rules.in_table_name {
                            has_in_table = true;
                        } else if !has_out_table && table == self.rules.out_table_name {
                            has_out_table = true;
                        }
                        if has_block_table && has_in_table && has_out_table {
                            break;
                        }
                    }
                    netlock_state &= has_block_table && has_in_table && has_out_table;
                }
            } else {
                for anchor in self
                    .ctl
                    .show(ShowModifier::Anchors, "", true)?
                    .split_whitespace()
                {
                    let ruleset = self.ctl.show(ShowModifier::Rules, anchor, false)?;
                    if !ruleset.is_empty() {
                        rules.insert(anchor.into(), ruleset);
                    }
                }
            }
        } else {
            netlock_state = false;
        }
        Ok(Status {
            firewall_state: self.ctl.is_enabled()?,
            netlock_state,
            rules,
        })
    }

    pub fn state(&self) -> bool {
        self.state
    }

    pub fn anchor(&self) -> &str {
        &self.anchor
    }

    pub fn set_anchor(&mut self, anchor: impl AsRef<str>) -> bool {
        if self.state {
            return false;
        }
        self.anchor = self.format_anchor(anchor.as_ref());
        true
    }

    pub fn rules(&mut self) -> &mut Rules {
        &mut self.rules
    }

    pub fn set_skipass_loopback(&mut self) -> ExecResult<()> {
        let loopback_group = "lo".to_string();
        if self.anchor.is_empty() {
            self.rules.skip_interfaces.insert(loopback_group);
        } else {
            for interface in self
                .ctl
                .show(ShowModifier::Interfaces(&loopback_group), "", true)?
                .lines()
                .map(|s| s.split_whitespace().collect::<Vec<_>>())
                .filter(|v| v.len() == 1) // v[1] == "(skip)"
                .map(|v| v[0])
            {
                if self.is_log {
                    eprintln!("[skipass_loopback] interface: `{}`", interface);
                }
                self.rules.pass_interfaces.insert(interface.into());
            }
        }
        Ok(())
    }

    pub fn extend_rules_from_routing_table(&mut self) -> ExecResult<()> {
        let info = get_useful_routing_table_info()?;
        let interface = info.interface();
        if !interface.is_empty() {
            self.rules
                .pass_interfaces
                .insert(Direction::new(interface).to_out());
        }
        let destination = info.destination();
        if !destination.is_empty() {
            self.rules
                .pass_destinations
                .insert(Direction::new(destination).to_out());
        }
        if self.is_log {
            eprintln!(
                "[routing_table] interface: `{}`, destination: `{}`",
                interface, destination,
            );
        }
        Ok(())
    }

    pub fn extend_rules_from_configuration_files(
        &mut self,
        paths: &[impl AsRef<Path>],
    ) -> io::Result<()> {
        for destination in &get_destinations_from_configuration_files(paths)? {
            if self.is_log {
                eprintln!("[configuration_files] destination: `{}`", destination);
            }
            self.rules
                .pass_destinations
                .insert(Direction::new(destination).to_out());
        }
        Ok(())
    }

    fn load(&mut self, file: LoadFile, new_anchor: Option<impl AsRef<str>>) -> ExecResult<()> {
        self.enable_firewall()?;
        match new_anchor {
            Some(new_anchor) => {
                let anchor = self.anchor.clone();
                let new_anchor = self.format_anchor(new_anchor.as_ref());
                self.ctl.load(file, &new_anchor)?;
                if self.state && anchor != new_anchor {
                    self.reset(&anchor)?;
                }
                self.anchor = new_anchor;
            }
            None => self.ctl.load(file, &self.anchor)?,
        }
        self.state = true;
        self.ctl.flush(FlushModifier::States, "")?;
        Ok(())
    }

    fn format_anchor(&self, anchor: &str) -> String {
        anchor.replace(Self::ANCHOR_REPLACE_FROM, Self::ANCHOR_REPLACE_TO)
    }

    fn reset(&self, anchor: &str) -> ExecResult<()> {
        if anchor.is_empty() {
            self.ctl.load(LoadFile::Path(&self.ctl.conf_path), "")
        } else {
            self.ctl.flush(FlushModifier::All, anchor)
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn enable_firewall(&mut self) -> ExecResult<()> {
        if !self.ctl.is_enabled()? {
            self.ctl.enable()?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable_firewall(&mut self) -> ExecResult<()> {
        if !self.ctl.check_token()? {
            self.ctl.enable()?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn disable_firewall(&mut self) -> ExecResult<()> {
        if self.ctl.state && self.ctl.is_enabled()? {
            self.ctl.disable()?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_firewall(&mut self) -> ExecResult<()> {
        if self.ctl.check_token()? {
            self.ctl.disable()?;
        }
        Ok(())
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

enum ShowModifier<'a> {
    Rules,
    Anchors,
    States,
    Info,
    References,
    Labels,
    Tables,
    Interfaces(&'a str),
}

impl<'a> ShowModifier<'_> {
    const RULES: &'a str = "rules";
    const ANCHORS: &'a str = "Anchors";
    const STATES: &'a str = "states";
    const INFO: &'a str = "info";
    const REFERENCES: &'a str = "References";
    const LABELS: &'a str = "labels";
    const TABLES: &'a str = "Tables";
    const INTERFACES: &'a str = "Interfaces";
}

impl Display for ShowModifier<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rules => write!(f, "{}", Self::RULES),
            Self::Anchors => write!(f, "{}", Self::ANCHORS),
            Self::States => write!(f, "{}", Self::STATES),
            Self::Info => write!(f, "{}", Self::INFO),
            Self::References => write!(f, "{}", Self::REFERENCES),
            Self::Labels => write!(f, "{}", Self::LABELS),
            Self::Tables => write!(f, "{}", Self::TABLES),
            Self::Interfaces(_) => write!(f, "{}", Self::INTERFACES),
        }
    }
}

enum FlushModifier {
    Rules,
    States,
    Tables,
    All,
}

impl<'a> FlushModifier {
    const RULES: &'a str = "rules";
    const STATES: &'a str = "states";
    const TABLES: &'a str = "Tables";
    const ALL: &'a str = "all";
}

impl Display for FlushModifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rules => write!(f, "{}", Self::RULES),
            Self::States => write!(f, "{}", Self::STATES),
            Self::Tables => write!(f, "{}", Self::TABLES),
            Self::All => write!(f, "{}", Self::ALL),
        }
    }
}

enum LoadFile<'a> {
    Path(&'a Path),
    Stdin(&'a str),
}

// enum TableCommand {
//     Flush,
//     Add,
//     Delete,
//     Replace,
//     Show,
//     Test,
// }
//
// impl<'a> TableCommand {
//     const FLUSH: &'a str = "flush";
//     const ADD: &'a str = "add";
//     const DELETE: &'a str = "delete";
//     const REPLACE: &'a str = "replace";
//     const SHOW: &'a str = "show";
//     const TEST: &'a str = "test";
// }
//
// impl Display for TableCommand {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         match self {
//             Self::Flush => write!(f, "{}", Self::FLUSH),
//             Self::Add => write!(f, "{}", Self::ADD),
//             Self::Delete => write!(f, "{}", Self::DELETE),
//             Self::Replace => write!(f, "{}", Self::REPLACE),
//             Self::Show => write!(f, "{}", Self::SHOW),
//             Self::Test => write!(f, "{}", Self::TEST),
//         }
//     }
// }

pub struct Ctl {
    ctl_path: PathBuf,
    conf_path: PathBuf,
    #[cfg(not(target_os = "macos"))]
    state: bool,
    #[cfg(target_os = "macos")]
    token: String,
}

impl<'a> Ctl {
    pub const DEFAULT_CTL_PATH: &'a str = "/sbin/pfctl";
    pub const DEFAULT_CONF_PATH: &'a str = "/etc/pf.conf";

    #[cfg(not(target_os = "macos"))]
    const FLAG_ENABLE: &'a str = "-e";
    #[cfg(target_os = "macos")]
    const FLAG_ENABLE: &'a str = "-E";
    #[cfg(not(target_os = "macos"))]
    const FLAG_DISABLE: &'a str = "-d";
    #[cfg(target_os = "macos")]
    const FLAG_DISABLE: &'a str = "-X";
    const FLAG_SHOW: &'a str = "-s";
    const FLAG_ANCHOR: &'a str = "-a";
    const FLAG_FLUSH: &'a str = "-F";
    const FLAG_FILE: &'a str = "-f";
    const FLAG_VERBOSE: &'a str = "-v";
    const FLAG_INTERFACE: &'a str = "-i";
    // const FLAG_TABLE: &'a str = "-t";
    // const FLAG_TABLE_COMMAND: &'a str = "-T";

    pub fn new<P: Into<PathBuf>>(ctl_path: P, conf_path: P) -> Self {
        let ctl_path = ctl_path.into();
        assert!(ctl_path.is_executable());
        let conf_path = conf_path.into().expanduser();
        assert!(conf_path.is_file() && !conf_path.starts_with("~"));
        Self {
            ctl_path,
            conf_path,
            #[cfg(not(target_os = "macos"))]
            state: false,
            #[cfg(target_os = "macos")]
            token: "".into(),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn enable(&mut self) -> ExecResult<()> {
        self.exec(&[Self::FLAG_ENABLE])?;
        self.state = true;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable(&mut self) -> ExecResult<()> {
        let mut token = String::new();
        for opt in String::from_utf8_lossy(&self.exec(&[Self::FLAG_ENABLE])?.stderr)
            .to_lowercase()
            .lines()
            .filter(|&s| s.contains("token :"))
            .map(|s| s.split(':').nth(1))
        {
            if let Some(s) = &opt {
                token = s.trim().into();
                break;
            }
        }
        assert!(!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()));
        self.token = token;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn disable(&mut self) -> ExecResult<()> {
        self.exec(&[Self::FLAG_DISABLE])?;
        self.state = false;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable(&mut self) -> ExecResult<bool> {
        assert!(!self.token.is_empty());
        let is_disabled =
            String::from_utf8_lossy(&self.exec(&[Self::FLAG_DISABLE, &self.token])?.stderr)
                .to_lowercase()
                .contains("pf disabled");
        self.token.clear();
        Ok(is_disabled)
    }

    fn is_enabled(&self) -> ExecResult<bool> {
        Ok(self
            .show(ShowModifier::Info, "", false)?
            .to_lowercase()
            .contains("status: enabled"))
    }

    #[cfg(target_os = "macos")]
    fn check_token(&self) -> ExecResult<bool> {
        if self.token.is_empty() {
            return Ok(false);
        }
        Ok(self
            .show(ShowModifier::References, "", false)?
            .contains(&self.token))
    }

    fn flush(&self, modifier: FlushModifier, anchor: &str) -> ExecResult<()> {
        let modifier = &modifier.to_string();
        let mut args = vec![Self::FLAG_FLUSH, modifier];
        if !anchor.is_empty() {
            args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
        }
        self.exec(&args)?;
        Ok(())
    }

    fn load(&self, file: LoadFile, anchor: &str) -> ExecResult<()> {
        match file {
            LoadFile::Path(path) => {
                let mut args = vec![OsStr::new(Self::FLAG_FILE), path.as_os_str()];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[OsStr::new(Self::FLAG_ANCHOR), OsStr::new(anchor)]);
                }
                self.exec(&args)?;
            }
            LoadFile::Stdin(rules) => {
                let mut args = vec![Self::FLAG_FILE, "-"];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
                }
                exec_stdin(&self.ctl_path, &args, rules)?;
            }
        }
        Ok(())
    }

    fn show(&self, modifier: ShowModifier, anchor: &str, verbose: bool) -> ExecResult<String> {
        let modifier_ptr = &modifier.to_string();
        let mut args = vec![Self::FLAG_SHOW, modifier_ptr];
        if !anchor.is_empty() {
            args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
        }
        if verbose {
            args.push(Self::FLAG_VERBOSE);
        }
        if let ShowModifier::Interfaces(interface) = modifier {
            if !interface.is_empty() {
                args.extend_from_slice(&[Self::FLAG_INTERFACE, interface]);
            }
        }
        Ok(String::from_utf8_lossy(&self.exec(&args)?.stdout).into())
    }

    // fn exec_table<S: AsRef<str>>(
    //     &self,
    //     table: &str,
    //     command: TableCommand,
    //     addresses: &[S],
    //     anchor: &str,
    // ) -> ExecResult<Output> {
    //     let mut args = vec![Self::FLAG_TABLE, table];
    //     if !anchor.is_empty() {
    //         args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
    //     }
    //     let command = command.to_string();
    //     args.extend_from_slice(&[Self::FLAG_TABLE_COMMAND, &command]);
    //     for address in addresses.iter().map(|s| s.as_ref()) {
    //         if address.starts_with('/') {
    //             args.extend_from_slice(&[Self::FLAG_FILE, address]);
    //         } else {
    //             args.push(address);
    //         }
    //     }
    //     self.exec(&args)
    // }

    fn exec<S: AsRef<OsStr>>(&self, args: &[S]) -> ExecResult<Output> {
        exec(&self.ctl_path, args)
    }
}

impl Default for Ctl {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CTL_PATH, Self::DEFAULT_CONF_PATH)
    }
}

pub enum BlockPolicy {
    Drop,
    Return,
}

impl<'a> BlockPolicy {
    const DROP: &'a str = "drop";
    const RETURN: &'a str = "return";
}

impl Display for BlockPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drop => write!(f, "{}", Self::DROP),
            Self::Return => write!(f, "{}", Self::RETURN),
        }
    }
}

impl Default for BlockPolicy {
    fn default() -> Self {
        Self::Drop
    }
}

pub enum StatePolicy {
    IfBound,
    Floating,
}

impl<'a> StatePolicy {
    const IF_BOUND: &'a str = "if-bound";
    const FLOATING: &'a str = "floating";
}

impl Display for StatePolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::IfBound => write!(f, "{}", Self::IF_BOUND),
            Self::Floating => write!(f, "{}", Self::FLOATING),
        }
    }
}

impl Default for StatePolicy {
    fn default() -> Self {
        Self::Floating
    }
}

pub enum Action {
    Block,
    Pass,
}

impl Default for Action {
    fn default() -> Self {
        Self::Block
    }
}

pub enum Antispoofing {
    NoRoute,
    UrpfFailed,
}

impl<'a> Antispoofing {
    const NO_ROUTE: &'a str = "no-route";
    const URPF_FAILED: &'a str = "urpf-failed";
}

impl Display for Antispoofing {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => write!(f, "{}", Self::NO_ROUTE),
            Self::UrpfFailed => write!(f, "{}", Self::URPF_FAILED),
        }
    }
}

impl Default for Antispoofing {
    fn default() -> Self {
        Self::UrpfFailed
    }
}

pub enum Multicast {
    NotRoutable,
    All,
}

impl Default for Multicast {
    fn default() -> Self {
        Self::NotRoutable
    }
}

pub struct Lan {
    pub is_block_out_dns: bool,
    pub multicast: Multicast,
}

impl Default for Lan {
    fn default() -> Self {
        Self {
            is_block_out_dns: true,
            multicast: Default::default(),
        }
    }
}

pub enum ICMP {
    Echoreq,
    All,
}

impl Default for ICMP {
    fn default() -> Self {
        Self::Echoreq
    }
}

pub struct Rules {
    block_table_name: String,
    in_table_name: String,
    out_table_name: String,
    pub block_policy: BlockPolicy,
    pub state_policy: StatePolicy,
    pub min_ttl: u8,
    pub is_enable_log: bool,
    pub incoming: Action,
    pub outgoing: Action,
    pub antispoofing: Option<Antispoofing>,
    pub is_block_ipv6: bool,
    pub lan: Option<Lan>,
    pub icmp: Option<ICMP>,
    pub skip_interfaces: HashSet<String>,
    pub pass_interfaces: HashSet<Direction>,
    pub pass_owners: HashSet<Owner>,
    pub block_destinations: HashSet<String>,
    pub pass_destinations: HashSet<Direction>,
}

impl<'a> Rules {
    pub const DEFAULT_BLOCK_TABLE_NAME: &'a str = "netlock_block";
    pub const DEFAULT_IN_TABLE_NAME: &'a str = "netlock_pass_in";
    pub const DEFAULT_OUT_TABLE_NAME: &'a str = "netlock_pass_out";

    pub fn new<S: Into<String>>(block_table_name: S, in_table_name: S, out_table_name: S) -> Self {
        Self {
            block_table_name: block_table_name.into(),
            in_table_name: in_table_name.into(),
            out_table_name: out_table_name.into(),
            ..Default::default()
        }
    }

    // based on `true story` (Eddie by AirVPN)
    #[allow(unused_must_use)]
    pub fn build(&self) -> String {
        let mut rules = Vec::new();
        self.write(&mut rules);
        String::from_utf8(rules).expect("Rules.write() invalid utf-8")
    }

    pub fn write(&self, mut to: impl IoWrite) -> IoResult<()> {
        self.write_header(&mut to)?;
        self.write_options(&mut to)?;
        self.write_scrub(&mut to)?;
        self.write_incoming(&mut to)?;
        self.write_outgoing(&mut to)?;
        self.write_antispoofing(&mut to)?;
        self.write_blocklist(&mut to)?;
        self.write_interfaces(&mut to)?;
        self.write_owners(&mut to)?;
        self.write_ipv6(&mut to)?;
        self.write_lan(&mut to)?;
        self.write_icmp(&mut to)?;
        self.write_destinations(&mut to)?;
        Ok(())
    }

    pub fn write_header(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# HEADER")?;
        writeln!(&mut to, "# {}", &time())?;
        writeln!(&mut to)
    }

    pub fn write_options(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# OPTIONS")?;
        writeln!(&mut to, "set block-policy {}", &self.block_policy)?;
        writeln!(&mut to, "set state-policy {}", &self.state_policy)?;
        if !self.skip_interfaces.is_empty() {
            let interfaces = self.write_macros(&mut to, "skip", &self.skip_interfaces)?;
            writeln!(&mut to, "set skip on {{ {} }}", &interfaces.join(", "))?;
        }
        writeln!(&mut to)
    }

    pub fn write_scrub(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# SCRUB")?;
        writeln!(&mut to, "scrub in all")?;
        if self.min_ttl > 0 {
            writeln!(&mut to, "scrub out all min-ttl {}", self.min_ttl)?;
        }
        writeln!(&mut to)
    }

    pub fn write_incoming(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# INCOMING")?;
        match self.incoming {
            Action::Block => {
                writeln!(
                    &mut to,
                    "block {} in {} all",
                    &self.block_policy,
                    self.get_log()
                )?;
            }
            Action::Pass => {
                writeln!(&mut to, "pass in all")?;
            }
        }
        writeln!(&mut to)
    }

    pub fn write_outgoing(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# OUTGOING")?;
        match self.outgoing {
            Action::Block => {
                writeln!(&mut to, "block return out {} all", self.get_log())?;
            }
            Action::Pass => {
                writeln!(&mut to, "pass out all")?;
            }
        }
        writeln!(&mut to)
    }

    pub fn write_antispoofing(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# ANTISPOOFING")?;
        if let Some(antispoofing) = &self.antispoofing {
            writeln!(
                &mut to,
                "block drop in {} quick from {} to any label \"ANTISPOOFING\"",
                self.get_log(),
                antispoofing,
            )?;
        }
        writeln!(&mut to)
    }

    pub fn write_blocklist(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# BLOCKLIST")?;
        self.write_table(&mut to, &self.block_table_name, &self.block_destinations)?;
        writeln!(
            &mut to,
            "block drop in quick from <{}> to any label \"BLOCKLIST_IN\"",
            &self.block_table_name,
        )?;
        writeln!(
            &mut to,
            "block return out quick from any to <{}> label \"BLOCKLIST_OUT\"",
            &self.block_table_name,
        )?;
        writeln!(&mut to)
    }

    pub fn write_interfaces(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# INTERFACES")?;
        let mut in_interfaces = vec![];
        let mut out_interfaces = vec![];
        for direct_interface in &self.pass_interfaces {
            let interface = direct_interface.safe_unwrap();
            if direct_interface.is_in() {
                in_interfaces.push(interface);
            } else if direct_interface.is_out() {
                out_interfaces.push(interface);
            } else {
                in_interfaces.push(interface);
                out_interfaces.push(interface);
            }
        }
        let in_interfaces = self.write_macros(&mut to, "pass_in", &in_interfaces)?;
        let out_interfaces = self.write_macros(&mut to, "pass_out", &out_interfaces)?;
        if !in_interfaces.is_empty() {
            writeln!(
                &mut to,
                "pass in quick on {{ {} }} all",
                &in_interfaces.join(", "),
            )?;
        }
        if !out_interfaces.is_empty() {
            writeln!(
                &mut to,
                "pass out quick on {{ {} }} all",
                &out_interfaces.join(", "),
            )?;
        }
        writeln!(&mut to)
    }

    pub fn write_owners(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# OWNERS")?;
        let mut users = vec![];
        let mut groups = vec![];
        for owner in &self.pass_owners {
            if owner.is_group() {
                &mut groups
            } else {
                &mut users
            }
            .push(owner.safe_unwrap());
        }
        if !users.is_empty() {
            writeln!(&mut to, "pass quick all user {{ {} }}", &users.join(", "))?;
        }
        if !groups.is_empty() {
            writeln!(&mut to, "pass quick all group {{ {} }}", &groups.join(", "))?;
        }
        writeln!(&mut to)
    }

    pub fn write_ipv6(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# IPV6")?;
        if self.is_block_ipv6 {
            writeln!(&mut to, "block {} in quick inet6 all", &self.block_policy)?;
            writeln!(&mut to, "block return out quick inet6 all")?;
        }
        writeln!(&mut to)
    }

    pub fn write_lan(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# LAN")?;
        if let Some(lan) = &self.lan {
            let ipv4nrm = gvars::IPV4_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv6nrm = gvars::IPV6_NOT_ROUTABLE_MULTICASTS.join(", ");
            let (ipv4m, ipv6m): (&str, &str) = match lan.multicast {
                Multicast::NotRoutable => (&ipv4nrm, &ipv6nrm),
                Multicast::All => (gvars::IPV4_MULTICAST, gvars::IPV6_MULTICAST),
            };
            if lan.is_block_out_dns {
                let mut block_out_dns = |addrs: &[&str]| -> IoResult<()> {
                    for &addr in addrs {
                        writeln!(
                            &mut to,
                            "block return out quick {} proto {{ tcp, udp }} from {} to {} port domain",
                            if addr.contains(':') { "inet6" } else { "inet" }, addr, addr,
                        )?;
                    }
                    Ok(())
                };
                block_out_dns(&gvars::IPV4_PRIVATE_NETWORKS)?;
                if !self.is_block_ipv6 {
                    block_out_dns(&gvars::IPV6_PRIVATE_NETWORKS)?;
                }
            }
            for addr in &gvars::IPV4_PRIVATE_NETWORKS {
                writeln!(
                    &mut to,
                    "pass quick inet from {} to {{ {}, {}, {} }}",
                    addr,
                    addr,
                    &Ipv4Addr::BROADCAST,
                    ipv4m,
                )?;
            }
            writeln!(
                &mut to,
                "pass quick inet from {} to {{ {}, {} }}",
                &Ipv4Addr::UNSPECIFIED,
                &Ipv4Addr::BROADCAST,
                &ipv4nrm,
            )?;
            if !self.is_block_ipv6 {
                for addr in &gvars::IPV6_PRIVATE_NETWORKS {
                    writeln!(
                        &mut to,
                        "pass quick inet6 from {} to {{ {}, {} }}",
                        addr, addr, ipv6m,
                    )?;
                }
                writeln!(
                    &mut to,
                    "pass quick inet6 from {} to {{ {} }}",
                    &Ipv6Addr::UNSPECIFIED,
                    &ipv6nrm,
                )?;
            }
        }
        writeln!(&mut to)
    }

    pub fn write_icmp(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# ICMP")?;
        match self.icmp {
            Some(ICMP::Echoreq) => {
                let mut pass_icmp = |af: &str, proto: &str, type_prefix: &str, label: &str| {
                    writeln!(
                        &mut to,
                        "pass quick {} proto {} all {} echoreq label \"{}\"",
                        af, proto, type_prefix, label,
                    )
                };
                pass_icmp("inet", "icmp", "icmp-type", "ICMP")?;
                if !self.is_block_ipv6 {
                    pass_icmp("inet6", "icmp6", "icmp6-type", "ICMP6")?;
                }
            }
            Some(ICMP::All) => {
                let mut pass_icmp = |af: &str, proto: &str, label: &str| {
                    writeln!(
                        &mut to,
                        "pass quick {} proto {} all label \"{}\"",
                        af, proto, label,
                    )
                };
                pass_icmp("inet", "icmp", "ICMP")?;
                if !self.is_block_ipv6 {
                    pass_icmp("inet6", "icmp6", "ICMP6")?;
                }
            }
            _ => {}
        }
        writeln!(&mut to)
    }

    pub fn write_destinations(&self, mut to: impl IoWrite) -> IoResult<()> {
        writeln!(&mut to, "# DESTINATIONS")?;
        let mut in_destinations = vec![];
        let mut out_destinations = vec![];
        for direct_destination in &self.pass_destinations {
            let destination = direct_destination.safe_unwrap();
            if direct_destination.is_in() {
                in_destinations.push(destination);
            } else if direct_destination.is_out() {
                out_destinations.push(destination);
            } else {
                in_destinations.push(destination);
                out_destinations.push(destination);
            }
        }
        self.write_table(&mut to, &self.in_table_name, &in_destinations)?;
        self.write_table(&mut to, &self.out_table_name, &out_destinations)?;
        writeln!(
            &mut to,
            "pass in quick from <{}> to any",
            &self.in_table_name,
        )?;
        writeln!(
            &mut to,
            "pass out quick from any to <{}>",
            &self.out_table_name,
        )?;
        writeln!(&mut to)
    }

    fn write_macros(
        &self,
        mut to: impl IoWrite,
        prefix: &str,
        interfaces: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> IoResult<Vec<String>> {
        let mut macros = vec![];
        for (idx, interface) in interfaces.into_iter().enumerate() {
            let macro_var = &format!("{}{}_if", prefix, &idx);
            writeln!(&mut to, "{} = \"{}\"", macro_var, interface.as_ref())?;
            macros.push(format!("${}", macro_var));
        }
        Ok(macros)
    }

    fn write_table(
        &self,
        mut to: impl IoWrite,
        table_name: &str,
        destinations: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> IoResult<()> {
        let mut addresses = vec![];
        let mut files = vec![];
        for destination in destinations {
            let destination = destination.as_ref();
            if destination.starts_with('/') {
                files.push(format!("file \"{}\"", destination));
            } else {
                addresses.push(destination.to_string());
            }
        }
        writeln!(
            &mut to,
            "table <{}> {{ {} }} {}",
            table_name,
            addresses.join(", "),
            files.join(" "),
        )?;
        Ok(())
    }

    fn get_log(&self) -> &str {
        if self.is_enable_log {
            "log"
        } else {
            ""
        }
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            block_table_name: Self::DEFAULT_BLOCK_TABLE_NAME.into(),
            in_table_name: Self::DEFAULT_IN_TABLE_NAME.into(),
            out_table_name: Self::DEFAULT_OUT_TABLE_NAME.into(),
            block_policy: Default::default(),
            state_policy: Default::default(),
            min_ttl: 0,
            is_enable_log: false,
            incoming: Default::default(),
            outgoing: Default::default(),
            antispoofing: Some(Default::default()),
            is_block_ipv6: false,
            lan: Some(Default::default()),
            icmp: Some(Default::default()),
            skip_interfaces: Default::default(),
            pass_interfaces: Default::default(),
            pass_owners: Default::default(),
            block_destinations: Default::default(),
            pass_destinations: Default::default(),
        }
    }
}
