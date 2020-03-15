use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter, Write};
use std::fs::{create_dir_all, write};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::gvars;
use crate::tools::{get_destinations_from_configuration_files, get_useful_routing_table_info};
use crate::utils::{
    clear_go_permissions, exec, exec_stdin, read_lines, time, ExecResult, ExpandUser, IsExecutable,
};

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

    pub fn enable(&mut self, anchor: Option<String>) -> ExecResult<()> {
        let _ = self.load_settings_conf();
        let rules = &self.manager.rules.build();
        self.manager
            .load(LoadFile::Stdin(rules), anchor.as_deref())?;
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

    pub fn load(&mut self, anchor: Option<String>) -> ExecResult<()> {
        self.load_settings_conf()?;
        self.manager.load(
            LoadFile::Path(&self.get_firewall_conf_path()),
            anchor.as_deref(),
        )?;
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
            Some(s) => write(conf_path, s)?,
            _ => write(conf_path, &self.manager.rules.build())?,
        }
        clear_go_permissions(conf_path)
    }

    fn make_settings_conf(&self) -> io::Result<()> {
        create_dir_all(&self.conf_dir)?;
        let conf_path = &self.get_settings_conf_path();
        write(
            conf_path,
            [
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
            ]
            .iter()
            .map(|&v| format!("{}{}{}", v.0, Self::SETTINGS_SEP, v.1))
            .collect::<Vec<_>>()
            .join("\n"),
        )?;
        clear_go_permissions(conf_path)
    }

    fn load_settings_conf(&mut self) -> io::Result<()> {
        for line in read_lines(&self.get_settings_conf_path())? {
            let line = line?;
            let opts = line.split(Self::SETTINGS_SEP).collect::<Vec<_>>();
            if opts.len() < 2 {
                continue;
            }
            match opts[0] {
                Self::SETTINGS_MANAGER_STATE => {
                    self.manager.state = opts[1].parse().unwrap_or(self.manager.state)
                }
                Self::SETTINGS_MANAGER_ANCHOR => self.manager.anchor = opts[1].into(),
                #[cfg(not(target_os = "macos"))]
                Self::SETTINGS_CTL_STATE => {
                    self.manager.ctl.state = opts[1].parse().unwrap_or(self.manager.ctl.state);
                }
                #[cfg(target_os = "macos")]
                Self::SETTINGS_CTL_TOKEN => self.manager.ctl.token = opts[1].into(),
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
    rules: Vec<String>,
}

impl Status {
    pub fn firewall_state(&self) -> bool {
        self.firewall_state
    }

    pub fn netlock_state(&self) -> bool {
        self.netlock_state
    }

    pub fn rules(&self) -> &[String] {
        &self.rules
    }
}

pub struct Manager {
    state: bool,
    anchor: String,
    ctl: Ctl,
    rules: Rules,
}

impl<'a> Manager {
    pub const ANCHOR_REPLACE_FROM: char = '$';
    pub const ANCHOR_REPLACE_TO: &'a str = "zz.netlock";

    pub fn new(ctl: Ctl, rules: Rules) -> Self {
        Self {
            state: false,
            anchor: "".into(),
            ctl,
            rules,
        }
    }

    pub fn enable(&mut self, new_anchor: Option<&str>) -> ExecResult<()> {
        self.load(LoadFile::Stdin(&self.rules.build()), new_anchor)
    }

    pub fn disable(&mut self) -> ExecResult<()> {
        self.disable_firewall()?;
        self.reset(&self.anchor)?;
        self.state = false;
        Ok(())
    }

    pub fn get_status(&self) -> ExecResult<Status> {
        let mut rules = vec![self.ctl.show(ShowModifier::Rules, "", false)?];
        if !self.anchor.is_empty() {
            for anchor in self
                .ctl
                .show(ShowModifier::Anchors, "", true)?
                .split_whitespace()
            {
                let ruleset = self.ctl.show(ShowModifier::Rules, anchor, false)?;
                if !ruleset.is_empty() {
                    rules.push(ruleset);
                }
            }
        }
        Ok(Status {
            firewall_state: self.ctl.is_enabled()?,
            netlock_state: self.state,
            rules,
        })
    }

    pub fn state(&self) -> bool {
        self.state
    }

    pub fn anchor(&self) -> &str {
        &self.anchor
    }

    pub fn set_anchor(&mut self, s: &str) -> bool {
        if self.state {
            return false;
        }
        self.anchor = self.format_anchor(s);
        true
    }

    pub fn rules(&mut self) -> &mut Rules {
        &mut self.rules
    }

    pub fn set_skipass_loopback(&mut self) -> ExecResult<()> {
        let loopback_group = "lo".to_string();
        if self.anchor.is_empty() {
            if !self.rules.skip_interfaces.contains(&loopback_group) {
                self.rules.skip_interfaces.push(loopback_group);
            }
        } else {
            for interface in self
                .ctl
                .show(ShowModifier::Interfaces(&loopback_group), "", true)?
                .lines()
                .map(|s| s.split_whitespace().collect::<Vec<_>>())
                .filter(|v| v.len() == 1) // v[1] == "(skip)"
                .map(|v| PassInterface::new(v[0]))
            {
                if !self.rules.pass_interfaces.contains(&interface) {
                    self.rules.pass_interfaces.push(interface);
                }
            }
        }
        Ok(())
    }

    pub fn extend_rules_from_routing_table(&mut self) -> ExecResult<()> {
        let info = get_useful_routing_table_info()?;
        let interface = info.interface();
        if !interface.is_empty() {
            let pass_interface = PassInterface::new(interface).to_out();
            if !self.rules.pass_interfaces.contains(&pass_interface) {
                self.rules.pass_interfaces.push(pass_interface);
            }
        }
        let destination = info.destination().to_string();
        if !destination.is_empty() && !self.rules.out_destinations.contains(&destination) {
            self.rules.out_destinations.push(destination);
        }
        Ok(())
    }

    pub fn extend_rules_from_configuration_files(
        &mut self,
        paths: &[impl AsRef<Path>],
    ) -> io::Result<()> {
        for destination in get_destinations_from_configuration_files(paths)? {
            if !self.rules.out_destinations.contains(&destination) {
                self.rules.out_destinations.push(destination);
            }
        }
        Ok(())
    }

    fn load(&mut self, file: LoadFile, new_anchor: Option<&str>) -> ExecResult<()> {
        self.enable_firewall()?;
        match new_anchor {
            Some(s) => {
                let anchor = self.anchor.clone();
                let new_anchor = self.format_anchor(s);
                self.ctl.load(file, &new_anchor)?;
                if self.state && anchor != new_anchor {
                    self.reset(&anchor)?;
                }
                self.anchor = new_anchor;
            }
            _ => self.ctl.load(file, &self.anchor)?,
        }
        self.state = true;
        self.ctl.flush(FlushModifier::States, "")?;
        Ok(())
    }

    fn format_anchor(&self, s: &str) -> String {
        s.replace(Self::ANCHOR_REPLACE_FROM, Self::ANCHOR_REPLACE_TO)
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
        for arr in String::from_utf8_lossy(&self.exec(&[Self::FLAG_ENABLE])?.stderr)
            .to_lowercase()
            .lines()
            .filter(|&s| s.contains("token :"))
            .map(|s| s.split(':').collect::<Vec<_>>())
        {
            token = arr[1].trim().into();
            break;
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
            LoadFile::Path(p) => {
                let mut args = vec![OsStr::new(Self::FLAG_FILE), p.as_os_str()];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[OsStr::new(Self::FLAG_ANCHOR), OsStr::new(anchor)]);
                }
                self.exec(&args)?;
            }
            LoadFile::Stdin(s) => {
                let mut args = vec![Self::FLAG_FILE, "-"];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
                }
                exec_stdin(&self.ctl_path, &args, s)?;
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
        if let ShowModifier::Interfaces(s) = modifier {
            if !s.is_empty() {
                args.extend_from_slice(&[Self::FLAG_INTERFACE, s]);
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

#[derive(PartialEq, Clone)]
pub struct PassInterface {
    interface: String,
}

impl PassInterface {
    const IN: char = '<';
    const OUT: char = '>';

    pub fn new(s: &str) -> Self {
        Self {
            interface: s.into(),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn get_name(&self) -> String {
        self.interface
            .trim_start_matches(|c| c == Self::IN || c == Self::OUT)
            .into()
    }

    pub fn is_in(&self) -> bool {
        self.interface.starts_with(Self::IN)
    }

    pub fn is_out(&self) -> bool {
        self.interface.starts_with(Self::OUT)
    }

    pub fn has_no_direction(&self) -> bool {
        !self.is_in() && !self.is_out()
    }

    pub fn to_in_string(&self) -> String {
        format!("{}{}", Self::IN, &self.get_name())
    }

    pub fn to_out_string(&self) -> String {
        format!("{}{}", Self::OUT, &self.get_name())
    }

    pub fn to_in(&self) -> Self {
        Self {
            interface: self.to_in_string(),
        }
    }

    pub fn to_out(&self) -> Self {
        Self {
            interface: self.to_out_string(),
        }
    }
}

impl<S: AsRef<str>> From<S> for PassInterface {
    fn from(s: S) -> Self {
        Self::new(s.as_ref())
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
    pub skip_interfaces: Vec<String>,
    pub pass_interfaces: Vec<PassInterface>,
    pub block_destinations: Vec<String>,
    pub in_destinations: Vec<String>,
    pub out_destinations: Vec<String>,
}

impl<'a> Rules {
    pub const DEFAULT_BLOCK_TABLE_NAME: &'a str = "netlock_block";
    pub const DEFAULT_IN_TABLE_NAME: &'a str = "netlock_pass_in";
    pub const DEFAULT_OUT_TABLE_NAME: &'a str = "netlock_pass_out";

    pub fn new(block_table_name: &str, in_table_name: &str, out_table_name: &str) -> Self {
        Self {
            block_table_name: block_table_name.into(),
            in_table_name: in_table_name.into(),
            out_table_name: out_table_name.into(),
            ..Default::default()
        }
    }

    // based on `true story` (Eddie AirVPN)
    #[allow(unused_must_use)]
    pub fn build(&self) -> String {
        let mut s = String::new();
        writeln!(&mut s, "#{}", &time());
        let mut pass_in_interfaces = vec![];
        let mut pass_out_interfaces = vec![];
        let mut pass_interfaces = vec![];
        for pass_interface in &self.pass_interfaces {
            if pass_interface.is_in() {
                &mut pass_in_interfaces
            } else if pass_interface.is_out() {
                &mut pass_out_interfaces
            } else {
                &mut pass_interfaces
            }
            .push(pass_interface.get_name());
        }
        let mut build_macros = |prefix: &str, interfaces: &[String]| {
            let mut results = vec![];
            for (idx, interface) in interfaces.iter().enumerate() {
                let macro_var = &format!("{}{}_if", prefix, &idx);
                writeln!(&mut s, "{} = \"{}\"", macro_var, interface);
                results.push(format!("${}", macro_var));
            }
            results
        };
        let skip_interfaces = build_macros("skip", &self.skip_interfaces);
        let pass_in_interfaces = build_macros("pass_in", &pass_in_interfaces);
        let pass_out_interfaces = build_macros("pass_out", &pass_out_interfaces);
        let pass_interfaces = build_macros("pass", &pass_interfaces);
        let mut build_tables = |table_name: &str, destinations: &[String]| {
            let mut addresses = vec![];
            let mut files = vec![];
            for destination in destinations {
                if destination.starts_with('/') {
                    files.push(format!("file \"{}\"", destination));
                } else {
                    addresses.push(destination.to_string());
                }
            }
            writeln!(
                &mut s,
                "table <{}> {{ {} }} {}",
                table_name,
                addresses.join(", "),
                files.join(" "),
            );
        };
        build_tables(&self.block_table_name, &self.block_destinations);
        build_tables(&self.in_table_name, &self.in_destinations);
        build_tables(&self.out_table_name, &self.out_destinations);
        writeln!(&mut s, "set block-policy {}", &self.block_policy);
        writeln!(&mut s, "set state-policy {}", &self.state_policy);
        if !skip_interfaces.is_empty() {
            writeln!(&mut s, "set skip on {{ {} }}", &skip_interfaces.join(", "));
        }
        writeln!(&mut s, "scrub in all");
        if self.min_ttl > 0 {
            writeln!(&mut s, "scrub out all min-ttl {}", self.min_ttl);
        }
        let log = if self.is_enable_log { "log" } else { "" };
        match self.incoming {
            Action::Block => {
                writeln!(&mut s, "block {} in {} all", &self.block_policy, log);
            }
            Action::Pass => {
                writeln!(&mut s, "pass in all");
            }
        }
        match self.outgoing {
            Action::Block => {
                writeln!(&mut s, "block return out {} all", log);
            }
            Action::Pass => {
                writeln!(&mut s, "pass out all");
            }
        }
        if let Some(antispoofing) = &self.antispoofing {
            writeln!(
                &mut s,
                "block drop in {} quick from {} to any label \"ANTISPOOFING\"",
                log, antispoofing,
            );
        }
        writeln!(
            &mut s,
            "block drop in quick from <{}> to any label \"BLOCKLIST_IN\"",
            &self.block_table_name,
        );
        writeln!(
            &mut s,
            "block return out quick from any to <{}> label \"BLOCKLIST_OUT\"",
            &self.block_table_name,
        );
        if !pass_in_interfaces.is_empty() {
            writeln!(
                &mut s,
                "pass in quick on {{ {} }} all",
                &pass_in_interfaces.join(", "),
            );
        }
        if !pass_out_interfaces.is_empty() {
            writeln!(
                &mut s,
                "pass out quick on {{ {} }} all",
                &pass_out_interfaces.join(", "),
            );
        }
        if !pass_interfaces.is_empty() {
            writeln!(
                &mut s,
                "pass quick on {{ {} }} all",
                &pass_interfaces.join(", "),
            );
        }
        if self.is_block_ipv6 {
            writeln!(&mut s, "block {} in quick inet6 all", &self.block_policy);
            writeln!(&mut s, "block return out quick inet6 all");
        }
        if let Some(lan) = &self.lan {
            let ipv4nrm = gvars::IPV4_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv6nrm = gvars::IPV6_NOT_ROUTABLE_MULTICASTS.join(", ");
            let (ipv4m, ipv6m): (&str, &str) = match lan.multicast {
                Multicast::NotRoutable => (&ipv4nrm, &ipv6nrm),
                Multicast::All => (gvars::IPV4_MULTICAST, gvars::IPV6_MULTICAST),
            };
            if lan.is_block_out_dns {
                let mut block_out_dns = |addrs: &[&str]| {
                    for &addr in addrs {
                        writeln!(
                            &mut s,
                            "block return out quick {} proto {{ tcp, udp }} from {} to {} port domain",
                            if addr.contains(':') { "inet6" } else { "inet" }, addr, addr,
                        );
                    }
                };
                block_out_dns(&gvars::IPV4_PRIVATE_NETWORKS);
                if !self.is_block_ipv6 {
                    block_out_dns(&gvars::IPV6_PRIVATE_NETWORKS);
                }
            }
            for addr in &gvars::IPV4_PRIVATE_NETWORKS {
                writeln!(
                    &mut s,
                    "pass quick inet from {} to {{ {}, {}, {} }}",
                    addr,
                    addr,
                    &Ipv4Addr::BROADCAST,
                    ipv4m,
                );
            }
            writeln!(
                &mut s,
                "pass quick inet from {} to {{ {}, {} }}",
                &Ipv4Addr::UNSPECIFIED,
                &Ipv4Addr::BROADCAST,
                &ipv4nrm,
            );
            if !self.is_block_ipv6 {
                for addr in &gvars::IPV6_PRIVATE_NETWORKS {
                    writeln!(
                        &mut s,
                        "pass quick inet6 from {} to {{ {}, {} }}",
                        addr, addr, ipv6m,
                    );
                }
                writeln!(
                    &mut s,
                    "pass quick inet6 from {} to {{ {} }}",
                    &Ipv6Addr::UNSPECIFIED,
                    &ipv6nrm,
                );
            }
        }
        match self.icmp {
            Some(ICMP::Echoreq) => {
                let mut pass_icmp = |af: &str, proto: &str, type_prefix: &str, label: &str| {
                    writeln!(
                        &mut s,
                        "pass quick {} proto {} all {} echoreq label \"{}\"",
                        af, proto, type_prefix, label,
                    );
                };
                pass_icmp("inet", "icmp", "icmp-type", "ICMP");
                if !self.is_block_ipv6 {
                    pass_icmp("inet6", "icmp6", "icmp6-type", "ICMP6");
                }
            }
            Some(ICMP::All) => {
                let mut pass_icmp = |af: &str, proto: &str, label: &str| {
                    writeln!(
                        &mut s,
                        "pass quick {} proto {} all label \"{}\"",
                        af, proto, label,
                    );
                };
                pass_icmp("inet", "icmp", "ICMP");
                if !self.is_block_ipv6 {
                    pass_icmp("inet6", "icmp6", "ICMP6");
                }
            }
            _ => {}
        }
        writeln!(
            &mut s,
            "pass in quick from <{}> to any",
            &self.in_table_name,
        );
        writeln!(
            &mut s,
            "pass out quick from any to <{}>",
            &self.out_table_name,
        );
        s
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
            skip_interfaces: vec![],
            pass_interfaces: vec![],
            block_destinations: vec![],
            in_destinations: vec![],
            out_destinations: vec![],
        }
    }
}
