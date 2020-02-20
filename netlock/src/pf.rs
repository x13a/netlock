use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter, Write};
use std::fs::{create_dir_all, read_to_string, write};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::gvars;
use crate::utils::{
    clear_go_permissions, exec, exec_stdin, is_osx, time, ExecResult, ExpandUser, IsExecutable,
};

pub struct Loader {
    conf_dir: PathBuf,
    manager: Manager,
}

impl<'a> Loader {
    const SETTINGS_SEP: char = ':';
    const SETTINGS_MANAGER_STATE: &'a str = "MANAGER_STATE";
    const SETTINGS_MANAGER_ANCHOR: &'a str = "MANAGER_ANCHOR";
    const SETTINGS_CTL_STATE: &'a str = "CTL_STATE";
    const SETTINGS_CTL_TOKEN: &'a str = "CTL_TOKEN";

    pub fn new(conf_dir: impl Into<PathBuf>, manager: Manager) -> Self {
        let conf_dir = conf_dir.into().expanduser();
        assert!(!conf_dir.starts_with("~"));
        Self { conf_dir, manager }
    }

    pub fn enable(&mut self, anchor: Option<String>) -> ExecResult<()> {
        let _ = self.load_settings_conf();
        self.manager.enable(None, anchor.as_deref())?;
        self.make_firewall_conf()?;
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
        self.load_settings_conf()?;
        self.manager.get_status()
    }

    pub fn manager(&mut self) -> &mut Manager {
        &mut self.manager
    }

    fn make_firewall_conf(&self) -> io::Result<()> {
        create_dir_all(&self.conf_dir)?;
        let conf_path = &self.get_firewall_conf_path();
        write(conf_path, &self.manager.rules.build())?;
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
                (
                    Self::SETTINGS_CTL_STATE,
                    &self.manager.ctl.state.to_string(),
                ),
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
        for opts in read_to_string(&self.get_settings_conf_path())?
            .lines()
            .map(|s| s.split(Self::SETTINGS_SEP).collect::<Vec<_>>())
            .filter(|v| v.len() >= 2)
        {
            match opts[0] {
                Self::SETTINGS_MANAGER_STATE => {
                    self.manager.state = opts[1].parse().unwrap_or(self.manager.state)
                }
                Self::SETTINGS_MANAGER_ANCHOR => self.manager.anchor = opts[1].into(),
                Self::SETTINGS_CTL_STATE => {
                    self.manager.ctl.state = opts[1].parse().unwrap_or(self.manager.ctl.state);
                }
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

    pub fn enable(&mut self, rules: Option<&Rules>, new_anchor: Option<&str>) -> ExecResult<()> {
        self.load(
            LoadFile::Stdin(&rules.unwrap_or(&self.rules).build()),
            new_anchor,
        )
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
        for interface in self
            .ctl
            .show(ShowModifier::Interfaces(&loopback_group), "", false)?
            .split_whitespace()
            .map(ToString::to_string)
        {
            if !self.rules.pass_interfaces.contains(&interface) {
                self.rules.pass_interfaces.push(interface);
            }
        }
        if !self.rules.skip_interfaces.contains(&loopback_group) {
            self.rules.skip_interfaces.push(loopback_group);
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

    fn enable_firewall(&mut self) -> ExecResult<()> {
        if is_osx() {
            if !self.ctl.check_token()? {
                self.ctl.acquire()?;
            }
        } else if !self.ctl.is_enabled()? {
            self.ctl.enable()?;
        }
        Ok(())
    }

    fn disable_firewall(&mut self) -> ExecResult<()> {
        if self.ctl.is_enabled()? {
            if is_osx() {
                if self.ctl.check_token()? {
                    self.ctl.release()?;
                }
            } else if self.ctl.state {
                self.ctl.disable()?;
            }
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
    Info,
    References,
    Tables,
    Interfaces(&'a str),
}

impl<'a> ShowModifier<'_> {
    const RULES: &'a str = "rules";
    const ANCHORS: &'a str = "Anchors";
    const INFO: &'a str = "info";
    const REFERENCES: &'a str = "References";
    const TABLES: &'a str = "Tables";
    const INTERFACES: &'a str = "Interfaces";
}

impl Display for ShowModifier<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rules => write!(f, "{}", Self::RULES),
            Self::Anchors => write!(f, "{}", Self::ANCHORS),
            Self::Info => write!(f, "{}", Self::INFO),
            Self::References => write!(f, "{}", Self::REFERENCES),
            Self::Tables => write!(f, "{}", Self::TABLES),
            Self::Interfaces(_) => write!(f, "{}", Self::INTERFACES),
        }
    }
}

enum FlushModifier {
    All,
}

impl<'a> FlushModifier {
    const ALL: &'a str = "all";
}

impl Display for FlushModifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "{}", Self::ALL),
        }
    }
}

enum LoadFile<'a> {
    Path(&'a Path),
    Stdin(&'a str),
}

pub struct Ctl {
    ctl_path: PathBuf,
    conf_path: PathBuf,
    state: bool,
    token: String,
}

impl<'a> Ctl {
    pub const DEFAULT_CTL_PATH: &'a str = "/sbin/pfctl";
    pub const DEFAULT_CONF_PATH: &'a str = "/etc/pf.conf";

    const FLAG_ENABLE: &'a str = "-e";
    const FLAG_DISABLE: &'a str = "-d";
    const FLAG_ACQUIRE: &'a str = "-E";
    const FLAG_RELEASE: &'a str = "-X";
    const FLAG_SHOW: &'a str = "-s";
    const FLAG_ANCHOR: &'a str = "-a";
    const FLAG_FLUSH: &'a str = "-F";
    const FLAG_FILE: &'a str = "-f";
    const FLAG_VERBOSE: &'a str = "-v";
    const FLAG_INTERFACE: &'a str = "-i";

    pub fn new<P: Into<PathBuf>>(ctl_path: P, conf_path: P) -> Self {
        let ctl_path = ctl_path.into();
        assert!(ctl_path.is_executable());
        let conf_path = conf_path.into().expanduser();
        assert!(conf_path.is_file() && !conf_path.starts_with("~"));
        Self {
            ctl_path,
            conf_path,
            state: false,
            token: "".into(),
        }
    }

    fn enable(&mut self) -> ExecResult<()> {
        self.exec(&[Self::FLAG_ENABLE])?;
        self.state = true;
        Ok(())
    }

    fn disable(&mut self) -> ExecResult<()> {
        self.exec(&[Self::FLAG_DISABLE])?;
        self.state = false;
        Ok(())
    }

    fn acquire(&mut self) -> ExecResult<()> {
        let stderr =
            String::from_utf8_lossy(&self.exec(&[Self::FLAG_ACQUIRE])?.stderr).to_lowercase();
        let mut token = "";
        for arr in stderr
            .lines()
            .filter(|&s| s.contains("token :"))
            .map(|s| s.split(':').collect::<Vec<_>>())
        {
            token = arr[1].trim();
            break;
        }
        assert!(!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()));
        self.token = token.into();
        Ok(())
    }

    fn release(&mut self) -> ExecResult<bool> {
        assert!(!self.token.is_empty());
        let is_disabled =
            String::from_utf8_lossy(&self.exec(&[Self::FLAG_RELEASE, &self.token])?.stderr)
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

    fn check_token(&self) -> ExecResult<bool> {
        if self.token.is_empty() {
            return Ok(false);
        }
        Ok(self
            .show(ShowModifier::References, "", false)?
            .to_lowercase()
            .contains(&self.token))
    }

    fn flush(&self, modifier: FlushModifier, anchor: &str) -> ExecResult<()> {
        let modifier = modifier.to_string();
        let mut args = vec![Self::FLAG_FLUSH, &modifier];
        if !anchor.is_empty() {
            args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
        }
        self.exec(&args).and(Ok(()))
    }

    fn load(&self, file: LoadFile, anchor: &str) -> ExecResult<()> {
        match file {
            LoadFile::Path(p) => {
                let mut args = vec![OsStr::new(Self::FLAG_FILE), p.as_os_str()];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[OsStr::new(Self::FLAG_ANCHOR), OsStr::new(anchor)]);
                }
                self.exec(&args)
            }
            LoadFile::Stdin(s) => {
                let mut args = vec![Self::FLAG_FILE, "-"];
                if !anchor.is_empty() {
                    args.extend_from_slice(&[Self::FLAG_ANCHOR, anchor]);
                }
                exec_stdin(&self.ctl_path, &args, s)
            }
        }
        .and(Ok(()))
    }

    fn show(&self, modifier: ShowModifier, anchor: &str, verbose: bool) -> ExecResult<String> {
        let modifier_string = modifier.to_string();
        let mut args = vec![Self::FLAG_SHOW, &modifier_string];
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
        Self::Return
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

pub enum Multicast {
    NotRoutable,
    All,
}

impl Default for Multicast {
    fn default() -> Self {
        Self::NotRoutable
    }
}

pub struct PrivateNetworks {
    pub is_block_out_dns: bool,
    pub multicast: Multicast,
}

impl Default for PrivateNetworks {
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
    in_table_name: String,
    out_table_name: String,
    pub block_policy: BlockPolicy,
    pub incoming: Action,
    pub outgoing: Action,
    pub is_enable_antispoofing: bool,
    pub is_block_ipv6: bool,
    pub private_networks: Option<PrivateNetworks>,
    pub icmp: Option<ICMP>,
    pub skip_interfaces: Vec<String>,
    pub pass_interfaces: Vec<String>,
    pub in_destinations: Vec<String>,
    pub out_destinations: Vec<String>,
}

impl<'a> Rules {
    pub const DEFAULT_IN_TABLE_NAME: &'a str = "netlock_pass_in";
    pub const DEFAULT_OUT_TABLE_NAME: &'a str = "netlock_pass_out";

    const ANTISPOOFING_SOURCES: [&'a str; 2] = ["no-route", "urpf-failed"];

    pub fn new(in_table_name: &str, out_table_name: &str) -> Self {
        Self {
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
        let pass_interfaces = build_macros("pass", &self.pass_interfaces);
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
        build_tables(&self.in_table_name, &self.in_destinations);
        build_tables(&self.out_table_name, &self.out_destinations);
        writeln!(&mut s, "set block-policy {}", &self.block_policy);
        writeln!(&mut s, "set skip on {{ {} }}", &skip_interfaces.join(", "));
        writeln!(&mut s, "scrub in all");
        match self.incoming {
            Action::Block => {
                writeln!(&mut s, "block {} in all", &self.block_policy);
            }
            Action::Pass => {
                writeln!(&mut s, "pass in all");
            }
        }
        match self.outgoing {
            Action::Block => {
                writeln!(&mut s, "block {} out all", &self.block_policy);
            }
            Action::Pass => {
                writeln!(&mut s, "pass out all");
            }
        }
        if self.is_enable_antispoofing {
            writeln!(
                &mut s,
                "block drop in quick from {{ {} }} to any",
                &Self::ANTISPOOFING_SOURCES.join(", "),
            );
        }
        if self.is_block_ipv6 {
            writeln!(&mut s, "block {} quick inet6 all", &self.block_policy);
        }
        if !pass_interfaces.is_empty() {
            writeln!(
                &mut s,
                "pass quick on {{ {} }} all",
                &pass_interfaces.join(", "),
            );
        }
        if let Some(private_networks) = &self.private_networks {
            let ipv4nrm = gvars::IPV4_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv6nrm = gvars::IPV6_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv4m: &str;
            let ipv6m: &str;
            match private_networks.multicast {
                Multicast::NotRoutable => {
                    ipv4m = &ipv4nrm;
                    ipv6m = &ipv6nrm;
                }
                Multicast::All => {
                    ipv4m = gvars::IPV4_MULTICAST;
                    ipv6m = gvars::IPV6_MULTICAST;
                }
            }
            for addr in &gvars::IPV4_PRIVATE_NETWORKS {
                if private_networks.is_block_out_dns {
                    writeln!(
                        &mut s,
                        "block {} out quick inet proto {{ tcp, udp }} from {} to {} port domain",
                        &self.block_policy, addr, addr,
                    );
                }
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
            for addr in &gvars::IPV6_PRIVATE_NETWORKS {
                if private_networks.is_block_out_dns {
                    writeln!(
                        &mut s,
                        "block {} out quick inet6 proto {{ tcp, udp }} from {} to {} port domain",
                        &self.block_policy, addr, addr,
                    );
                }
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
        match self.icmp {
            Some(ICMP::Echoreq) => {
                writeln!(&mut s, "pass quick inet proto icmp all icmp-type echoreq");
                writeln!(
                    &mut s,
                    "pass quick inet6 proto icmp6 all icmp6-type echoreq",
                );
            }
            Some(ICMP::All) => {
                writeln!(&mut s, "pass quick proto {{ icmp, icmp6 }} all");
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
            in_table_name: Self::DEFAULT_IN_TABLE_NAME.into(),
            out_table_name: Self::DEFAULT_OUT_TABLE_NAME.into(),
            block_policy: Default::default(),
            incoming: Default::default(),
            outgoing: Default::default(),
            is_enable_antispoofing: false,
            is_block_ipv6: false,
            private_networks: Some(Default::default()),
            icmp: Some(Default::default()),
            skip_interfaces: vec![],
            pass_interfaces: vec![],
            in_destinations: vec![],
            out_destinations: vec![],
        }
    }
}
