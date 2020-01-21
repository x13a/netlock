use std::ffi::OsStr;
use std::fmt::Write;
use std::fs::{create_dir_all, remove_file, write};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::gvars;
use crate::utils::{self, ExecResult, ExpandUser, IsExecutable};

pub struct Manager {
    conf_dir: PathBuf,
    state: bool,
    ctl: Ctl,
    pub opts: Options,
}

impl Manager {
    pub fn new(conf_dir: impl Into<PathBuf>, ctl: Ctl) -> Self {
        let conf_dir = conf_dir.into().expanduser();
        assert!(!conf_dir.starts_with("~"));
        Self {
            conf_dir,
            state: false,
            ctl,
            opts: Default::default(),
        }
    }

    pub fn enable(&mut self) -> ExecResult<()> {
        self.make_configuration()?;
        self.load()
    }

    pub fn disable(&mut self) -> ExecResult<()> {
        let state_path = &self.get_state_path();
        if state_path.is_file() {
            self.ctl.state = true;
        }
        if self.ctl.state {
            self.ctl.disable()?;
            remove_file(state_path)?;
        } else {
            self.ctl.load_configuration(&self.ctl.conf_path)?;
        }
        self.state = false;
        Ok(())
    }

    pub fn load(&mut self) -> ExecResult<()> {
        if !self.ctl.is_enabled()? {
            self.ctl.enable()?;
            self.make_state()?;
        }
        self.ctl.load_configuration(&self.get_conf_path())?;
        self.state = true;
        Ok(())
    }

    pub fn get_state(&self) -> bool {
        self.state
    }

    fn make_configuration(&self) -> io::Result<()> {
        create_dir_all(&self.conf_dir)?;
        let conf_path = &self.get_conf_path();
        write(conf_path, &self.opts.build())?;
        utils::clear_go_permissions(conf_path)
    }

    fn make_state(&self) -> io::Result<()> {
        let state_path = &self.get_state_path();
        write(state_path, "")?;
        utils::clear_go_permissions(state_path)
    }

    fn get_conf_path(&self) -> PathBuf {
        self.conf_dir.join(gvars::CONF_FILE_NAME)
    }

    fn get_state_path(&self) -> PathBuf {
        self.conf_dir.join(gvars::STATE_FILE_NAME)
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new(gvars::DEFAULT_CONF_DIR, Default::default())
    }
}

pub struct Ctl {
    ctl_path: PathBuf,
    conf_path: PathBuf,
    state: bool,
}

impl<'a> Ctl {
    pub const DEFAULT_CTL_PATH: &'a str = "/sbin/pfctl";
    pub const DEFAULT_CONF_PATH: &'a str = "/etc/pf.conf";

    pub fn new<P: Into<PathBuf>>(ctl_path: P, conf_path: P) -> Self {
        let ctl_path = ctl_path.into();
        assert!(ctl_path.is_executable());
        let conf_path = conf_path.into().expanduser();
        assert!(conf_path.is_file() && !conf_path.starts_with("~"));
        Self {
            ctl_path,
            conf_path,
            state: false,
        }
    }

    fn enable(&mut self) -> ExecResult<()> {
        self.exec(&["-e"])?;
        self.state = true;
        Ok(())
    }

    fn disable(&mut self) -> ExecResult<()> {
        self.exec(&["-d"])?;
        self.state = false;
        Ok(())
    }

    fn is_enabled(&self) -> ExecResult<bool> {
        Ok(String::from_utf8_lossy(&self.exec(&["-s", "info"])?.stdout)
            .to_lowercase()
            .contains("status: enabled"))
    }

    fn load_configuration<P: AsRef<Path>>(&self, path: P) -> ExecResult<()> {
        self.exec(&[OsStr::new("-f"), path.as_ref().as_os_str()])
            .and(Ok(()))
    }

    fn exec<S: AsRef<OsStr>>(&self, args: &[S]) -> ExecResult<Output> {
        utils::exec(&self.ctl_path, args)
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

impl Default for BlockPolicy {
    fn default() -> Self {
        Self::Drop
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

pub enum ICMP {
    Echoreq,
    All,
}

impl Default for ICMP {
    fn default() -> Self {
        Self::Echoreq
    }
}

pub struct Options {
    in_table_name: String,
    out_table_name: String,
    pub block_policy: BlockPolicy,
    pub incoming: Action,
    pub outgoing: Action,
    pub is_enable_antispoofing: bool,
    pub is_block_ipv6: bool,
    pub private_networks: Option<Multicast>,
    pub icmp: Option<ICMP>,
    pub skip_interfaces: Vec<String>,
    pub pass_interfaces: Vec<String>,
    pub in_destinations: Vec<String>,
    pub out_destinations: Vec<String>,
}

impl<'a> Options {
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

    // based on Eddie
    #[allow(unused_must_use)]
    pub fn build(&self) -> String {
        let mut s = String::new();
        writeln!(&mut s, "#{}", &utils::time());
        let split_destinations = |arr: &[String]| {
            let mut destinations = vec![];
            let mut files = vec![];
            for destination in arr {
                if destination.starts_with('/') {
                    files.push(format!("file \"{}\"", destination));
                } else {
                    destinations.push(destination.to_string());
                }
            }
            (destinations.join(", "), files.join(" "))
        };
        let (in_destinations, in_files) = split_destinations(&self.in_destinations);
        writeln!(
            &mut s,
            "table <{}> {{ {} }} {}",
            &self.in_table_name, in_destinations, in_files,
        );
        let (out_destinations, out_files) = split_destinations(&self.out_destinations);
        writeln!(
            &mut s,
            "table <{}> {{ {} }} {}",
            &self.out_table_name, out_destinations, out_files,
        );
        writeln!(&mut s, "set ruleset-optimization basic");
        match &self.block_policy {
            BlockPolicy::Drop => {
                writeln!(&mut s, "set block-policy drop");
            }
            BlockPolicy::Return => {
                writeln!(&mut s, "set block-policy return");
            }
        }
        let mut skip_ifaces = vec!["lo".to_string()];
        skip_ifaces.extend_from_slice(&self.skip_interfaces);
        writeln!(&mut s, "set skip on {{ {} }}", &skip_ifaces.join(", "));
        writeln!(&mut s, "scrub in all");
        match &self.incoming {
            Action::Block => {
                writeln!(&mut s, "block in all");
            }
            Action::Pass => {
                writeln!(&mut s, "pass in all");
            }
        }
        match &self.outgoing {
            Action::Block => {
                writeln!(&mut s, "block out all");
            }
            Action::Pass => {
                writeln!(&mut s, "pass out all");
            }
        }
        if self.is_enable_antispoofing {
            writeln!(
                &mut s,
                "block in quick from {{ {} }} to any",
                &Self::ANTISPOOFING_SOURCES.join(", "),
            );
        }
        if self.is_block_ipv6 {
            writeln!(&mut s, "block quick inet6 all");
        }
        if let Some(multicast) = &self.private_networks {
            let ipv4nrm = gvars::IPV4_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv6nrm = gvars::IPV6_NOT_ROUTABLE_MULTICASTS.join(", ");
            let ipv4m: &str;
            let ipv6m: &str;
            match multicast {
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
                writeln!(
                    &mut s,
                    "pass quick inet from {} to {{ {}, {}, {} }}",
                    addr,
                    addr,
                    gvars::BROADCAST,
                    ipv4m,
                );
            }
            writeln!(
                &mut s,
                "pass quick inet from {} to {{ {}, {} }}",
                gvars::IPV4_UNSPECIFIED,
                gvars::BROADCAST,
                &ipv4nrm,
            );
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
                gvars::IPV6_UNSPECIFIED,
                &ipv6nrm,
            );
        }
        if !self.pass_interfaces.is_empty() {
            writeln!(
                &mut s,
                "pass quick on {{ {} }} all",
                &self.pass_interfaces.join(", "),
            );
        }
        match &self.icmp {
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

impl Default for Options {
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
