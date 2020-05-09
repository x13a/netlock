use std::fs::read_dir;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use crate::utils::{exec, read_lines, ExecResult, IsHidden};

pub struct RoutingInfo {
    interface: String,
    destination: String,
}

impl RoutingInfo {
    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }
}

#[cfg(unix)]
pub fn get_useful_routing_table_info() -> ExecResult<RoutingInfo> {
    // TODO IPv6
    struct Record<'a> {
        destination: &'a str,
        gateway: &'a str,
        flags: &'a str,
        netif: &'a str,
    }

    impl Record<'_> {
        fn is_master(&self) -> bool {
            self.destination == "0/1" || self.destination == "128.0/1"
        }

        fn is_default(&self) -> bool {
            self.destination == "default"
        }

        fn is_loopback(&self) -> bool {
            self.netif.starts_with("lo")
        }

        fn check_flags(&self) -> bool {
            ["U", "G", "S"].iter().all(|&s| self.flags.contains(s))
        }
    }

    let mut interface = String::new();
    let mut destination = String::new();
    let mut default_gateway = "";
    let mut default_netif = "";
    for record in
        String::from_utf8_lossy(&exec("/usr/sbin/netstat", &["-lnr", "-f", "inet"])?.stdout)
            .lines()
            .map(|s| s.split_whitespace().collect::<Vec<_>>())
            .filter(|v| v.len() >= 8)
            .skip(1) // header
            .map(|v| Record {
                destination: v[0],
                gateway: v[1],
                flags: v[3],
                netif: v[7],
            })
            .filter(|r| !r.is_loopback() && r.check_flags())
    {
        if record.is_master() && interface.is_empty() {
            interface = record.netif.into();
            if !destination.is_empty() {
                break;
            }
            continue;
        }
        if record.is_default() && default_gateway.is_empty() {
            default_gateway = record.gateway;
            default_netif = record.netif;
            continue;
        }
        if !default_gateway.is_empty()
            && destination.is_empty()
            && record.gateway == default_gateway
            && record.netif == default_netif
        {
            destination = record.destination.into();
            let _destination_vec = destination.split('/').collect::<Vec<_>>();
            assert!(Ipv4Addr::from_str(_destination_vec[0]).is_ok());
            if _destination_vec.len() != 1 {
                assert_eq!(_destination_vec.len(), 2);
                assert_eq!(_destination_vec[1], "32");
            }
            if !interface.is_empty() {
                break;
            }
        }
    }
    Ok(RoutingInfo {
        interface,
        destination,
    })
}

fn get_destinations_from_ovpn_file(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let mut destinations = vec![];
    for line in read_lines(path)? {
        let line = line?;
        if !line.starts_with("remote ") {
            continue;
        }
        if let Some(destination) = line.split_whitespace().nth(1) {
            destinations.push(destination.into());
        }
    }
    Ok(destinations)
}

fn get_destinations_from_configuration_file(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let path = path.as_ref();
    if let Some(ext) = path.extension() {
        if ext == "ovpn" {
            return get_destinations_from_ovpn_file(path);
        }
    }
    Ok(vec![])
}

pub fn get_destinations_from_configuration_files(
    paths: &[impl AsRef<Path>],
) -> io::Result<Vec<String>> {
    let mut destinations = vec![];
    for path in paths {
        let path = path.as_ref().canonicalize()?;
        if path.is_file() {
            destinations.extend_from_slice(&get_destinations_from_configuration_file(&path)?);
        } else if path.is_dir() {
            for entry in read_dir(&path)? {
                let path = entry?.path();
                if path.is_file() && !path.is_hidden() {
                    destinations
                        .extend_from_slice(&get_destinations_from_configuration_file(&path)?);
                }
            }
        }
    }
    Ok(destinations)
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Direction(String);

impl<'a> Direction {
    pub const IN: &'a str = "in:";
    pub const OUT: &'a str = "out:";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn safe_unwrap(&self) -> &str {
        self.0
            .trim_start_matches(Self::IN)
            .trim_start_matches(Self::OUT)
    }

    pub fn is_in(&self) -> bool {
        self.0.starts_with(Self::IN)
    }

    pub fn is_out(&self) -> bool {
        self.0.starts_with(Self::OUT)
    }

    pub fn has_no_direction(&self) -> bool {
        !self.is_in() && !self.is_out()
    }

    pub fn to_in_string(&self) -> String {
        format!("{}{}", Self::IN, &self.safe_unwrap())
    }

    pub fn to_out_string(&self) -> String {
        format!("{}{}", Self::OUT, &self.safe_unwrap())
    }

    pub fn to_in(&self) -> Self {
        Self(self.to_in_string())
    }

    pub fn to_out(&self) -> Self {
        Self(self.to_out_string())
    }
}

impl<S: AsRef<str>> From<S> for Direction {
    fn from(s: S) -> Self {
        Self::new(s.as_ref())
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Owner(String);

impl<'a> Owner {
    pub const USER: &'a str = "u:";
    pub const GROUP: &'a str = "g:";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn safe_unwrap(&self) -> &str {
        self.0
            .trim_start_matches(Self::USER)
            .trim_start_matches(Self::GROUP)
    }

    pub fn is_user(&self) -> bool {
        self.0.starts_with(Self::USER)
    }

    pub fn is_group(&self) -> bool {
        self.0.starts_with(Self::GROUP)
    }
}

impl<S: AsRef<str>> From<S> for Owner {
    fn from(s: S) -> Self {
        Self::new(s.as_ref())
    }
}
