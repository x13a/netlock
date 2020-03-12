use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::utils::{exec, ExecResult};

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
            assert!(interface.starts_with("utun") || interface.starts_with("tun"));
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
