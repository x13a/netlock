package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

const defaultConfPath string = "/etc/pf.conf"

func NewPF(
	allowIncoming bool,
	allowOutgoing bool,
	allowPrivateNetwork bool,
	allowICMP bool,
	ips []string,
	interfaces []string,
) *PF {
	pf := &PF{
		defaultConfPath:     defaultConfPath,
		allowIncoming:       allowIncoming,
		allowOutgoing:       allowOutgoing,
		allowPrivateNetwork: allowPrivateNetwork,
		allowICMP:           allowICMP,
		ips:                 ips,
		interfaces:          interfaces,
	}
	return pf
}

type PF struct {
	ctlPath             string
	defaultConfPath     string
	allowIncoming       bool
	allowOutgoing       bool
	allowPrivateNetwork bool
	allowICMP           bool
	ips                 []string
	interfaces          []string
}

func (pf *PF) EnableLock() {
	pf.preconfig()
	pf.loadConf(pf.makeLockConf())
}

func (pf *PF) DisableLock() {
	pf.preconfig()
	pf.loadConf(pf.defaultConfPath)
}

func (pf *PF) isEnabled() bool {
	return strings.Contains(pf.exec("-si"), "Status: Enabled")
}

// Based on Eddie
func (pf *PF) BuildLockRules() string {
	var buf strings.Builder
	buf.WriteString("set block-policy return\n")
	interfaces := "lo0"
	if len(pf.interfaces) > 0 {
		interfaces = fmt.Sprintf(
			"%s %s",
			interfaces,
			strings.Join(pf.interfaces, " "),
		)
	}
	fmt.Fprintf(&buf, "set skip on { %s }\n", interfaces)
	buf.WriteString("scrub in all\n")
	if pf.allowIncoming {
		buf.WriteString("pass in all\n")
	} else {
		buf.WriteString("block in all\n")
	}
	if pf.allowOutgoing {
		buf.WriteString("pass out all\n")
	} else {
		buf.WriteString("block out all\n")
	}
	if pf.allowPrivateNetwork {
		buf.WriteString("pass out quick inet from 192.168.0.0/16 to 192.168.0.0/16\n")
		buf.WriteString("pass in quick inet from 192.168.0.0/16 to 192.168.0.0/16\n")
		buf.WriteString("pass out quick inet from 172.16.0.0/12 to 172.16.0.0/12\n")
		buf.WriteString("pass in quick inet from 172.16.0.0/12 to 172.16.0.0/12\n")
		buf.WriteString("pass out quick inet from 10.0.0.0/8 to 10.0.0.0/8\n")
		buf.WriteString("pass in quick inet from 10.0.0.0/8 to 10.0.0.0/8\n")
		buf.WriteString("pass out quick inet from 192.168.0.0/16 to 224.0.0.0/24\n")
		buf.WriteString("pass out quick inet from 172.16.0.0/12 to 224.0.0.0/24\n")
		buf.WriteString("pass out quick inet from 10.0.0.0/8 to 224.0.0.0/24\n")
		buf.WriteString("pass out quick inet from 192.168.0.0/16 to 239.255.255.250/32\n")
		buf.WriteString("pass out quick inet from 172.16.0.0/12 to 239.255.255.250/32\n")
		buf.WriteString("pass out quick inet from 10.0.0.0/8 to 239.255.255.250/32\n")
		buf.WriteString("pass out quick inet from 192.168.0.0/16 to 239.255.255.253/32\n")
		buf.WriteString("pass out quick inet from 172.16.0.0/12 to 239.255.255.253/32\n")
		buf.WriteString("pass out quick inet from 10.0.0.0/8 to 239.255.255.253/32\n")
		buf.WriteString("pass out quick inet6 from fe80::/10 to fe80::/10\n")
		buf.WriteString("pass in quick inet6 from fe80::/10 to fe80::/10\n")
		buf.WriteString("pass out quick inet6 from ff00::/8 to ff00::/8\n")
		buf.WriteString("pass in quick inet6 from ff00::/8 to ff00::/8\n")
	}
	if pf.allowICMP {
		buf.WriteString("pass quick proto icmp\n")
		buf.WriteString("pass quick proto icmp6 all\n")
	}
	ipRuleTmpl := "pass out quick %s from any to %s\n"
	for _, ip := range pf.ips {
		var inet string
		if strings.Contains(ip, ":") {
			inet = "inet6"
		} else {
			inet = "inet"
		}
		fmt.Fprintf(&buf, ipRuleTmpl, inet, ip)
	}
	return buf.String()
}

func (pf *PF) makeLockConf() string {
	tmpFile, err := ioutil.TempFile("", "netlock.*.conf")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tmpFile.WriteString(pf.BuildLockRules()); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		log.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		log.Fatal(err)
	}
	return tmpFile.Name()
}

func (pf *PF) preconfig() {
	ctlPath, err := exec.LookPath("pfctl")
	if err != nil {
		log.Fatal(err)
	}
	pf.ctlPath = ctlPath
	if !isRoot() {
		log.Fatal("sudo required for pfctl")
	}
	if !pf.isEnabled() {
		log.Fatal("pf is disabled")
	}
}

func (pf *PF) loadConf(confPath string) {
	pf.exec("-f", confPath)
}

func (pf *PF) exec(args ...string) string {
	return execCombinedOutput(pf.ctlPath, args...)
}
