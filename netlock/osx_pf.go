package main

import (
	"strings"
	"fmt"
	"log"
	"io/ioutil"
	"os/exec"
)

const defaultConfPath = "/etc/pf.conf"


func NewPF(
	allowIncoming bool,
	allowOutgoing bool,
	allowPrivateNetwork bool, 
	allowICMP bool, 
	ips []string, 
	interfaces []string,
) *PF {
	pf := &PF{
		defaultConfPath: defaultConfPath,
		allowIncoming: allowIncoming,
		allowOutgoing: allowOutgoing,
		allowICMP: allowICMP,
		allowPrivateNetwork: allowPrivateNetwork,
		ips: ips,
		interfaces: interfaces,
	}
	return pf
}


type PF struct {
	ctlPath string
	defaultConfPath string
	allowIncoming bool
	allowOutgoing bool
	allowPrivateNetwork bool
	allowICMP bool
	ips []string
	interfaces []string
}


func (pf *PF) EnableLock() {
	pf.preconfig()
	pf.loadConf(pf.makeLockConf())
}


func (pf *PF) DisableLock() {
	pf.preconfig()
	pf.loadConf(pf.defaultConfPath)
}


func (pf *PF) PrintLockRules() {
	log.Println(pf.makeLockRules())
}


func (pf *PF) isEnabled() bool {
	return strings.Contains(pf.exec("-si"), "Status: Enabled")
}


func (pf *PF) makeLockRules() string {
	rules := "set block-policy return\n"
	interfaces := "lo0"
	if len(pf.interfaces) > 0 {
		interfaces = fmt.Sprintf(
			"%s %s", 
			interfaces, 
			strings.Join(pf.interfaces, " "),
		)
	}
	rules += fmt.Sprintf("set skip on { %s }\n", interfaces)
	rules += "scrub in all\n"
	if pf.allowIncoming {
		rules += "pass in all\n"
	} else {
		rules += "block in all\n"
	}
	if pf.allowOutgoing {
		rules += "pass out all\n"
	} else {
		rules += "block out all\n"
	}
	if pf.allowPrivateNetwork {
		rules += "pass out quick inet from 192.168.0.0/16 to 192.168.0.0/16\n"
		rules += "pass in quick inet from 192.168.0.0/16 to 192.168.0.0/16\n"
		rules += "pass out quick inet from 172.16.0.0/12 to 172.16.0.0/12\n"
		rules += "pass in quick inet from 172.16.0.0/12 to 172.16.0.0/12\n"
		rules += "pass out quick inet from 10.0.0.0/8 to 10.0.0.0/8\n"
		rules += "pass in quick inet from 10.0.0.0/8 to 10.0.0.0/8\n"
		rules += "pass out quick inet from 192.168.0.0/16 to 224.0.0.0/24\n"
		rules += "pass out quick inet from 172.16.0.0/12 to 224.0.0.0/24\n"
		rules += "pass out quick inet from 10.0.0.0/8 to 224.0.0.0/24\n"
		rules += "pass out quick inet from 192.168.0.0/16 to 239.255.255.250/32\n"
		rules += "pass out quick inet from 172.16.0.0/12 to 239.255.255.250/32\n"
		rules += "pass out quick inet from 10.0.0.0/8 to 239.255.255.250/32\n"
		rules += "pass out quick inet from 192.168.0.0/16 to 239.255.255.253/32\n"
		rules += "pass out quick inet from 172.16.0.0/12 to 239.255.255.253/32\n"
		rules += "pass out quick inet from 10.0.0.0/8 to 239.255.255.253/32\n"
		rules += "pass out quick inet6 from fe80::/10 to fe80::/10\n"
		rules += "pass in quick inet6 from fe80::/10 to fe80::/10\n"
		rules += "pass out quick inet6 from ff00::/8 to ff00::/8\n"
		rules += "pass in quick inet6 from ff00::/8 to ff00::/8\n"
	}
	if pf.allowICMP {
		rules += "pass quick proto icmp\n"
		rules += "pass quick proto icmp6 all\n"
	}
	ipRuleTmpl := "pass out quick %s from any to %s\n"
	for _, ip := range pf.ips {
		inet := "inet"
		if strings.Contains(ip, ":") {
			inet = "inet6"
		}
		rules += fmt.Sprintf(ipRuleTmpl, inet, ip)
	}
	return rules
}


func (pf *PF) makeLockConf() string {
	tmpfile, err := ioutil.TempFile("", "netlock.*.conf")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tmpfile.WriteString(pf.makeLockRules()); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	return tmpfile.Name()
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
