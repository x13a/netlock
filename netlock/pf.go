package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

const pfDefaultConfigurationPath string = "/etc/pf.conf"

func NewPF(
	defaultConfigurationPath string,
	allowIncoming bool,
	allowOutgoing bool,
	allowPrivateNetworks bool,
	allowICMP bool,
	destinations []string,
	interfaces []string,
) *PF {
	if defaultConfigurationPath == "" {
		defaultConfigurationPath = pfDefaultConfigurationPath
	}
	return &PF{
		defaultConfigurationPath: defaultConfigurationPath,
		destinationsTableName:    "allowed_destinations",
		allowIncoming:            allowIncoming,
		allowOutgoing:            allowOutgoing,
		allowPrivateNetworks:     allowPrivateNetworks,
		allowICMP:                allowICMP,
		destinations:             destinations,
		interfaces:               interfaces,
	}
}

type PF struct {
	ctlPath                  string
	defaultConfigurationPath string
	destinationsTableName    string
	allowIncoming            bool
	allowOutgoing            bool
	allowPrivateNetworks     bool
	allowICMP                bool
	destinations             []string
	interfaces               []string
}

func (pf *PF) EnableLock() {
	pf.preconfig()
	pf.loadConfiguration(pf.makeLockConfiguration())
}

func (pf *PF) DisableLock() {
	pf.preconfig()
	pf.loadConfiguration(pf.defaultConfigurationPath)
}

func (pf *PF) isEnabled() bool {
	return strings.Contains(
		strings.ToLower(pf.mustExec("-s", "info")),
		"status: enabled",
	)
}

// Based on Eddie
func (pf *PF) BuildLockRules() string {
	var buf strings.Builder
	fmt.Fprintf(
		&buf,
		"table <%s> { %s }\n",
		pf.destinationsTableName,
		strings.Join(pf.destinations, ", "),
	)
	buf.WriteString("set block-policy return\n")
	interfaces := "lo0"
	if len(pf.interfaces) > 0 {
		interfaces = fmt.Sprintf(
			"%s, %s",
			interfaces,
			strings.Join(pf.interfaces, ", "),
		)
	}
	fmt.Fprintf(&buf, "set skip on { %s }\n", interfaces)
	buf.WriteString("scrub in all fragment reassemble\n")
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
	if pf.allowPrivateNetworks {
		ipv4PrivateAddrs := []string{
			"169.254/16",
			"192.168/16",
			"172.16/12",
			"10/8",
		}
		for _, addr := range ipv4PrivateAddrs {
			fmt.Fprintf(&buf, "pass quick from %s to %s\n", addr, addr)
		}
		fmt.Fprintf(
			&buf,
			"pass out quick from { %s } to { 224/24, 255.255.255.255/32 }\n",
			strings.Join(ipv4PrivateAddrs, ", "),
		)
		ipv6PrivateAddrs := []string{"fe80::/10", "fc00::/7"}
		for _, addr := range ipv6PrivateAddrs {
			fmt.Fprintf(&buf, "pass quick from %s to %s\n", addr, addr)
		}
		fmt.Fprintf(
			&buf,
			"pass out quick from { %s } to { ff02::/16, ff12::/16 }\n",
			strings.Join(ipv6PrivateAddrs, ", "),
		)
	}
	if pf.allowICMP {
		buf.WriteString("pass quick proto { icmp, icmp6 } all\n")
	}
	fmt.Fprintf(
		&buf,
		"pass out quick from any to <%s>\n",
		pf.destinationsTableName,
	)
	return buf.String()
}

func (pf *PF) makeLockConfiguration() string {
	tmpf, err := ioutil.TempFile("", "netlock.*.conf")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tmpf.WriteString(pf.BuildLockRules()); err != nil {
		tmpf.Close()
		os.Remove(tmpf.Name())
		log.Fatal(err)
	}
	if err := tmpf.Close(); err != nil {
		log.Fatal(err)
	}
	return tmpf.Name()
}

func (pf *PF) preconfig() {
	ctlPath, err := exec.LookPath("pfctl")
	if err != nil {
		log.Fatal(err)
	}
	pf.ctlPath = ctlPath
	if _, err := os.Stat(pf.defaultConfigurationPath); err != nil {
		log.Fatalf("stat() failed on %s", pf.defaultConfigurationPath)
	}
	if isRootResult, err := isRoot(); err != nil {
		log.Fatal(err)
	} else if !isRootResult {
		log.Fatal("sudo is required for pfctl")
	}
	if !pf.isEnabled() {
		log.Fatal("Packet filter is disabled")
	}
}

func (pf *PF) loadConfiguration(path string) string {
	return pf.mustExec("-F", "all", "-f", path)
}

func (pf *PF) mustExec(args ...string) string {
	result, err := exec.Command(pf.ctlPath, args...).CombinedOutput()
	if err != nil {
		os.Stderr.Write(result)
		log.Fatal(err)
	}
	return string(result)
}
