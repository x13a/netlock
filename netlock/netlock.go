package main

import (
	"fmt"
	"flag"
	"log"
	"os"
	"strings"
	"net"
	"errors"
	"bufio"
)


type (
	flagIPsType []string
	flagSliceType []string
	flagHostsType []string
	flagFilesType []string
)


var (
	flagEnableLock bool
	flagDisableLock bool
	flagAllowIncoming bool
	flagAllowOutgoing bool
	flagAllowPrivateNetwork bool
	flagAllowICMP bool
	flagIPs flagIPsType
	flagInterfaces flagSliceType
	flagHosts flagHostsType
	flagFiles flagFilesType
	flagPrintLockRulesAndExit bool
)


func addIP(ip string) error {
	if addr := net.ParseIP(ip); addr != nil {
		flagIPs = append(flagIPs, ip)
		return nil
	}
	return errors.New("Invalid ip")
}


func addHostIPs(host string) error {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		flagIPs = append(flagIPs, addr.String())
	}
	return nil
}


func (s *flagIPsType) String() string {
	return fmt.Sprint(*s)
}


func (s *flagIPsType) Set(val string) error {
	return addIP(val)
}


func (s *flagSliceType) String() string {
	return fmt.Sprint(*s)
}


func (s *flagSliceType) Set(val string) error {
	*s = append(*s, val)
	return nil
}


func (s *flagHostsType) String() string {
	return fmt.Sprint(*s)
}


func (s *flagHostsType) Set(val string) error {
	return addHostIPs(val)
}


func (s *flagFilesType) String() string {
	return fmt.Sprint(*s)
}


func (s *flagFilesType) Set(val string) error {
	file, err := os.Open(val)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "remote ") {
			continue
		}
		lineSlice := split(line)
		if len(lineSlice) < 2 {
			continue
		}
		ipOrHost := lineSlice[1]
		if err := addIP(ipOrHost); err == nil {
			continue
		}
		if err := addHostIPs(ipOrHost); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}


func parseArgs() {
	flag.BoolVar(&flagEnableLock, "e", false, "Enable lock")
	flag.BoolVar(&flagDisableLock, "d", false, "Disable lock")
	flag.BoolVar(
		&flagAllowIncoming, 
		"allow-incoming",
		false, 
		"Allow incoming connections outside vpn",
	)
	flag.BoolVar(
		&flagAllowOutgoing,
		"allow-outgoing",
		false,
		"Allow outgoing connections outside vpn",
	)
	flag.BoolVar(
		&flagAllowPrivateNetwork,
		"allow-private-network",
		false,
		"Allow private network access outside vpn",
	)
	flag.BoolVar(&flagAllowICMP, "allow-icmp", false, "Allow ICMP outside vpn")
	flag.Var(&flagIPs, "ip", "Pass to ip")
	flag.Var(&flagInterfaces, "if", "Skip on interface")
	flag.Var(&flagHosts, "host", "Add ips resolving host")
	flag.Var(&flagFiles, "file", "Add ips reading .ovpn file")
	flag.BoolVar(
		&flagPrintLockRulesAndExit, 
		"print", 
		false, 
		"Print lock rules and exit",
	)
	flag.Parse()
}


func init() {
	parseArgs()
	if flagEnableLock && flagDisableLock {
		log.Fatal("Enable and disable are mutually exclusive")
	} else if
		!flagEnableLock && 
		!flagDisableLock && 
		!flagPrintLockRulesAndExit {

		flag.PrintDefaults()
		os.Exit(64)
	}
}


func main() {
	pf := NewPF(
		flagAllowIncoming,
		flagAllowOutgoing,
		flagAllowPrivateNetwork,
		flagAllowICMP,
		flagIPs,
		flagInterfaces,
	)
	if flagEnableLock {
		log.Println("Enabling lock..")
		pf.EnableLock()
		log.Println("Done")
	} else if flagDisableLock {
		log.Println("Disabling lock..")
		pf.DisableLock()
		log.Println("Done")
	} else if flagPrintLockRulesAndExit {
		pf.PrintLockRules()
	}
}