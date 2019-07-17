package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
)

const stringsDone string = "OK"

type (
	flagServersType []string
	flagSliceType   []string
	flagFilesType   []string
)

var (
	flagEnableLock          bool
	flagDisableLock         bool
	flagAllowIncoming       bool
	flagAllowOutgoing       bool
	flagAllowPrivateNetwork bool
	flagAllowICMP           bool
	flagServers             flagServersType
	flagInterfaces          flagSliceType
	flagFiles               flagFilesType
	flagPrintLockRules      bool
)

func addServer(s string) error {
	if net.ParseIP(s) != nil {
		flagServers = append(flagServers, s)
		return nil
	}
	addrs, err := net.LookupIP(s)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		flagServers = append(flagServers, addr.String())
	}
	return nil
}

func (s *flagServersType) String() string {
	return fmt.Sprint(*s)
}

func (s *flagServersType) Set(val string) error {
	return addServer(val)
}

func (s *flagSliceType) String() string {
	return fmt.Sprint(*s)
}

func (s *flagSliceType) Set(val string) error {
	*s = append(*s, val)
	return nil
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
	subgroup := `([^\s]{4,})`
	re := regexp.MustCompile(fmt.Sprintf(
		`(?:remote\s%s|Endpoint\s?=\s?%s:)`,
		subgroup,
		subgroup,
	))
	for scanner.Scan() {
		lineSubmatch := re.FindStringSubmatch(scanner.Text())
		if lineSubmatch == nil {
			continue
		}
		var server string
		for idx, submatch := range lineSubmatch {
			if idx != 0 && submatch != "" {
				server = submatch
				break
			}
		}
		if err := addServer(server); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func flagParse() {
	flag.BoolVar(&flagEnableLock, "e", false, "Enable")
	flag.BoolVar(&flagDisableLock, "d", false, "Disable")
	flag.BoolVar(&flagAllowIncoming, "allow-incoming", false, "Allow incoming")
	flag.BoolVar(&flagAllowOutgoing, "allow-outgoing", false, "Allow outgoing")
	flag.BoolVar(
		&flagAllowPrivateNetwork,
		"allow-private-network",
		false,
		"Allow private network",
	)
	flag.BoolVar(&flagAllowICMP, "allow-icmp", false, "Allow ICMP")
	flag.Var(&flagServers, "pass", "Pass to ip/host")
	flag.Var(&flagInterfaces, "skip", "Skip on interface")
	flag.Var(
		&flagFiles,
		"file",
		"Pass to servers from openvpn/wireguard configuration file",
	)
	flag.BoolVar(&flagPrintLockRules, "print", false, "Print lock rules")
	flag.Parse()
}

func init() {
	flagParse()
	if flagEnableLock && flagDisableLock {
		log.Fatal("Enable and disable are mutually exclusive")
	} else if !flagEnableLock && !flagDisableLock && !flagPrintLockRules {
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
		flagServers,
		flagInterfaces,
	)
	if flagPrintLockRules {
		fmt.Println(pf.BuildLockRules())
	}
	if flagEnableLock {
		pf.EnableLock()
		fmt.Println(stringsDone)
	} else if flagDisableLock {
		pf.DisableLock()
		fmt.Println(stringsDone)
	}
}
