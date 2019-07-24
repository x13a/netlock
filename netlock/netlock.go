package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

type (
	flagDestinationsType struct{}
	flagInterfacesType   struct{}
	flagFilesType        struct{}
)

var (
	flagEnableLock               bool
	flagDisableLock              bool
	flagDefaultConfigurationPath string
	flagAllowIncoming            bool
	flagAllowOutgoing            bool
	flagAllowPrivateNetworks     bool
	flagAllowICMP                bool
	flagDestinations             flagDestinationsType
	flagInterfaces               flagInterfacesType
	flagFiles                    flagFilesType
	flagPrintLockRules           bool
	destinations                 []string
	interfaces                   []string
)

func setMultiple(dest *[]string, vals string) {
	for _, val := range strings.Split(vals, ",") {
		*dest = append(*dest, strings.TrimSpace(val))
	}
}

func (s *flagDestinationsType) String() string {
	return fmt.Sprint(*s)
}

func (s *flagDestinationsType) Set(val string) error {
	setMultiple(&destinations, val)
	return nil
}

func (s *flagInterfacesType) String() string {
	return fmt.Sprint(*s)
}

func (s *flagInterfacesType) Set(val string) error {
	setMultiple(&interfaces, val)
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
		var destination string
		for idx, submatch := range lineSubmatch {
			if idx != 0 && submatch != "" {
				destination = submatch
				break
			}
		}
		destinations = append(destinations, destination)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func flagParse() {
	flag.BoolVar(&flagEnableLock, "e", false, "Enable")
	flag.BoolVar(&flagDisableLock, "d", false, "Disable")
	flag.StringVar(
		&flagDefaultConfigurationPath,
		"default-configuration-path",
		"",
		"Custom default configuration path",
	)
	flag.BoolVar(&flagAllowIncoming, "allow-incoming", false, "Allow incoming")
	flag.BoolVar(&flagAllowOutgoing, "allow-outgoing", false, "Allow outgoing")
	flag.BoolVar(
		&flagAllowPrivateNetworks,
		"allow-private-networks",
		false,
		"Allow private networks",
	)
	flag.BoolVar(&flagAllowICMP, "allow-icmp", false, "Allow ICMP")
	flag.Var(&flagDestinations, "pass", "Pass to destinations")
	flag.Var(&flagInterfaces, "skip", "Skip on interfaces")
	flag.Var(
		&flagFiles,
		"file",
		"Pass to destinations from openvpn/wireguard configuration file",
	)
	flag.BoolVar(&flagPrintLockRules, "print", false, "Print lock rules")
	flag.Parse()
}

func init() {
	flagParse()
	if flagEnableLock && flagDisableLock {
		log.Fatal("Enable and disable are mutually exclusive")
	}
	if !flagEnableLock && !flagDisableLock && !flagPrintLockRules {
		flag.PrintDefaults()
		os.Exit(64)
	}
}

func main() {
	pf := NewPF(
		flagDefaultConfigurationPath,
		flagAllowIncoming,
		flagAllowOutgoing,
		flagAllowPrivateNetworks,
		flagAllowICMP,
		destinations,
		interfaces,
	)
	if flagPrintLockRules {
		fmt.Println(pf.BuildLockRules())
	}
	if flagEnableLock {
		pf.EnableLock()
		fmt.Println("OK")
	} else if flagDisableLock {
		pf.DisableLock()
		fmt.Println("OK")
	}
}
