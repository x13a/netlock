package main

import (
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func execCombinedOutput(filepath string, args ...string) string {
	out, err := exec.Command(filepath, args...).CombinedOutput()
	if err != nil {
		os.Stderr.WriteString(string(out))
		log.Fatal(err)
	}
	return string(out)
}

func split(s string) []string {
	var results []string
	for _, v := range strings.Split(s, " ") {
		if v != "" {
			results = append(results, v)
		}
	}
	return results
}

func isRoot() bool {
	cuser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return cuser.Uid == "0"
}
