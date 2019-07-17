package main

import (
	"log"
	"os"
	"os/exec"
	"os/user"
)

func execCombinedOutput(filepath string, args ...string) string {
	stdoutStderr, err := exec.Command(filepath, args...).CombinedOutput()
	if err != nil {
		os.Stderr.Write(stdoutStderr)
		log.Fatal(err)
	}
	return string(stdoutStderr)
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return currentUser.Uid == "0"
}
