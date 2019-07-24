package main

import "os/user"

func isRoot() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, err
	}
	return currentUser.Uid == "0", nil
}
