package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "keygen":
		keygen()
	case "fetch":
		fetch()
	case "login":
		login(len(os.Args) > 2 && os.Args[2] == "sms")
	case "serve":
		serve()
	default:
		fmt.Fprintln(os.Stderr, "usage: go-findmy keygen|login [sms]|fetch|serve")
		os.Exit(2)
	}
}
