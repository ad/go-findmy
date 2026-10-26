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
	default:
		fmt.Fprintln(os.Stderr, "usage: go-findmy keygen|fetch")
		os.Exit(2)
	}
}
