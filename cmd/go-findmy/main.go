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
	case "serve":
		serve()
	default:
		fmt.Fprintln(os.Stderr, "usage: go-findmy keygen|fetch|serve")
		os.Exit(2)
	}
}
