package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/ad/go-findmy/internal/anisette"
	"github.com/ad/go-findmy/internal/icloud"
)

const accountDir = "account"

func login(sms bool) {
	sc := anisette.New(anisetteURL)
	acct, err := icloud.Open(accountDir, sc)
	if err != nil {
		log.Fatal(err)
	}
	if err := acct.Cooldown(); err != nil {
		log.Fatal(err)
	}

	in := bufio.NewReader(os.Stdin)
	appleID := ask(in, "Apple ID: ")
	stty("-echo")
	password := ask(in, "Password: ")
	stty("echo")
	fmt.Println()

	// A fresh machine is accepted for about 60 s, so credentials come first and the login right after.
	fresh, err := sc.Provision()
	if err != nil {
		log.Fatal(err)
	}
	if fresh {
		log.Print("anisette: provisioned a new machine")
	}

	ctx := context.Background()
	sf, err := acct.Login(ctx, appleID, password)
	if err != nil {
		log.Fatal(err)
	}
	if sf != nil {
		if sms || !sf.TrustedDevice {
			err = smsCode(ctx, in, sf)
		} else {
			err = trustedDeviceCode(ctx, in, sf)
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("logged in, tokens saved in %s/\n", accountDir)
}

func stty(arg string) {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	cmd.Run()
}

func ask(in *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	s, err := in.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(s)
}

func trustedDeviceCode(ctx context.Context, in *bufio.Reader, sf *icloud.SecondFactor) error {
	if err := sf.RequestTrustedDeviceCode(ctx); err != nil {
		return err
	}
	return sf.SubmitTrustedDeviceCode(ctx, ask(in, "Code from your Apple device: "))
}

func smsCode(ctx context.Context, in *bufio.Reader, sf *icloud.SecondFactor) error {
	phones, err := sf.Phones(ctx)
	if err != nil {
		return err
	}
	if len(phones) == 0 {
		return fmt.Errorf("icloud: the account has no trusted phone numbers")
	}
	for i, p := range phones {
		fmt.Printf("%d) %s\n", i+1, p.Number)
	}
	n := 1
	if len(phones) > 1 {
		fmt.Sscan(ask(in, "Phone number: "), &n)
	}
	if n < 1 || n > len(phones) {
		return fmt.Errorf("no phone number %d", n)
	}
	id := phones[n-1].ID
	if err := sf.RequestSMSCode(ctx, id); err != nil {
		return err
	}
	return sf.SubmitSMSCode(ctx, id, ask(in, "SMS code: "))
}
