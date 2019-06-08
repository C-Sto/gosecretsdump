package main

import (
	"flag"
	"os"

	"github.com/pkg/profile"

	"github.com/c-sto/gosecretsdump/cmd"
)

func main() {

	defer profile.Start().Stop()

	s := cmd.Settings{}
	flag.StringVar(&s.Outfile, "out", "", "Location to export output")
	flag.StringVar(&s.NTDSLoc, "ntds", "", "Location of the NTDS file (required)")
	flag.StringVar(&s.SystemLoc, "system", "", "Location of the SYSTEM file (required)")
	flag.BoolVar(&s.Status, "status", false, "Include status in hash output")
	flag.BoolVar(&s.EnabledOnly, "enabled", false, "Only output enabled accounts")
	flag.BoolVar(&s.NoPrint, "noprint", false, "Don't print output to screen (probably use this with the -out flag)")
	flag.Parse()

	if s.SystemLoc == "" || s.NTDSLoc == "" {
		flag.Usage()
		os.Exit(1)
	}

	cmd.GoSecretsDump(s)
}

//info dumped out of https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py
