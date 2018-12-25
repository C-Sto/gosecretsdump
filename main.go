package main

import (
	"flag"
	"os"

	"github.com/c-sto/gosecretsdump/libdumpsecrets"
)

type settings struct {
	NtdsLocation   string
	SystemLocation string
}

func main() {
	s := libdumpsecrets.Settings{}
	flag.StringVar(&s.NTDSLoc, "ntds", "", "Location of the NTDS file (required)")
	flag.StringVar(&s.SystemLoc, "system", "", "Location of the SYSTEM file (required)")
	flag.BoolVar(&s.Status, "status", false, "Include status in hash output")
	flag.BoolVar(&s.EnabledOnly, "enabled", false, "Only output enabled accounts")
	flag.Parse()

	if s.SystemLoc == "" || s.NTDSLoc == "" {
		flag.Usage()
		os.Exit(1)
	}

	gsd := libdumpsecrets.Gosecretsdump{}.Init(s)

	gsd.Dump()
}

//info dumped out of https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py
