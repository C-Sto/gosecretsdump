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
	s := settings{}
	flag.StringVar(&s.NtdsLocation, "ntds", "", "Location of the NTDS file (required)")
	flag.StringVar(&s.SystemLocation, "system", "", "Location of the SYSTEM file (required)")
	flag.Parse()

	if s.SystemLocation == "" || s.NtdsLocation == "" {
		flag.Usage()
		os.Exit(1)
	}

	gsd := libdumpsecrets.Gosecretsdump{}.Init(s.NtdsLocation, s.SystemLocation)

	gsd.Dump()
}

//info dumped out of https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py
