package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/C-Sto/gosecretsdump/cmd"
)

const version = "0.2.0"

func main() {

	//defer profile.Start(profile.ProfilePath("./")).Stop()
	//defer profile.Start(profile.MemProfile, profile.ProfilePath("./")).Stop()
	//defer profile.Start(profile.BlockProfile, profile.ProfilePath("./")).Stop()
	fmt.Println("gosecretsdump v" + version + " (@C__Sto)")
	s := cmd.Settings{}
	var vers bool
	flag.StringVar(&s.Outfile, "out", "", "Location to export output")
	flag.StringVar(&s.NTDSLoc, "ntds", "", "Location of the NTDS file (required)")
	flag.StringVar(&s.SystemLoc, "system", "", "Location of the SYSTEM file (required)")
	flag.BoolVar(&s.Status, "status", false, "Include status in hash output")
	flag.BoolVar(&s.EnabledOnly, "enabled", false, "Only output enabled accounts")
	flag.BoolVar(&s.NoPrint, "noprint", false, "Don't print output to screen (probably use this with the -out flag)")
	flag.BoolVar(&s.Stream, "stream", false, "Stream to files rather than writing in a block. Can be much slower.")
	flag.BoolVar(&vers, "version", false, "Print version and exit")
	flag.BoolVar(&s.History, "history", false, "Include Password History")
	flag.Parse()

	if vers {
		os.Exit(0)
	}
	if s.SystemLoc == "" || s.NTDSLoc == "" {
		flag.Usage()
		os.Exit(1)
	}
	cmd.GoSecretsDump(s)
}

//info dumped out of https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py
