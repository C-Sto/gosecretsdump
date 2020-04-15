package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/C-Sto/gosecretsdump/pkg/ditreader"
)

type Settings struct {
	SystemLoc   string
	NTDSLoc     string
	Status      bool
	EnabledOnly bool
	Outfile     string
	NoPrint     bool
	Stream      bool
	History     bool
}

func GoSecretsDump(s Settings) error {
	dr, err := ditreader.New(s.SystemLoc, s.NTDSLoc)
	if err != nil {
		return err
	}
	//handle any output
	dataChan := dr.GetOutChan()
	if s.Outfile != "" {
		fmt.Println("Writing to file ", s.Outfile)
		if s.Stream {
			fileStreamWriter(dataChan, s)
		} else {
			fileWriter(dataChan, s)
		}
	} else {
		consoleWriter(dataChan, s)
	}
	return nil
}

func consoleWriter(val <-chan ditreader.DumpedHash, s Settings) {
	for dh := range val {
		if s.EnabledOnly {
			if dh.UAC.AccountDisable {
				continue
			}
		}
		var append strings.Builder
		if s.Status {
			stat := "Enabled"
			if dh.UAC.AccountDisable {
				stat = "Disabled"
			}
			append.WriteString(" (status=")
			append.WriteString(stat)
			append.WriteString(")")
		}
		var hs strings.Builder
		hs.WriteString(dh.HashString())
		hs.WriteString(append.String())
		hs.WriteString("\n")
		if dh.Supp.Username != "" {
			hs.WriteString(dh.Supp.ClearString())
			hs.WriteString(append.String())
			if len(dh.Supp.KerbKeys) > 0 {
				hs.WriteString("\n")
				hs.WriteString(dh.Supp.KerbString())
				hs.WriteString(append.String())
			}
			hs.WriteString("\n")
			if s.History {
				hs.WriteString(dh.HistoryString())
			}
			//pts = dh.Supp.HashString() + "\n"
		}
		fmt.Print(hs.String())
	}
}

func fileWriter(val <-chan ditreader.DumpedHash, s Settings) {

	//build up the data to eventually write
	hashes := strings.Builder{}
	plaintext := strings.Builder{}
	kerbs := strings.Builder{}

	for dh := range val {
		//dh := <-val
		if s.EnabledOnly {
			if dh.UAC.AccountDisable {
				continue
			}
		}
		var append strings.Builder
		if s.Status {
			stat := "Enabled"
			if dh.UAC.AccountDisable {
				stat = "Disabled"
			}
			append.WriteString(" (status=")
			append.WriteString(stat)
			append.WriteString(")")
		}

		var hs strings.Builder
		hs.WriteString(dh.HashString())
		hs.WriteString(append.String())
		hs.WriteString("\n")
		hashes.WriteString(hs.String())
		var pts strings.Builder
		if dh.Supp.Username != "" {
			pts.WriteString(dh.Supp.ClearString())
			pts.WriteString(append.String())
			pts.WriteString("\n")
			if len(dh.Supp.KerbKeys) > 0 {
				kerbs.WriteString(dh.Supp.KerbString())
				kerbs.WriteString(append.String())
				kerbs.WriteString("\n")
			}

			//pts = dh.Supp.HashString() + "\n"
			plaintext.WriteString(pts.String())
		}
		hashes.WriteString(hs.String())
		//fmt.Print(hs.String() + pts.String())
	}

	file, err := os.OpenFile(s.Outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err) //ok to panic here
	}
	defer file.Close()
	file.WriteString(hashes.String())

	ctfile, err := os.OpenFile(s.Outfile+".cleartext", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err) //ok to panic here
	}
	defer ctfile.Close()
	ctfile.WriteString(plaintext.String())

	krbfile, err := os.OpenFile(s.Outfile+".kerb", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer krbfile.Close()
	krbfile.WriteString(kerbs.String())

}

func fileStreamWriter(val <-chan ditreader.DumpedHash, s Settings) {
	file, err := os.OpenFile(s.Outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err) //ok to panic here
	}
	defer file.Close()

	ctfile, err := os.OpenFile(s.Outfile+".cleartext", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		panic(err) //ok to panic here
	}
	defer ctfile.Close()
	count := 0
	for dh := range val {
		//dh := <-val
		append := ""
		if s.Status {
			stat := "Enabled"
			if dh.UAC.AccountDisable {
				stat = "Disabled"
			}
			append += " (status=" + stat + ")"
		}
		if s.EnabledOnly {
			if dh.UAC.AccountDisable {
				continue
			}
		}

		hs := dh.HashString() + append + "\n"
		pts := ""
		if dh.Supp.Username != "" {
			pts = dh.Supp.ClearString() + append + "\n"
			ctfile.WriteString(pts)
		}
		file.WriteString(hs)
		fmt.Print(hs + pts)

		count++
		if count%10 == 1 {
			file.Sync()
		}
	}
}
