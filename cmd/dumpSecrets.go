package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/C-Sto/gosecretsdump/pkg/ditreader"
	"github.com/C-Sto/gosecretsdump/pkg/samreader"
)

type Dumper interface {
	//New(string, string) (Dumper, error)
	GetOutChan() <-chan ditreader.DumpedHash
	Dump() error
}

type Settings struct {
	SystemLoc   string
	NTDSLoc     string
	SAMLoc      string
	LiveSAM     bool
	Status      bool
	EnabledOnly bool
	Outfile     string
	NoPrint     bool
	Stream      bool
	History     bool
}

func GoSecretsDump(s Settings) error {
	var dr Dumper
	var err error
	if s.NTDSLoc != "" {
		dr, err = ditreader.New(s.SystemLoc, s.NTDSLoc)
		if err != nil {
			return err
		}
	}

	if s.SAMLoc != "" {
		dr, err = samreader.New(s.SystemLoc, s.SAMLoc)
		if err != nil {
			return err
		}
	}

	if s.LiveSAM {
		dr, err = samreader.NewLive()
		if err != nil {
			return err
		}
	}

	//handle any output
	dataChan := dr.GetOutChan()
	wg := sync.WaitGroup{}
	wg.Add(1)
	if s.Outfile != "" {
		fmt.Printf("Writing to file %s\n", s.Outfile)
		if s.Stream {
			go fileStreamWriter(dataChan, s, &wg)
		} else {
			go fileWriter(dataChan, s, &wg)
		}
	} else {
		go consoleWriter(dataChan, s, &wg)
	}
	e := dr.Dump()
	if e != nil {
		return e
	}
	wg.Wait()
	return e
}

func consoleWriter(val <-chan ditreader.DumpedHash, s Settings, wg *sync.WaitGroup) {
	defer wg.Done()
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
			if dh.Supp.ClearPassword != "" {
				hs.WriteString(dh.Supp.ClearString())
				hs.WriteString(append.String())
				hs.WriteString("\n")
			}
			if len(dh.Supp.KerbKeys) > 0 {
				hs.WriteString(dh.Supp.KerbString())
				hs.WriteString(append.String())
				hs.WriteString("\n")
			}
			if s.History {
				hs.WriteString(dh.HistoryString())
			}
			//pts = dh.Supp.HashString() + "\n"
		}
		fmt.Print(hs.String())
	}
}

func fileWriter(val <-chan ditreader.DumpedHash, s Settings, wg *sync.WaitGroup) {
	defer wg.Done()
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
		var pts strings.Builder
		if dh.Supp.Username != "" {
			if dh.Supp.ClearPassword != "" {
				pts.WriteString(dh.Supp.ClearString())
				pts.WriteString(append.String())
				pts.WriteString("\n")
			}
			if len(dh.Supp.KerbKeys) > 0 {
				kerbs.WriteString(dh.Supp.KerbString())
				kerbs.WriteString(append.String())
				kerbs.WriteString("\n")
			}
			if s.History {
				hs.WriteString(dh.HistoryString())
			}
			//pts = dh.Supp.HashString() + "\n"
			plaintext.WriteString(pts.String())
		}
		hashes.WriteString(hs.String())
		//fmt.Print(hs.String() + pts.String())
	}

	if hashes.Len() > 0 {
		file, err := os.OpenFile(s.Outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			panic(err) //ok to panic here
		}
		defer file.Close()
		file.WriteString(hashes.String())
	}

	if plaintext.Len() > 0 {
		ctfile, err := os.OpenFile(s.Outfile+".cleartext", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			panic(err) //ok to panic here
		}
		defer ctfile.Close()
		ctfile.WriteString(plaintext.String())
	}

	if kerbs.Len() > 0 {
		krbfile, err := os.OpenFile(s.Outfile+".kerb", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		defer krbfile.Close()
		krbfile.WriteString(kerbs.String())
	}

}

func fileStreamWriter(val <-chan ditreader.DumpedHash, s Settings, wg *sync.WaitGroup) {
	defer wg.Done()
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
