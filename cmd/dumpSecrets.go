package cmd

import (
	"sync"

	"github.com/c-sto/gosecretsdump/pkg/ditreader"
)

type Settings struct {
	SystemLoc   string
	NTDSLoc     string
	Status      bool
	EnabledOnly bool
	Outfile     string
	NoPrint     bool
}

func GoSecretsDump(s Settings) {
	wg := &sync.WaitGroup{}
	dr := ditreader.New(s.NTDSLoc, s.SystemLoc)
	//start reading from db
	go dr.Dump(wg)

	//handle any output

	//ensure dumping has finished before exiting
	wg.Wait()

}
