package cmd

import (
	"fmt"

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
	dr := ditreader.New(s.SystemLoc, s.NTDSLoc)
	//handle any output
	dataChan := dr.GetOutChan()

	for val := range dataChan {
		fmt.Println(val.HashString())
	}

}
