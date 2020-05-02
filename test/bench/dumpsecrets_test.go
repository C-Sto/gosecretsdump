package bench

import (
	"testing"

	"github.com/C-Sto/gosecretsdump/pkg/ditreader"
)

/*
func BenchmarkBigProgram(t *testing.B) {
	dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
	//handle any output
	dataChan := dr.GetOutChan()
	for range dataChan {

	}
}*/

func BenchmarkProgram(t *testing.B) {
	t.ReportAllocs()
	for i := 0; i < t.N; i++ {
		dr, err := ditreader.New("../system", "../ntds.dit")
		if err != nil {
			t.Fatal(err)
		}
		//dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
		//handle any output
		dataChan := dr.GetOutChan()
		go dr.Dump()
		for range dataChan {

		}

	}
}
