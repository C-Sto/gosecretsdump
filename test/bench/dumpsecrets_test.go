package bench

import (
	"testing"

	"github.com/c-sto/gosecretsdump/pkg/ditreader"
)

/*
func BenchmarkBigProgram(t *testing.B) {
	dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
	//handle any output
	dataChan := dr.GetOutChan()
	for range dataChan {

	}
}*/

func TestProgram(t *testing.T) {
	dr := ditreader.New("../system", "../ntds.dit")
	//dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
	//handle any output
	dataChan := dr.GetOutChan()
	i := 0
	for range dataChan {
		i++
	}
	if i != 39 {
		t.Fatal("Did not recover all users. Expected 39, got ", i)
	}
}

func BenchmarkProgram(t *testing.B) {
	for i := 0; i < t.N; i++ {
		dr := ditreader.New("../system", "../ntds.dit")
		//dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
		//handle any output
		dataChan := dr.GetOutChan()

		for range dataChan {

		}

	}
}
