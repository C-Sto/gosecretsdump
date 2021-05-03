package test

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/C-Sto/gosecretsdump/pkg/ditreader"
)

func TestProgram(t *testing.T) {
	dr, err := ditreader.New("./system", "./ntds.dit")
	if err != nil {
		t.Fatal(err)
	}
	//dr := ditreader.New("../big/registry/SYSTEM", "../big/Active Directory/ntds.dit")
	//handle any output
	dataChan := dr.GetOutChan()
	go dr.Dump()
	i := 0
	for range dataChan {
		i++
	}
	if i != 39 {
		t.Fatal("Did not recover all users. Expected 39, got ", i)
	}
}

func TestGetHashes(t *testing.T) {
	//get valid output files
	s, e := ioutil.ReadFile("impacket-out/2016/2016.ntds")
	if e != nil {
		t.Error("Could not read from 2016 file")
	}
	corretkerb := make(map[string]bool, len(s))
	sa := strings.Split(string(s), "\n")
	for _, v := range sa {
		if v != "" {
			corretkerb[v] = true
		}
	}

	dr, err := ditreader.New("./ntds_reference/2016/system", "./ntds_reference/2016/ntds.dit")
	if err != nil {
		t.Fatal(err)
	}
	go dr.Dump()
	dataChan := dr.GetOutChan()
	for ok := range dataChan {
		//ensure it exists (don't find values that are not in impacket.. yet)
		if _, found := corretkerb[ok.HashString()]; !found {
			t.Errorf("found unexpected value: %s", ok.HashString())
		}
		//check history too
		for _, h := range ok.HistoryStrings() {
			if _, found := corretkerb[h]; !found {
				t.Errorf("found unexpected value: %s", h)
			}
			delete(corretkerb, h)
		}
		//ensure we don't miss any that impacket finds
		delete(corretkerb, ok.HashString())
	}
	if len(corretkerb) > 0 {
		t.Errorf("Expected empty map. Unfound hashes: %+v", corretkerb)
	}
}
