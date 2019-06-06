package ditreader

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/c-sto/gosecretsdump/pkg/systemreader"

	"github.com/c-sto/gosecretsdump/pkg/esent"
)

//New Creates a new dit dumper
func New(system, ntds string) DitReader {
	r := DitReader{
		isRemote:           false,
		history:            false,
		noLMHash:           true,
		remoteOps:          "",
		useVSSMethod:       false,
		justNTLM:           false,
		pwdLastSet:         false,
		resumeSession:      "",
		outputFileName:     "",
		justUser:           "",
		printUserStatus:    false,
		systemHiveLocation: system,
		ntdsFileLocation:   ntds,
		db:                 esent.Esedb{}.Init(ntds),
		userData:           make(chan DumpedHash, 100),
	}
	r.cursor = r.db.OpenTable("datatable")
	go r.dump() //start dumping the file immediately output will be put into the output channel as it comes

	return r
}

type DitReader struct {
	ntdsFile  *os.File
	bootKey   []byte
	isRemote  bool
	history   bool
	noLMHash  bool
	remoteOps string

	useVSSMethod       bool
	justNTLM           bool
	pwdLastSet         bool
	resumeSession      string
	outputFileName     string
	systemHiveLocation string
	ntdsFileLocation   string

	justUser        string
	printUserStatus bool

	perSecretCallback bool // nil
	secret            bool //nil

	resumeSessionMgr bool // nil

	db       esent.Esedb
	cursor   *esent.Cursor
	pek      [][]byte
	tmpUsers []esent.Esent_record

	//output chans
	userData chan DumpedHash

	//settings Settings
}

func (d *DitReader) dump() {

}

//GetOutChan returns a reference to the objects output channel for read only operations
func (d DitReader) GetOutChan() <-chan DumpedHash {
	return d.userData
}

func (d *DitReader) Dump() error {
	//if local (always local for now)
	if d.systemHiveLocation != "" {
		ls := systemreader.New(d.systemHiveLocation)
		d.bootKey = ls.BootKey()
		if d.ntdsFileLocation != "" {
			d.noLMHash = ls.HasNoLMHashPolicy()
		}
	} else {
		return fmt.Errorf("System hive empty")
	}

	//fmt.Println("Searching for pekList") //info
	d.getPek()
	//verify pek retreived good
	if len(d.pek) < 1 {
		panic("NO PEK FOUND THIS IS VERY BAD")
	}
	//fmt.Println("Reading and decrypting hashes from", g.ntdsFileLocation)

	for {
		//read each record from the db
		record, err := d.db.GetNextRow(d.cursor)
		if err != nil {
			break //we will get an 'ignore' error when there are no more records
		}

		//check for the right kind of record
		if _, ok := accTypes[record.Column[nToInternal["sAMAccountType"]].Long]; ok {

			//attempt to decrypt the record
			dh, err := d.DecryptRecord(record)
			if err != nil {
				fmt.Println("Coudln't decrypt record:", err.Error())
				continue
			}
			g.handleHash(dh)
			ds, err := g.decryptSupp(record)
			if err != nil {
				fmt.Println("Coudln't decrypt record:", err.Error())
				continue
			}
			g.handleSupp(dh, ds)
		}
	}
}

func (d DitReader) PEK() [][]byte {
	if len(d.pek) < 1 {
		return d.getPek()
	}
	return d.pek
}

func (d *DitReader) getPek() [][]byte {
	pekList := []byte{}
	for {
		record, err := d.db.GetNextRow(d.cursor)
		if err != nil && err.Error() != "ignore" {
			panic(err) //todo: remove all panics and handle errors properly
		}
		if err != nil && err.Error() == "ignore" {
			break //lol fml
		}
		if v, ok := record.Column[nToInternal["pekList"]]; ok && len(v.BytVal) > 0 {
			pekList = v.BytVal
			break
		}
		if _, ok := record.Column[nToInternal["sAMAccountType"]]; ok {
			//users found?
			d.tmpUsers = append(d.tmpUsers, record)
		}
	}
	if len(pekList) > 0 { //not an empty pekkyboi

		encryptedPekList, err := NewPeklistEnc(pekList)
		if err != nil {
			//should probably hard fail here
			panic(err)
		}
		if bytes.Compare(encryptedPekList.Header[:4], []byte{2, 0, 0, 0}) == 0 {
			//up to windows 2012 r2 something something
			md := md5.New()
			md.Write(d.bootKey)
			for i := 0; i < 1000; i++ {
				md.Write(encryptedPekList.KeyMaterial[:])
			}
			tmpKey := md.Sum([]byte{})
			rc, err := rc4.NewCipher(tmpKey)
			if err != nil {
				panic(err)
			}
			dst := make([]byte, len(encryptedPekList.EncryptedPek))
			rc.XORKeyStream(dst, encryptedPekList.EncryptedPek)
			decryptedPekList := NewPeklistPlain(dst)
			pekLen := 20 //len of the pek_key structure
			for i := 0; i < len(decryptedPekList.DecryptedPek)/pekLen; i++ {
				cursor := i * pekLen
				pek := NewPekKey(decryptedPekList.DecryptedPek[cursor : cursor+pekLen])
				fmt.Println("PEK found and decrypted:", hex.EncodeToString(pek.Key[:]))
				d.pek = append(d.pek, pek.Key[:])
			}

		} else if bytes.Compare(encryptedPekList.Header[:4], []byte("\x03\x00\x00\x00")) == 0 {
			//something something 2016 TP4
			/*
				# Windows 2016 TP4 header starts this way
				# Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
				# using AES:
				# Key: the bootKey
				# CipherText: PEKLIST_ENC['EncryptedPek']
				# IV: PEKLIST_ENC['KeyMaterial']
			*/
			ePek := decryptAES(d.bootKey, encryptedPekList.EncryptedPek, encryptedPekList.KeyMaterial[:])
			decryptedPekList := NewPeklistPlain(ePek)
			d.pek = append(d.pek, decryptedPekList.DecryptedPek[4:20])
		}
	}
	return d.pek
}
