package ditreader

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"github.com/C-Sto/gosecretsdump/pkg/systemreader"
	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/go-ese/parser"
)

func New(system, ntds string) (DitReader, error) {
	r := DitReader{
		pekLock:            new(sync.RWMutex),
		objectChan:         make(chan InterestingObject, 1000),
		systemHiveLocation: system,
		ntdsFileLocation:   ntds,
		//db:                 esent.Esedb{}.Init(ntds),
		userData: make(chan DumpedHash, 500),
	}

	//lock the peklock until we actually have a pek
	r.pekLock.Lock()

	fp, _ := os.Open(ntds)
	x, _ := parser.NewESEContext(fp)

	r.catalog, _ = parser.ReadCatalog(x)
	return r, nil
}

//GetOutChan returns a reference to the objects output channel for read only operations
func (d DitReader) GetOutChan() <-chan DumpedHash {
	return d.userData
}

func (d *DitReader) dumpCallback(row *ordereddict.Dict) (err error) {
	if d.pek == nil {
		p, err := GetPek(row, d.bootKey)
		if err != nil {
			return err
		}
		if p != nil {
			d.pek = p
			d.pekLock.Unlock() //should now allow decryption routine to progress
		}
	}

	dh, err := GetObject(row)
	if err != nil {
		return err
	}
	if dh.Rid != 0 {
		d.objectChan <- dh
	}

	return
}

func (d *DitReader) Decryptroutine() {
	for interesting := range d.objectChan {
		d.pekLock.RLock()
		d.userData <- interesting.Decrypt(d.pek)
		d.pekLock.RUnlock()
	}
	close(d.userData)
}

func (d DitReader) Dump() error {
	//if local (always local for now)
	if d.systemHiveLocation != "" {
		ls, err := systemreader.New(d.systemHiveLocation)
		if err != nil {
			return err
		}
		d.bootKey = ls.BootKey()
		if d.ntdsFileLocation != "" {
			d.noLMHash = ls.HasNoLMHashPolicy()
		}
	} else {
		return fmt.Errorf("System hive empty")
	}

	go d.Decryptroutine()
	err := d.catalog.DumpTable("datatable", d.dumpCallback)
	close(d.objectChan)
	return err

}

type DitReader struct {
	systemHiveLocation string
	ntdsFileLocation   string
	userData           chan DumpedHash

	noLMHash bool

	bootKey      []byte
	pekLock      *sync.RWMutex
	pek          [][]byte
	objectChan   chan InterestingObject
	objectbuffer []InterestingObject

	catalog *parser.Catalog
}

func GetPek(row *ordereddict.Dict, bootkey []byte) (pek [][]byte, err error) {
	bb, ok := row.Get(npekList)
	if !ok {
		return nil, nil
	}
	b, _ := hex.DecodeString((bb).(string))
	return getPek(b, bootkey)
}

func getPek(pekList, bootKey []byte) (pek [][]byte, err error) {
	encryptedPekList, err := NewPeklistEnc(pekList)
	if err != nil {
		//should probably hard fail here
		return
	}
	if bytes.Compare(encryptedPekList.Header[:4], []byte{2, 0, 0, 0}) == 0 {
		//up to windows 2012 r2 something something
		md := md5.New()
		md.Write(bootKey)
		for i := 0; i < 1000; i++ {
			md.Write(encryptedPekList.KeyMaterial[:])
		}
		tmpKey := md.Sum([]byte{})
		rc, err := rc4.NewCipher(tmpKey)
		if err != nil {
			return nil, err
		}
		dst := make([]byte, len(encryptedPekList.EncryptedPek))
		rc.XORKeyStream(dst, encryptedPekList.EncryptedPek)
		decryptedPekList := NewPeklistPlain(dst)
		pekLen := 20 //len of the pek_key structure
		for i := 0; i < len(decryptedPekList.DecryptedPek)/pekLen; i++ {
			cursor := i * pekLen
			//fmt.Println("PEK found and decrypted:", hex.EncodeToString(pek.Key[:]))
			pek = append(pek, NewPekKey(decryptedPekList.DecryptedPek[cursor:cursor+pekLen]))
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
		ePek, err := DecryptAES(bootKey, encryptedPekList.EncryptedPek, encryptedPekList.KeyMaterial[:])
		if err != nil {
			return nil, err
		}
		decryptedPekList := NewPeklistPlain(ePek)
		pek = append(pek, decryptedPekList.DecryptedPek[4:20])
	}

	return
}
