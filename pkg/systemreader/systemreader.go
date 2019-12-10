package systemreader

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/c-sto/gosecretsdump/pkg/winregistry"
	"golang.org/x/text/encoding/unicode"
)

//SystemReader provides an interface to get goodies from a SYSTEM file.
type SystemReader struct {
	systemLoc string
	bootKey   []byte
	registry  winregistry.WinregRegistry
}

//New creates a new SystemReader pointing at the specified file.
func New(s string) (SystemReader, error) {
	var err error
	r := SystemReader{systemLoc: s}
	r.registry, err = winregistry.WinregRegistry{}.Init(s, false)
	return r, err
}

//BootKey returns the bootkey extracted from the SYSTEM file
func (l SystemReader) BootKey() []byte {
	if len(l.bootKey) < 1 {
		l.getBootKey()
	}
	return l.bootKey
}

func (l *SystemReader) getBootKey() error {
	bk := []byte{}
	tmpKey := ""
	//winreg := winregistry.WinregRegistry{}.Init(l.systemLoc, false)
	//get control set
	_, bcurrentControlset, err := l.registry.GetVal("\\Select\\Current")
	if err != nil {
		return err
	}

	currentControlset := fmt.Sprintf("ControlSet%03d", binary.LittleEndian.Uint32(bcurrentControlset))
	for _, k := range []string{"JD", "Skew1", "GBG", "Data"} {
		ans := l.registry.GetClass(fmt.Sprintf("\\%s\\Control\\Lsa\\%s", currentControlset, k))
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		nansLen := 16
		if len(ans) < 16 {
			nansLen = len(ans)
		}
		digit := make([]byte, len(ans[:nansLen])/2)
		ud.Transform(digit, ans[:16], false)
		tmpKey = tmpKey + strings.Replace(string(digit), "\x00", "", -1)
	}
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	unhexedKey, err := hex.DecodeString(tmpKey)
	if err != nil {
		return err
	}
	for i := 0; i < len(unhexedKey); i++ {
		bk = append(bk, unhexedKey[transforms[i]])
	}
	//fmt.Println("Target system bootkey: ", "0x"+hex.EncodeToString(bk))
	l.bootKey = bk
	return nil
}

//HasNoLMHashPolicy returns true if no LM hashes are allowed per the SYSTEM file. A False response indicates that LM hashes may exist within the domain/machine.
func (l SystemReader) HasNoLMHashPolicy() bool {
	//winreg := winregistry.WinregRegistry{}.Init(l.systemLoc, false)
	_, bcurrentControlSet, err := l.registry.GetVal("\\Select\\Current")
	if err != nil {
		fmt.Println("ERROR GETTING CONTROL SET FOR LM HASH", err)
	}
	currentControlSet := fmt.Sprintf("ControlSet%03d", binary.LittleEndian.Uint32(bcurrentControlSet))
	_, _, err = l.registry.GetVal(fmt.Sprintf("\\%s\\Control\\Lsa\\NoLmHash", currentControlSet))
	if err != nil && err.Error() == winregistry.NONE {
		//yee got some LM HASHES life is gonna be GOOD
		return false
	}
	return true
}
