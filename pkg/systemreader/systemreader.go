package systemreader

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/C-Sto/gosecretsdump/pkg/winregistry"
	"golang.org/x/text/encoding/unicode"
)

//SystemReader provides an interface to get goodies from a SYSTEM file.
type SystemReader struct {
	systemLoc string
	bootKey   []byte
	registry  winregistry.WinRegIF
}

//New creates a new SystemReader pointing at the specified file.
func New(s string) (SystemReader, error) {
	var err error
	r := SystemReader{systemLoc: s}
	r.registry, err = winregistry.InitOffline(s)
	return r, err
}

func NewLive() (SystemReader, error) {
	r := SystemReader{}
	var err error
	r.registry, err = winregistry.InitLive("SYSTEM")
	if err != nil {
		return r, err
	}
	return r, err
}

//BootKey returns the bootkey extracted from the SYSTEM file
func (l *SystemReader) BootKey() []byte {
	b, e := l.getBootKey()
	if e != nil {
		panic(e)
	}
	if len(b) == 0 {
		panic("NO BOOTKEY?")
	}
	return b
}

func (l *SystemReader) getBootKey() (bk []byte, err error) {
	tmpKey := ""
	//get control set
	_, bcurrentControlset, err := l.registry.GetVal("\\Select\\Current")
	if err != nil {
		return nil, err
	}
	currentControlset := fmt.Sprintf("ControlSet%03d", binary.LittleEndian.Uint32(bcurrentControlset))
	for _, k := range []string{"JD", "Skew1", "GBG", "Data"} {
		ans, e := l.registry.GetClass(fmt.Sprintf("\\%s\\Control\\Lsa\\%s", currentControlset, k))
		if e != nil {
			return []byte{}, e
		}
		tmpKey = tmpKey + string(ans)
	}
	if len(tmpKey) > 32 {
		ud := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		tmpKey, _ = ud.String(tmpKey)
	}
	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	unhexedKey, err := hex.DecodeString(tmpKey)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(unhexedKey); i++ {
		bk = append(bk, unhexedKey[transforms[i]])
	}
	l.bootKey = bk
	return bk, nil
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
