package winregistry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const NONE = "NoneReturn"

type winregF struct {
	Magic             [4]byte //','"regf'),
	Unknown           uint32
	Unknown2          uint32
	LastChange        uint64
	MajorVersion      uint32
	MinorVersion      uint32
	Z0                uint32
	Z11               uint32
	OffsetFirstRecord uint32
	DataSize          uint32
	Z1111             uint32
	Name              [48]byte   //','48s=""'),
	Remaining1        [411]byte  //','411s=""'),
	CheckSum          uint32     //','<L=0xffffffff'), # Sum of all DWORDs from 0x0 to 0x1FB
	Remaining2        [3585]byte //','3585s=""'),
}

const ROOT_KEY = 0x2c
const REG_NONE = 0x00
const REG_SZ = 0x01
const REG_EXPAND_SZ = 0x02
const REG_BINARY = 0x03
const REG_DWORD = 0x04
const REG_MULTISZ = 0x07
const REG_QWORD = 0x0b

func (w winregF) Init(ind []byte) (winregF, error) {
	r := winregF{}
	d := make([]byte, len(ind))
	copy(d, ind)
	buffer := bytes.NewBuffer(d)
	err := binary.Read(buffer, binary.LittleEndian, &r)
	if err != nil {
		return r, err
	}

	//do integrity stuff I guess?
	if bytes.Compare(r.Magic[:], []byte("regf")) != 0 {
		return r, fmt.Errorf("magic header on registry key failure")
	}
	return r, nil
}

type fileInMem struct {
	data []byte
}

type WinregRegistry struct {
	//fd        *os.File
	fd      fileInMem
	regF    winregF
	ident   string
	rootKey reg_blockStruct
}

type regdatablock struct {
}

type regHbinBlock struct {
	DataBlockSize int32
	//_Data ???
	Data []byte
}

func (r regHbinBlock) Init(inData []byte) regHbinBlock {
	rv := regHbinBlock{}
	rv.DataBlockSize = int32(binary.LittleEndian.Uint32(inData[:4]))
	x := rv.DataBlockSize
	if rv.DataBlockSize < 0 {
		//make it positive again
		x *= -1
	}

	rv.Data = inData[4:]
	return rv
}

type regHbin struct {
	Magic           [4]byte //','"hbin'),
	OffsetFirstHBin uint32
	OffsetNextHBin  uint32
	BlockSize       uint32
}

func (r regHbin) Init(inData []byte) (regHbin, error) {

	data := make([]byte, len(inData))
	copy(data, inData)

	hbin := regHbin{}
	buffer := bytes.NewBuffer(data[:0x20])
	err := binary.Read(buffer, binary.LittleEndian, &hbin)
	if err != nil {
		return hbin, err
	}

	if bytes.Compare(hbin.Magic[:], []byte("hbin")) != 0 {
		return hbin, errors.New("Bad Magic")
	}
	return hbin, nil
}

func (w WinregRegistry) findRootKey() (reg_blockStruct, error) {
	fp := 0
	for fp < w.fd.Len() {
		data := w.fd.Read(fp, 4096) // w.fileInMem[fp : fp+4096]

		fp += 4096
		hbin, err := regHbin{}.Init(data[:0x20])
		if err != nil {
			continue
		}
		//something about reading remaining bytes?
		//When size is omitted or negative, the entire contents of the file will be read and returned
		//fucking python
		newData := w.fd.Read(0, w.fd.Len())
		if hbin.OffsetNextHBin-4096 > 0 {
			newData = w.fd.Read(fp, int(hbin.OffsetNextHBin-4096)) // w.fileInMem[fp : fp+int(hbin.OffsetNextHBin-4096)]
		}
		fp += int(hbin.OffsetNextHBin - 4096)
		data = append(data, newData...)
		data = data[0x20:]
		//modification from impacket version. all this does is work out which one is the root key
		for len(data) > 0 {
			block := regHbinBlock{}.Init(data[:])
			if string(block.Data[:2]) == "nk" { //don't care if it's not the nk block
				//cat to block
				nkBlock, _ := reg_blockStruct{}.Init(block.Data)
				//if it's not the root, don't care
				if nkBlock.Type == ROOT_KEY {
					//if it is, return!
					return nkBlock, nil
				}

			}
			data = data[4+len(block.Data):]
		}
	}
	return reg_blockStruct{}, errors.New("Couldn't Find Root NK")
}

type WinRegLive struct {
	BaseKey string
}

func InitOffline(s string) (WinRegIF, error) {
	f, err := os.Open(s)
	if err != nil {
		return WinregRegistry{}, err
	}
	r := WinregRegistry{}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return r, err
	}
	f.Close()
	r.fd = fileInMem{data}
	r.regF, err = winregF{}.Init(r.fd.Read(0, 4096)) // data[:4096])
	if err != nil {
		return r, err
	}
	r.ident = ""
	r.rootKey, err = r.findRootKey()

	if err != nil {
		return r, fmt.Errorf("Could not find root key: %s", err.Error())
	} else if r.regF.MajorVersion != 1 && r.regF.MinorVersion > 5 {
		return r, fmt.Errorf("Unsupported version, unexpected value. Wanted major 1 and minor over 5 got major %d minor %x", r.regF.MajorVersion, r.regF.MinorVersion)
	}
	return r, nil
}

func (f fileInMem) Read(start, count int) []byte {
	r := make([]byte, count)
	copy(r, f.data[start:start+count])
	return r
}

func (f fileInMem) Len() int {
	return len(f.data)
}

type RegVal struct {
	ValType string
	ValData []byte
}

func (w WinregRegistry) getBlock(t uint32) (val reg_blockStruct, err error) {
	var block reg_hbinblock
	sizeBytes := w.fd.Read(int(t+4096), 4) // w.fileInMem[4096 : 4096+4]

	size := int32(binary.LittleEndian.Uint32(sizeBytes))*-1 - 4
	data := append(sizeBytes, w.fd.Read(int(t+4096+4), int(size))...)
	if len(data) == 0 {
		return reg_blockStruct{}, errors.New("No Data")
	}

	block = reg_hbinblock{}.Init(data)
	ret, err := reg_blockStruct{}.Init(block.Data)

	if err == nil {
		return ret, nil
	}

	return reg_blockStruct{}, errors.New("Couldn't find blocktype")
}

type reg_blockStruct struct {
	Magic           [2]byte // "nk'),
	Type            uint16
	lastChange      uint64
	Unknown         uint32
	OffsetParent    uint32
	NumSubKeys      uint32
	Unknown2        uint32
	OffsetSubKeyLf  uint32
	Unknown3        uint32
	NumValues       uint32
	OffsetValueList uint32
	OffsetSkRecord  uint32
	OffsetClassName uint32
	UnUsed          [20]byte // 20s=""'),
	NameLength      uint16
	ClassNameLength uint16
	//_KeyName _-KeyName self["NameLength"]'),
	KeyName []byte //:'), //ffs

	//lh
	NumKeys     uint16
	HashRecords []byte

	//vk
	//Magic "vk'),
	//	NameLength uint16
	DataLen    int32
	OffsetData uint32
	ValueType  uint32
	Flag       uint16
	UnUsedVK   uint16
	//_Name _-Name self["NameLength"]'),
	Name []byte //Name :'),

	//others
	Data []byte
}

type reg_hbinblock struct {
	DataBlockSize int32
	Data          []byte
}

func (b reg_blockStruct) Init(data []byte) (reg_blockStruct, error) {

	ret := reg_blockStruct{}

	copy(ret.Magic[:], data[:2]) //ret.Magic = data[:2]
	data = data[2:]
	switch string(ret.Magic[:]) {
	case "nk":
		ret.Type = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.lastChange = binary.LittleEndian.Uint64(data[:8])
		data = data[8:]
		ret.Unknown = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.OffsetParent = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.NumSubKeys = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.Unknown2 = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.OffsetSubKeyLf = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.Unknown3 = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.NumValues = binary.LittleEndian.Uint32(data[:4])

		data = data[4:]
		ret.OffsetValueList = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.OffsetSkRecord = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.OffsetClassName = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		copy(ret.UnUsed[:], data[:20]) //ret.UnUsed = data[:20]
		data = data[20:]
		ret.NameLength = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.ClassNameLength = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.KeyName = data[:ret.NameLength]

	case "lf":
		fallthrough
	case "lh":
		ret.NumKeys = binary.LittleEndian.Uint16(data[:2])
		ret.HashRecords = data[2:]

	case "vk":
		ret.NameLength = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.DataLen = int32(binary.LittleEndian.Uint32(data[:4]))
		data = data[4:]
		ret.OffsetData = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.ValueType = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
		ret.Flag = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.UnUsedVK = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		ret.Name = make([]byte, len(data)) //avoiding mutating state by accidental?
		copy(ret.Name, data[:])

	default:
		ret.Data = append(ret.Magic[:], data...)
		return ret, nil
	}
	return ret, nil
}

func (b reg_hbinblock) Init(ind []byte) reg_hbinblock {
	//zzzz
	d := make([]byte, len(ind))
	copy(d, ind)
	r := reg_hbinblock{}
	r.DataBlockSize = int32(binary.LittleEndian.Uint32(d[:4]))
	r.Data = d[4:]
	return r
}

func (w WinregRegistry) compareHash(magic [2]byte, hashData []byte, key string) (uint32, error) {
	if string(magic[:]) == "ri" {
		//offset := binary.LittleEndian.Uint32(hashData[:4])
		//nk, _ := w.getBlock(offset)
		return 0, fmt.Errorf("Not implemented: registry RI")
	}

	hashRec := reg_hash{}
	buffer := bytes.NewBuffer(hashData)
	err := binary.Read(buffer, binary.LittleEndian, &hashRec)
	if err != nil {
		return 0, err
	}
	switch string(magic[:]) {
	case "lf":
		for len(key) < 4 {
			key = key + "\x00"
		}
		if string(hashRec.KeyName[:4]) == key[:4] { //strip \x00?
			return hashRec.OffsetNk, nil
		}
	case "lh": //ZZZZZ GETLHHASH IS WRONG?
		if binary.LittleEndian.Uint32(hashRec.KeyName[:]) == w.getLhHash(key) {
			return hashRec.OffsetNk, nil
		}
	}

	return 0, errors.New("Not Found")
}

func (w WinregRegistry) getLhHash(key string) uint32 {
	res := 0
	for i := 0; i < len(key); i++ {
		b := strings.ToUpper(key)[i]
		res *= 37
		res += int(b)
	}

	return uint32(res % 0x100000000)
}

type reg_hash struct {
	OffsetNk uint32
	KeyName  [4]byte
}

func (w WinregRegistry) enumKey(parent reg_blockStruct) (r []string, err error) {
	if parent.NumSubKeys < 1 {
		return
	}

	lf, err := w.getBlock(parent.OffsetSubKeyLf)
	data := lf.HashRecords

	if bytes.Compare(lf.Magic[:], []byte("ri")) == 0 {
		return r, fmt.Errorf("Not yet implemented: RI registry")
	}
	for i := uint32(0); i < parent.NumSubKeys; i++ {
		hashRec := reg_hash{}
		err := binary.Read(bytes.NewBuffer(data[:8]), binary.LittleEndian, &hashRec)
		if err != nil {
			panic(err)
		}
		nk, err := w.getBlock(hashRec.OffsetNk)
		if err != nil {
			return r, err
		}
		r = append(r, string(nk.KeyName))
		data = data[8:]
	}
	return
}

func (w WinregRegistry) EnumKeys(s string) (r []string, err error) {
	f, err := w.findKey(s)
	if err != nil {
		return r, err
	}
	return w.enumKey(f)
}

func (w WinregRegistry) findSubKey(parKey reg_blockStruct, subkey string) (reg_blockStruct, error) {
	lf, err := w.getBlock(parKey.OffsetSubKeyLf)

	if err != nil {
		return reg_blockStruct{}, err
	}
	data := make([]byte, len(lf.HashRecords))
	copy(data, lf.HashRecords)
	if string(lf.Magic[:]) == "ri" {
		return reg_blockStruct{}, fmt.Errorf("Not implemented: registry RI subkey")
	}
	for record := uint32(0); record < parKey.NumSubKeys; record++ {
		hashrec := make([]byte, 8)
		copy(hashrec, data[:8])
		res, err := w.compareHash(lf.Magic, hashrec, subkey)
		if res != 0 && err == nil {
			nk, _ := w.getBlock(res)
			if strings.Replace(string(nk.KeyName), "\x00", "", -1) == subkey {
				//if string(nk.KeyName) == subkey {
				return nk, nil
			}
		}
		data = data[8:]
	}
	return reg_blockStruct{}, errors.New(NONE) //lf, nil
}

func (w WinregRegistry) findKey(s string) (reg_blockStruct, error) {
	if len(s) > 1 && string(s[0]) == "\\" {
		s = s[1:]
	}
	parentKey := w.rootKey
	if len(s) > 0 && string(s[0]) != "\\" {
		for _, subKey := range strings.Split(s, "\\") {
			res, err := w.findSubKey(parentKey, subKey)
			if err != nil {
				return reg_blockStruct{}, err
			}
			parentKey = res

		}
	}
	return parentKey, nil
}

//should return key/value in the form /key/goes/here value
//(no trailing slash on key, no starting/trailing slash on val)
func getKVFromPath(s string) (string, string) {
	lastSlash := strings.LastIndex(s, "\\")
	return s[:lastSlash], s[lastSlash+1:]
}

func (w WinregRegistry) getValBlocks(offset, count uint32) []reg_blockStruct {
	valList := []int32{}
	res := []reg_blockStruct{}

	ptr := int(4096 + offset)

	for i := uint32(0); i < count; i++ {
		valList = append(valList, int32(binary.LittleEndian.Uint32(w.fd.Read(ptr, 4))))
		ptr = ptr + 4
	}

	for _, valOff := range valList {
		if valOff > 0 {
			block, err := w.getBlock(uint32(valOff))
			if err != nil {
				fmt.Println("UNDEFINED BEHAVIOUR???? PLS CHECK GETVALBLOCKS OK", valOff, err.Error())
				continue
			}
			res = append(res, block)
		}
	}
	return res
}

func (w WinregRegistry) GetVal(s string) (uint32, []byte, error) {
	regKey, regValue := getKVFromPath(s)

	key, err := w.findKey(regKey)

	if err != nil || key.NumValues < 1 {

		return 0, nil, errors.New(NONE)
	}

	//we are here in py version
	//        if key['NumValues'] > 0:

	valueList := w.getValBlocks(key.OffsetValueList, key.NumValues+1)
	for _, val := range valueList {
		name := string(val.Name[:val.NameLength])
		if name == regValue {
			return val.ValueType, w.getValData(val), nil
		} else if regValue == "default" && val.Flag <= 0 {
			return val.ValueType, w.getValData(val), nil
		}
	}
	return 0, nil, errors.New(NONE)
}

func (w WinregRegistry) getValData(val reg_blockStruct) []byte {
	//something about a VK record?
	if val.DataLen == 0 {
		return []byte{}
	}
	if val.DataLen < 5 { //possibly a bug, the comment says 'below 5', but the code is below 0
		d := make([]byte, 4)
		binary.LittleEndian.PutUint32(d, val.OffsetData)
		return d
	}
	return w.getData(int32(val.OffsetData), val.DataLen+4)
}

func (w WinregRegistry) getData(offset, len int32) []byte {
	d := w.fd.Read(int(4096+offset), int(len))
	return d[4:] //not entirely sure why dropping the first 4 bytes, but ok
}

func (w WinregRegistry) GetClass(s string) ([]byte, error) {
	key, err := w.findKey(s)
	if err != nil {
		return []byte{}, err
	}
	if key.OffsetClassName > 0 {
		val, _ := w.getBlock(key.OffsetClassName)
		return val.Data[:key.ClassNameLength], nil
	}
	return []byte{}, fmt.Errorf("Class name not found?")
}
