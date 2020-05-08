package winregistry

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

type LiveReg struct {
	BasePath string
}

func InitLive(s string) (WinRegIF, error) {
	return LiveReg{
		BasePath: s,
	}, nil
}

func (l LiveReg) GetVal(path string) (regtype uint32, val []byte, err error) {
	splits := strings.Split(path, `\`)
	key := splits[len(splits)-1]
	joinpath := strings.Join(splits[:len(splits)-1], `\`)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, l.BasePath+joinpath, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	buff := make([]byte, 1024)
	n, regtype, err := k.GetValue(key, buff)
	buff = buff[:n]
	return regtype, buff, err
}

func (l LiveReg) GetClass(path string) (r []byte) {
	//welp
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, l.BasePath+path, 0x19)
	if err != nil {
		panic("No")
	}
	defer k.Close()

	type KeyInfo struct {
		Class           *uint16
		Classlen        uint32
		SaLen           uint32
		MaxClassLen     uint32
		SubKeyCount     uint32
		MaxSubKeyLen    uint32 // size of the key's subkey with the longest name, in Unicode characters, not including the terminating zero byte
		ValueCount      uint32
		MaxValueNameLen uint32 // size of the key's longest value name, in Unicode characters, not including the terminating zero byte
		MaxValueLen     uint32 // longest data component among the key's values, in bytes
		lastWriteTime   syscall.Filetime
	}
	back := make([]uint16, 20)
	ki := KeyInfo{Class: &back[0], Classlen: 20}

	err = syscall.RegQueryInfoKey(syscall.Handle(k), ki.Class, &ki.Classlen, nil,
		&ki.SubKeyCount, &ki.MaxSubKeyLen, &ki.MaxClassLen, &ki.ValueCount,
		&ki.MaxValueNameLen, &ki.MaxValueLen, &ki.SaLen, &ki.lastWriteTime)

	if err != nil {
		panic(err)
	}
	return []byte(syscall.UTF16ToString(back))
}

func (l LiveReg) EnumKeys(path string) (subkeys []string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, l.BasePath+path+`\`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return subkeys, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(0)
}
