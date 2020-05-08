package winregistry

type WinRegIF interface {
	GetVal(path string) (regtype uint32, val []byte, err error)
	GetClass(path string) (b []byte, err error)
	EnumKeys(path string) (subkeys []string, err error)
}
