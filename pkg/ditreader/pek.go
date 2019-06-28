package ditreader

import "fmt"

type PeklistEnc struct {
	Header       [8]byte
	KeyMaterial  [16]byte
	EncryptedPek []byte // ":"
}

//NewPeklistEnc returns an encrypted peklist object from the passed in record
func NewPeklistEnc(lData []byte) (PeklistEnc, error) {
	if len(lData) < 16 {
		return PeklistEnc{}, fmt.Errorf("Invalid data size. Expecting 16, got %d", len(lData))
	}
	r := PeklistEnc{}
	//lData := make([]byte, len(data)) //avoid mutation
	//copy(lData, data)
	copy(r.Header[:], lData[:8])
	lData = lData[8:]
	copy(r.KeyMaterial[:], lData[:16])
	lData = lData[16:]
	r.EncryptedPek = make([]byte, len(lData))
	copy(r.EncryptedPek, lData)
	return r, nil
}

type PeklistPlain struct {
	Header       [32]byte
	DecryptedPek []byte // ":"
}

//NewPeklistPlain returns a cleartext peklist object from the passed in record
func NewPeklistPlain(lData []byte) PeklistPlain {
	r := PeklistPlain{}
	//lData := make([]byte, len(data))
	//copy(lData, data)
	copy(r.Header[:], lData[:32])
	lData = lData[32:]
	r.DecryptedPek = make([]byte, len(lData))
	copy(r.DecryptedPek, lData)
	return r
}

type PekKey struct {
	Header  [1]byte
	Padding [3]byte
	Key     [16]byte
}

//NewPekKey returns a Pek key (the key portion of the PekKey structure)
func NewPekKey(lData []byte) []byte {
	//copy(r.Key[:], lData[4:20])
	return lData[4:20]
}
