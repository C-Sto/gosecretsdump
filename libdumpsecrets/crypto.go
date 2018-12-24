package libdumpsecrets

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strconv"
)

func (g Gosecretsdump) removeDES(b []byte, rid string) []byte {
	ridI, err := strconv.Atoi(rid)
	if err != nil {
		panic(err)
	}
	k1, k2 := deriveKey(ridI)
	c1, err := des.NewCipher(k1)
	if err != nil {
		panic(err)
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		panic(err)
	}
	p1 := make([]byte, 8)
	p2 := make([]byte, 8)

	c1.Decrypt(p1, b[:8])
	c2.Decrypt(p2, b[8:])
	return append(p1, p2...)
}

func deriveKey(baseKey int) (k1, k2 []byte) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, uint32(baseKey))
	key1 := []byte{
		key[0], key[1], key[2], key[3],
		key[0], key[1], key[2],
	}
	key2 := []byte{
		key[3], key[0], key[1], key[2],
		key[3], key[0], key[1],
	}

	return transformKey(key1), transformKey(key2)
}

func transformKey(inKey []byte) []byte {
	outKey := []byte{}
	outKey = append(outKey, inKey[0]>>0x01)
	outKey = append(outKey, ((inKey[0]&0x01)<<6)|inKey[1]>>2)
	outKey = append(outKey, ((inKey[1]&0x03)<<5)|inKey[2]>>3)
	outKey = append(outKey, ((inKey[2]&0x07)<<4)|inKey[3]>>4)
	outKey = append(outKey, ((inKey[3]&0x0f)<<3)|inKey[4]>>5)
	outKey = append(outKey, ((inKey[4]&0x1f)<<2)|inKey[5]>>6)
	outKey = append(outKey, ((inKey[5]&0x3f)<<1)|inKey[6]>>7)
	outKey = append(outKey, inKey[6]&0x7f)
	for i := range outKey {
		outKey[i] = (outKey[i] << 1) & 0xfe
	}
	return outKey
}

func (g Gosecretsdump) removeRC4(c crypted_hash) []byte {
	tmpKeyh := md5.New()
	tmpKeyh.Write(g.pek[int(c.Header[4])])
	tmpKeyh.Write(c.KeyMaterial[:])
	tmpKey := tmpKeyh.Sum(nil)
	lol, err := rc4.NewCipher(tmpKey[:])
	if err != nil {
		panic(err)
	}
	plain := make([]byte, len(c.EncryptedHash))
	lol.XORKeyStream(plain, c.EncryptedHash[:])
	return plain
}

func (c crypted_hash) Init(inData []byte) crypted_hash {
	data := make([]byte, len(inData))
	copy(data, inData)
	r := crypted_hash{}
	copy(r.Header[:], data[:8])
	data = data[8:]
	copy(r.KeyMaterial[:], data[:16])
	data = data[16:]
	copy(r.EncryptedHash[:], data[:16])
	return r
}

type crypted_hash struct {
	Header        [8]byte
	KeyMaterial   [16]byte
	EncryptedHash [16]byte
}
