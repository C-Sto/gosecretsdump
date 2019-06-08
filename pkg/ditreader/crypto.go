package ditreader

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strconv"
)

func removeDES(b []byte, rid string) []byte {
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

func (d DitReader) removeRC4(c CryptedHash) []byte {
	tmpKeyh := md5.New()
	tmpKeyh.Write(d.pek[int(c.Header[4])])
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

//NewCryptedHash creates a CryptedHash object containing key material and encrypted content.
func NewCryptedHash(inData []byte) CryptedHash {
	data := make([]byte, len(inData))
	copy(data, inData)
	r := CryptedHash{}
	copy(r.Header[:], data[:8])
	data = data[8:]
	copy(r.KeyMaterial[:], data[:16])
	data = data[16:]
	r.EncryptedHash = make([]byte, len(data))
	copy(r.EncryptedHash[:], data[:])
	return r
}

type CryptedHash struct {
	Header        [8]byte
	KeyMaterial   [16]byte
	EncryptedHash []byte
}

func decryptAES(key, value, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	thing := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(value))
	thing.CryptBlocks(dst, value)
	return dst
}

type CryptedHashW16 struct {
	Header       [8]byte
	KeyMaterial  [16]byte
	Unknown      uint32
	EncrypedHash [32]byte
}

func NewCryptedHashW16(inData []byte) CryptedHashW16 {
	r := CryptedHashW16{}
	data := make([]byte, len(inData))
	copy(data, inData)
	copy(r.Header[:], data[:8])
	data = data[8:]
	copy(r.KeyMaterial[:], data[:16])
	data = data[16:]

	r.Unknown = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]

	copy(r.EncrypedHash[:], data[:32])

	return r
}
