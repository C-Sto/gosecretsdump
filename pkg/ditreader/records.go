package ditreader

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Velocidex/ordereddict"
	"golang.org/x/text/encoding/unicode"
)

type InterestingObject struct {
	Sid SAMRRPCSID
	Rid uint32

	LMCrypted        []byte
	LMHistoryCrypted []byte
	NTCrypted        []byte
	NTHistoryCrypted []byte
	SuppCrypt        []byte

	SAMName string
	UPN     string

	UAC uacFlags
}

func GetObject(row *ordereddict.Dict) (ret InterestingObject, err error) {
	ss, ok := row.Get(nobjectSid)
	if !ok {
		return
	}
	v, _ := hex.DecodeString((ss).(string))

	ret.Sid, err = NewSAMRRPCSID(v)
	if !ok {
		return
	}
	ret.Rid = ret.Sid.Rid()

	//LM Hash
	ss, ok = row.Get(ndBCSPwd)
	if ok {
		ret.LMCrypted, _ = hex.DecodeString((ss).(string))
	}

	//NT Hash
	ss, ok = row.Get(nunicodePwd)
	if ok {
		ret.NTCrypted, _ = hex.DecodeString((ss).(string))
	}

	//Account name
	ss, ok = row.Get(nsAMAccountName)
	if ok {
		ret.SAMName = (ss).(string)
	}

	//username
	ss, ok = row.Get(nuserPrincipalName)
	if ok {
		ret.UPN = (ss).(string)
	}

	//Password history LM
	ss, ok = row.Get(nlmPwdHistory)
	if ok {
		ret.LMHistoryCrypted, _ = hex.DecodeString((ss).(string))
	}

	//password history NT
	ss, ok = row.Get(nntPwdHistory)
	if ok {
		ret.NTHistoryCrypted, _ = hex.DecodeString((ss).(string))
	}

	//check if account is enabled
	ss, ok = row.Get(nuserAccountControl)
	if ok {
		ret.UAC = decodeUAC((ss).(int))
	}

	//supp creds
	ss, ok = row.Get(nsupplementalCredentials)
	if ok {
		ret.SuppCrypt, _ = hex.DecodeString((ss).(string))
	}

	return
}

func LMDecrypt(b []byte, pek [][]byte, rid uint32) []byte {
	var tmpLM []byte
	encryptedLM, err := NewCryptedHash(b)
	if err != nil {
		return nil
	}
	if bytes.Equal(encryptedLM.Header[:4], []byte("\x13\x00\x00\x00")) {
		encryptedLMW := NewCryptedHashW16(b)
		pekIndex := encryptedLMW.Header
		tmpLM, err = DecryptAES(pek[pekIndex[4]], encryptedLMW.EncryptedHash[:16], encryptedLMW.KeyMaterial[:])
		if err != nil {
			return nil
		}
	} else {
		tmpLM, err = removeRC4(encryptedLM, pek)
		if err != nil {
			return nil
		}
	}
	LMHash, err := RemoveDES(tmpLM, rid)
	if err != nil {
		return nil
	}
	return LMHash
}

func (d InterestingObject) Decrypt(pek [][]byte) DumpedHash {
	dh := DumpedHash{}
	dh.Rid = d.Rid
	dh.Username = d.SAMName
	dh.UAC = d.UAC
	//var err error

	if len(d.LMCrypted) > 0 {
		dh.LMHash = LMDecrypt(d.LMCrypted, pek, d.Rid)
	}

	if len(d.NTCrypted) > 0 {
		dh.NTHash, _ = NTDecrypt(d.NTCrypted, pek, d.Rid)
	}

	if len(d.LMHistoryCrypted) > 0 {
		dh.History.LmHist, _ = LMHistoryDecrypt(d.LMHistoryCrypted, pek, d.Rid)
	}

	if len(d.NTHistoryCrypted) > 0 {
		dh.History.NTHist, _ = NTHistoryDecrypt(d.NTHistoryCrypted, pek, d.Rid)
	}

	if len(d.SuppCrypt) > 0 {
		dh.Supp, _ = SupplementalDecrypt(d.SuppCrypt, dh.Username, pek)
	}

	return dh
}

func LMHistoryDecrypt(v []byte, pek [][]byte, rid uint32) ([][]byte, error) {
	ret := [][]byte{}
	ch, err := NewCryptedHash(v)
	if err != nil {
		return nil, err
	}
	var tmphst []byte
	tmphst, err = removeRC4(ch, pek)
	if err != nil {
		return nil, err
	}

	for i := 16; i < len(tmphst); i += 16 {
		hst1 := tmphst[i : i+16]
		hst2, err := RemoveDES(hst1, rid)
		ret = append(ret, hst2)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func NTHistoryDecrypt(v []byte, pek [][]byte, rid uint32) ([][]byte, error) {
	ret := [][]byte{}
	ch, err := NewCryptedHash(v)
	if err != nil {
		return nil, err
	}
	var tmphst []byte
	if bytes.Equal(ch.Header[:4], []byte("\x13\x00\x00\x00")) {
		encryptedNTW := NewCryptedHashW16History(v)
		pekIndex := encryptedNTW.Header
		tmphst, err = DecryptAES(pek[pekIndex[4]], encryptedNTW.EncryptedHash[:], encryptedNTW.KeyMaterial[:])
		if err != nil {
			return nil, err
		}
	} else {
		tmphst, err = removeRC4(ch, pek)
		if err != nil {
			return nil, err
		}
	}
	for i := 16; i < len(tmphst); i += 16 {
		hst1 := tmphst[i : i+16]
		hst2, err := RemoveDES(hst1, rid)
		if err != nil {
			return nil, err
		}
		ret = append(ret, hst2)
	}
	return ret, nil
}

func NTDecrypt(v []byte, pek [][]byte, rid uint32) ([]byte, error) {
	var tmpNT []byte
	encryptedNT, err := NewCryptedHash(v)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(encryptedNT.Header[:4], []byte("\x13\x00\x00\x00")) {
		encryptedNTW := NewCryptedHashW16(v)
		pekIndex := encryptedNTW.Header
		tmpNT, err = DecryptAES(pek[pekIndex[4]], encryptedNTW.EncryptedHash[:16], encryptedNTW.KeyMaterial[:])
		if err != nil {
			return nil, err
		}
	} else {
		tmpNT, err = removeRC4(encryptedNT, pek)
		if err != nil {
			return nil, err
		}
	}
	return RemoveDES(tmpNT, rid)
}

func SupplementalDecrypt(bval []byte, username string, pek [][]byte) (SuppInfo, error) {
	r := SuppInfo{}

	if len(bval) > 24 { //is the value above the minimum for plaintex passwords?
		var plainBytes []byte
		//check if the record is something something? has a UPN?
		// if v, _ := record.StrVal(nuserPrincipalName); v != "" { //record.Column[nuserPrincipalName"]].StrVal != "" {
		// 	domain := v
		// 	parts := strings.Split(domain, "@")
		// 	domain = parts[len(parts)-1]
		// 	username = fmt.Sprintf("%s\\%s", domain, username)
		// }
		//fmt.Println(val.BytVal)
		ct, err := NewCryptedHash(bval)
		if err != nil {
			return r, err
		}
		//ct := crypted_hash{}.Init(val.BytVal)

		//check for windows 2016 tp4
		if bytes.Equal(ct.Header[:4], []byte{0x13, 0, 0, 0}) {
			//fmt.Println("TODO: WINDOWS 2016 SUPP DATA FOR PLAINTEXT")
			pekIndex := binary.LittleEndian.Uint16(ct.Header[4:6])
			plainBytes, err = DecryptAES(pek[pekIndex],
				ct.EncryptedHash[4:],
				ct.KeyMaterial[:])
			if err != nil {
				return r, err
			}
		} else {
			plainBytes, err = removeRC4(ct, pek)
			if err != nil {
				return r, err
			}
		}
		if len(plainBytes) < 100 {
			return r, fmt.Errorf("bad length for user properties: expecting >100 got %d ", len(plainBytes))
		}
		props := NewSAMRUserProperties(plainBytes)

		for _, x := range props.Properties {
			//apparently we should care about kerberos-newer-keys, but I don't really want to at the moment
			s, e := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(string(x.PropertyName))
			if e != nil {
				continue
			}
			if strings.Compare(s, "Primary:Kerberos-Newer-Keys") == 0 {
				//try decode the thing first
				nhex, err := hex.DecodeString(string(x.PropertyValue))
				if err != nil {
					continue
				}
				cursor := 0
				rec := NewSAMRKerbStoredCredNew(nhex)
				r.KerbKeys = make([]string, rec.CredentialCount)
				for credIndex := uint16(0); credIndex < rec.CredentialCount; credIndex++ {
					keyData := NewSAMRKerbKeyDataNew(rec.Buffer[cursor:])
					cursor += 24 //sizeof samrkerbkeydatanew
					keyVal := nhex[keyData.KeyOffset : keyData.KeyOffset+keyData.KeyLength]
					if k, ok := kerbkeytype[keyData.KeyType]; ok {
						r.KerbKeys[credIndex] = fmt.Sprintf("%s:%s:%s", username, k, hex.EncodeToString(keyVal))
					} else {
						r.KerbKeys[credIndex] = fmt.Sprintf("%s:%d:%s", username, keyData.KeyType, hex.EncodeToString(keyVal))
					}
				}
			}
			if strings.Compare(s, "Primary:CLEARTEXT") == 0 { //awwww yis
				//try decode the thing first
				nhex, err := hex.DecodeString(string(x.PropertyValue))
				if err != nil {
					continue
				}
				sdec, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(string(nhex))
				if err != nil {
					//check for machien key thingo here I guess
					continue
				}
				if !isASCII(sdec) {
					sdec = string(x.PropertyValue)
					r.NotASCII = true
				}
				r.ClearPassword = sdec
			}
			r.Username = username
		}
	}

	return r, nil
}
