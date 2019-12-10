package ditreader

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/C-Sto/gosecretsdump/pkg/esent"
	"golang.org/x/text/encoding/unicode"
)

func (d *DitReader) DecryptRecord(record esent.Esent_record) (DumpedHash, error) {
	dh := DumpedHash{}
	v, _ := record.GetBytVal(nobjectSid)
	sid, err := NewSAMRRPCSID(v) //record.Column[z].BytVal)
	if err != nil {
		return dh, err
	}
	dh.Rid = sid.FormatCanonical()[strings.LastIndex(sid.FormatCanonical(), "-")+1:]

	//lm hash
	if v, ok := record.StrVal(ndBCSPwd); ok && len(v) > 0 {
		//if record.Column[ndBCSPwd"]].StrVal != "" {
		tmpLM := []byte{}
		b, _ := record.GetBytVal(ndBCSPwd)
		encryptedLM := NewCryptedHash(b)
		if bytes.Compare(encryptedLM.Header[:4], []byte("\x13\x00\x00\x00")) == 0 {
			encryptedLMW := NewCryptedHashW16(b)
			pekIndex := encryptedLMW.Header
			tmpLM = decryptAES(d.pek[pekIndex[4]], encryptedLMW.EncrypedHash[:16], encryptedLMW.KeyMaterial[:])
		} else {
			tmpLM = d.removeRC4(encryptedLM)
		}
		dh.LMHash = removeDES(tmpLM, dh.Rid)
	} else {
		//hard coded empty lm hash
		dh.LMHash, _ = hex.DecodeString("aad3b435b51404eeaad3b435b51404ee")
	}

	//nt hash
	if v, _ := record.GetBytVal(nunicodePwd); len(v) > 0 { //  record.Column[nunicodePwd"]].BytVal; len(v) > 0 {
		tmpNT := []byte{}
		encryptedNT := NewCryptedHash(v)
		if bytes.Compare(encryptedNT.Header[:4], []byte("\x13\x00\x00\x00")) == 0 {
			encryptedNTW := NewCryptedHashW16(v)
			pekIndex := encryptedNTW.Header
			tmpNT = decryptAES(d.pek[pekIndex[4]], encryptedNTW.EncrypedHash[:16], encryptedNTW.KeyMaterial[:])
		} else {
			tmpNT = d.removeRC4(encryptedNT)
		}
		dh.NTHash = removeDES(tmpNT, dh.Rid)
	} else {
		//hard coded empty NTLM hash
		dh.NTHash, _ = hex.DecodeString("31D6CFE0D16AE931B73C59D7E0C089C0")
	}

	//username
	if v, ok := record.StrVal(nuserPrincipalName); ok && v != "" && strings.Contains(v, "@") { //record.Column[nuserPrincipalName"]].StrVal; v != "" {
		rec := v
		domain := rec[strings.LastIndex(rec, "@")+1:]
		dh.Username = fmt.Sprintf("%s\\%s", domain, v[:strings.LastIndex(rec, "@")])
	} else {
		v, _ := record.StrVal(nsAMAccountName)
		dh.Username = fmt.Sprintf("%s", v)
	}

	if v, _ := record.GetLongVal(nuserAccountControl); v != 0 { // record.Column[nuserAccountControl"]].Long; v != 0 {
		dh.UAC = decodeUAC(int(v))
	}

	if val, _ := record.GetBytVal(nsupplementalCredentials); len(val) > 24 {
		//if val := record.Column[nsupplementalCredentials"]]; len(val.BytVal) > 24 {
		var err error
		dh.Supp, err = d.decryptSupp(record)
		if err != nil {
			fmt.Println("Error: ", err)
		}
	}

	return dh, nil
}

func (d DitReader) decryptSupp(record esent.Esent_record) (SuppInfo, error) {
	r := SuppInfo{}
	bval, _ := record.GetBytVal(nsupplementalCredentials) // record.Column[nsupplementalCredentials"]]
	if len(bval) > 24 {                                   //is the value above the minimum for plaintex passwords?
		username, _ := record.StrVal(nsAMAccountName)
		var plainBytes []byte
		//check if the record is something something? has a UPN?
		if v, _ := record.StrVal(nuserPrincipalName); v != "" { //record.Column[nuserPrincipalName"]].StrVal != "" {
			domain := v
			parts := strings.Split(domain, "@")
			domain = parts[len(parts)-1]
			username = fmt.Sprintf("%s\\%s", domain, username)
		}
		//fmt.Println(val.BytVal)
		ct := NewCryptedHash(bval)
		//ct := crypted_hash{}.Init(val.BytVal)

		//check for windows 2016 tp4
		if bytes.Compare(ct.Header[:4], []byte{0x13, 0, 0, 0}) == 0 {
			//fmt.Println("TODO: WINDOWS 2016 SUPP DATA FOR PLAINTEXT")
			pekIndex := binary.LittleEndian.Uint16(ct.Header[4:6])
			plainBytes = decryptAES(d.pek[pekIndex],
				ct.EncryptedHash[4:],
				ct.KeyMaterial[:])
		} else {
			plainBytes = d.removeRC4(ct)
		}
		if len(plainBytes) < 100 {
			return r, fmt.Errorf("Bad length for user properties: expecting >100 got %d ", len(plainBytes))
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
				for credIndex := uint16(0); credIndex < rec.CredentialCount; credIndex++ {
					keyData := NewSAMRKerbKeyDataNew(rec.Buffer[cursor:])
					cursor += 24 //sizeof samrkerbkeydatanew
					keyVal := nhex[keyData.KeyOffset : keyData.KeyOffset+keyData.KeyLength]
					r.IsKey = true
					if k, ok := kerbkeytype[keyData.KeyType]; ok {
						r.KeyAnswer = fmt.Sprintf("%s:%s:%s", username, k, hex.EncodeToString(keyVal))
					} else {
						r.KeyAnswer = fmt.Sprintf("%s:%d:%s", username, keyData.KeyType, hex.EncodeToString(keyVal))
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
				r.Username = username
				r.ClearPassword = sdec
			}

		}
	}

	return r, nil
}
