package ditreader

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/c-sto/gosecretsdump/pkg/esent"
	"golang.org/x/text/encoding/unicode"
)

func (d *DitReader) DecryptRecord(record esent.Esent_record) (DumpedHash, error) {
	dh := DumpedHash{}
	z := nToInternal["objectSid"]
	sid, err := NewSAMRRPCSID(record.Column[z].BytVal)
	if err != nil {
		return dh, err
	}
	dh.Rid = sid.FormatCanonical()[strings.LastIndex(sid.FormatCanonical(), "-")+1:]

	//lm hash
	if record.Column[nToInternal["dBCSPwd"]].StrVal != "" {
		tmpLM := []byte{}
		encryptedLM := NewCryptedHash(record.Column[nToInternal["dBCSPwd"]].BytVal)
		if bytes.Compare(encryptedLM.Header[:4], []byte("\x13\x00\x00\x00")) == 0 {
			encryptedLMW := NewCryptedHashW16(record.Column[nToInternal["dBCSPwd"]].BytVal)
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
	if v := record.Column[nToInternal["unicodePwd"]].BytVal; len(v) > 0 {
		tmpNT := []byte{}
		encryptedNT := NewCryptedHash(v)
		if bytes.Compare(encryptedNT.Header[:4], []byte("\x13\x00\x00\x00")) == 0 {
			encryptedNTW := NewCryptedHashW16(record.Column[nToInternal["unicodePwd"]].BytVal)
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
	if v := record.Column[nToInternal["userPrincipalName"]].StrVal; v != "" {
		rec := record.Column[nToInternal["userPrincipalName"]].StrVal
		recs := strings.Split(rec, "@")
		domain := recs[len(recs)-1]
		dh.Username = fmt.Sprintf("%s\\%s", domain, record.Column[nToInternal["sAMAccountName"]].StrVal)
	} else {
		dh.Username = fmt.Sprintf("%s", record.Column[nToInternal["sAMAccountName"]].StrVal)
	}

	if v := record.Column[nToInternal["userAccountControl"]].Long; v != 0 {
		dh.UAC = decodeUAC(int(v))
	}

	if val := record.Column[nToInternal["supplementalCredentials"]]; len(val.BytVal) > 24 {
		var err error
		dh.Supp, err = d.decryptSupp(record)
		if err != nil {
			panic(err)
		}
	}

	return dh, nil
}

func (d DitReader) decryptSupp(record esent.Esent_record) (SuppInfo, error) {
	r := SuppInfo{}
	val := record.Column[nToInternal["supplementalCredentials"]]
	if len(val.BytVal) > 24 { //is the value above the minimum for plaintex passwords?
		username := ""
		var plainBytes []byte
		//check if the record is something something? has a UPN?
		fmt.Println(record)
		if record.Column[nToInternal["userPrincipalName"]].StrVal != "" {
			domain := record.Column[nToInternal["userPrincipalName"]].StrVal
			parts := strings.Split(domain, "@")
			domain = parts[len(parts)]
			username = fmt.Sprintf("%s\\%s", domain, record.Column[nToInternal["sAMAccountName"]].StrVal)
		} else {
			username = record.Column[nToInternal["sAMAccountName"]].StrVal
		}
		//fmt.Println(val.BytVal)
		ct := NewCryptedHash(val.BytVal)
		//ct := crypted_hash{}.Init(val.BytVal)

		//check for windows 2016 tp4
		if bytes.Compare(ct.Header[:4], []byte{0x13, 0, 0, 0}) == 0 {
			//fmt.Println("TODO: WINDOWS 2016 SUPP DATA FOR PLAINTEXT")
			pekIndex := binary.LittleEndian.Uint16(ct.Header[4:5])
			plainBytes = decryptAES(d.pek[pekIndex],
				ct.EncryptedHash[4:],
				ct.KeyMaterial[:])
		} else {
			plainBytes = d.removeRC4(ct)
		}

		props := NewSAMRUserProperties(plainBytes)
		for _, x := range props.Properties {
			//apparently we should care about kerberos-newer-keys, but I don't really want to at the moment
			s, e := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(string(x.PropertyName))
			if e != nil {
				continue
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
