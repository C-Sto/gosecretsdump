package ditreader

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/c-sto/gosecretsdump/pkg/esent"
)

func (d *DitReader) DecryptRecord(record esent.Esent_record) (DumpedHash, error) {
	dh := DumpedHash{}
	if d.useVSSMethod {
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
	} else {
		fmt.Println("DO NOT VSS METHOD?")
	}
	return dh, nil
}
