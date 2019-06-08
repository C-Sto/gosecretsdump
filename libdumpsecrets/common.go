package libdumpsecrets

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/text/encoding/unicode"

	"github.com/c-sto/gosecretsdump/pkg/esent"
)

//This is essentially a direct translation of impacket's secretsdump. I did not reverse any of the file stuff, just translated it into golang
//all credit should go to the impacket team for that

//this file (and the other impackety libs I use) will slowly be optimized once I get a feel for how everything works
//ideally making everything more parallel friendly etc

//global maps are probably not the best way of doing this, but it will do for now

func (g *Gosecretsdump) decryptSupp(record esent.Esent_record) (suppInfo, error) {
	r := suppInfo{}
	///*
	if g.useVSSMethod {
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
			ct := crypted_hash{}.Init(val.BytVal)

			//check for windows 2016 tp4
			if bytes.Compare(ct.Header[:4], []byte{0x13, 0, 0, 0}) == 0 {
				//fmt.Println("TODO: WINDOWS 2016 SUPP DATA FOR PLAINTEXT")
				pekIndex := binary.LittleEndian.Uint16(ct.Header[4:5])
				plainBytes = decryptAES(g.pek[pekIndex],
					ct.EncryptedHash[4:],
					ct.KeyMaterial[:])
			} else {
				plainBytes = g.removeRC4(ct)
			}

			props := SAMR_USER_PROPERTIES{}.New(plainBytes)
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

	} else {
		fmt.Println("NOT VSS METHOD???")
	}
	return r, nil
}

func (g Gosecretsdump) handleSupp(dh dumpedHash, ds suppInfo) {
	if ds.Username == "" {
		return
	}
	//print out the decrypted record
	prntLine := ds.HashString()
	if g.settings.Status {
		stat := "Enabled"
		if dh.UAC.AccountDisable {
			stat = "Disabled"
		}
		prntLine += " (status=" + stat + ")"
	}
	if g.settings.EnabledOnly {
		if !dh.UAC.AccountDisable {
			writeFileAndPrintLn(g.settings.Outfile, prntLine, !g.settings.NoPrint, true)
		}
	} else {
		writeFileAndPrintLn(g.settings.Outfile, prntLine, !g.settings.NoPrint, true)
	}
}

func (g Gosecretsdump) handleHash(dh dumpedHash) {
	//print out the decrypted record
	prntLine := dh.HashString()
	if g.settings.Status {
		stat := "Enabled"
		if dh.UAC.AccountDisable {
			stat = "Disabled"
		}
		prntLine += " (status=" + stat + ")"
	}
	if g.settings.EnabledOnly {
		if !dh.UAC.AccountDisable {
			writeFileAndPrintLn(g.settings.Outfile, prntLine, !g.settings.NoPrint, false)
		}
	} else {
		writeFileAndPrintLn(g.settings.Outfile, prntLine, !g.settings.NoPrint, false)
	}
}

func writeFileAndPrintLn(outfile, val string, print bool, cleartext bool) {
	if outfile != "" {
		if cleartext {
			outfile = outfile + ".cleartext"
		}
		file, err := os.OpenFile(outfile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.WriteString(val + "\n")
		file.Sync()
	}
	if print {
		fmt.Println(val)
	}
}
