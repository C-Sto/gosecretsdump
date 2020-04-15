package ditreader

import (
	"encoding/hex"
	"fmt"
	"strings"
	u "unicode"
)

type uacFlags struct {
	Script, AccountDisable, HomeDirRequired,
	Lockout, PasswdNotReqd, EncryptedTextPwdAllowed,
	TempDupAccount, NormalAccount, InterDomainTrustAcct,
	WorkstationTrustAccount, ServerTrustAccount,
	DontExpirePassword, MNSLogonAccount, SmartcardRequired,
	TrustedForDelegation, NotDelegated, UseDESOnly,
	DontPreauth, PasswordExpired, TrustedToAuthForDelegation,
	PartialSecrets bool
}

//https://stackoverflow.com/questions/53069040/checking-a-string-contains-only-ascii-characters
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > u.MaxASCII {
			return false
		}
	}
	return true
}

//whoa this is a dumb way of doing it,
//but I've had too many rums to think of the actual way
func decodeUAC(val int) uacFlags {
	r := uacFlags{}
	r.Script = val|1 == val
	r.AccountDisable = val|2 == val
	r.HomeDirRequired = val|8 == val
	r.Lockout = val|6 == val
	r.PasswdNotReqd = val|32 == val
	r.EncryptedTextPwdAllowed = val|128 == val
	r.TempDupAccount = val|256 == val
	r.NormalAccount = val|512 == val
	r.InterDomainTrustAcct = val|2048 == val
	r.WorkstationTrustAccount = val|4096 == val
	r.ServerTrustAccount = val|8192 == val
	r.DontExpirePassword = val|65536 == val
	r.MNSLogonAccount = val|131072 == val
	r.SmartcardRequired = val|262144 == val
	r.TrustedForDelegation = val|524288 == val
	r.NotDelegated = val|1048576 == val
	r.UseDESOnly = val|2097152 == val
	r.DontPreauth = val|4194304 == val
	r.PasswordExpired = val|8388608 == val
	r.TrustedToAuthForDelegation = val|16777216 == val
	r.PartialSecrets = val|67108864 == val
	return r
}

type SuppInfo struct {
	Username      string
	ClearPassword string
	NotASCII      bool
	KerbKeys      []string
}

func (s SuppInfo) ClearString() string {
	frmt := "%s:CLEARTEXT:%s"
	if s.NotASCII {
		frmt = "%s:CLEARTEXT_HEX:%s"
	}
	return fmt.Sprintf(frmt, s.Username, s.ClearPassword)
}

func (s SuppInfo) KerbString() string {
	return strings.Join(s.KerbKeys, "\n")
}

type DumpedHash struct {
	Username string
	LMHash   []byte
	NTHash   []byte
	Rid      string
	Enabled  bool
	UAC      uacFlags
	Supp     SuppInfo
	History  PwdHistory
}

type PwdHistory struct {
	LmHist [][]byte
	NTHist [][]byte
}

func (d DumpedHash) HistoryString() string {
	r := strings.Builder{}
	for i, v := range d.History.LmHist {
		r.WriteString(fmt.Sprintf("%s_history%d:%s:%s:%s:::\n",
			d.Username,
			i,
			d.Rid,
			hex.EncodeToString(v),
			hex.EncodeToString(emptyNT),
		))
	}
	for i, v := range d.History.NTHist {
		r.WriteString(fmt.Sprintf("%s_history%d:%s:%s:%s:::\n",
			d.Username,
			i,
			d.Rid,
			hex.EncodeToString(emptyLM),
			hex.EncodeToString(v),
		))
	}
	return r.String()
}

func (d DumpedHash) HashString() string {
	answer := fmt.Sprintf("%s:%s:%s:%s:::",
		d.Username,
		d.Rid,
		hex.EncodeToString(d.LMHash),
		hex.EncodeToString(d.NTHash))
	return answer
}
