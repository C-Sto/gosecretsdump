package ditreader

import (
	"encoding/binary"
	"fmt"
)

type SAMRUserProperties struct { /*
			# 2.2.10.1 USER_PROPERTIES
		class USER_PROPERTIES(Structure):
			structure = (
				('Reserved1','<L=0'), L = 4 bytes (uint32)
				('Length','<L=0'),
				('Reserved2','<H=0'), H = 2 bytes (uint16)
				('Reserved3','<H=0'),
				('Reserved4','96s=""'), S = 1byte (String)
				('PropertySignature','<H=0x50'),
				('PropertyCount','<H=0'),
				('UserProperties',':'),
		)*/
	Reserved1         uint32
	Length            uint32
	Reserved2         uint16
	Reserved3         uint16
	Reserved4         [96]byte
	PropertySignature uint16
	PropertyCount     uint16
	Properties        []SAMRUserProperty
}

func NewSAMRUserProperties(data []byte) SAMRUserProperties {
	r := SAMRUserProperties{}
	lData := make([]byte, len(data)) //avoid mutate
	copy(lData, data)

	r.Reserved1 = binary.LittleEndian.Uint32(lData[:4])
	lData = lData[4:]
	r.Length = binary.LittleEndian.Uint32(lData[:4])
	lData = lData[4:]
	r.Reserved2 = binary.LittleEndian.Uint16(lData[:2])
	lData = lData[2:]
	r.Reserved3 = binary.LittleEndian.Uint16(lData[:2])
	lData = lData[2:]
	copy(r.Reserved4[:], lData[:96])
	lData = lData[96:]
	r.PropertySignature = binary.LittleEndian.Uint16(lData[:2])
	lData = lData[2:]
	r.PropertyCount = binary.LittleEndian.Uint16(lData[:2])
	lData = lData[2:]
	//fill properties
	for i := uint16(0); i < r.PropertyCount; i++ {
		np := SAMR_USER_PROPERTY{}
		np.NameLength = binary.LittleEndian.Uint16(lData[:2])
		lData = lData[2:]
		np.ValueLength = binary.LittleEndian.Uint16(lData[:2])
		lData = lData[2:]
		np.Reserved = binary.LittleEndian.Uint16(lData[:2])
		lData = lData[2:]
		np.PropertyName = lData[:np.NameLength]
		lData = lData[np.NameLength:]
		np.PropertyValue = lData[:np.ValueLength]
		lData = lData[np.ValueLength:]
		r.Properties = append(r.Properties, np)
	}
	return r
}

type SAMRUserProperty struct {
	/*
			class USER_PROPERTY(Structure):
		    structure = (
		        ('NameLength','<H=0'),
		        ('ValueLength','<H=0'),
		        ('Reserved','<H=0'),
		        ('_PropertyName','_-PropertyName', "self['NameLength']"),
		        ('PropertyName',':'),
		        ('_PropertyValue','_-PropertyValue', "self['ValueLength']"),
		        ('PropertyValue',':'),
		)
	*/
	NameLength    uint16
	ValueLength   uint16
	Reserved      uint16
	PropertyName  []byte
	PropertyValue []byte
}

type SAMRRPCSID struct {
	Revision            uint8   //'<B'
	SubAuthorityCount   uint8   //'<B'
	IdentifierAuthority [6]byte //SAMR_RPC_SID_IDENTIFIER_AUTHORITY
	SubLen              int     //    ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
	SubAuthority        []byte  //':'
}

func (s SAMRRPCSID) FormatCanonical() string {
	ans := fmt.Sprintf("S-%d-%d", s.Revision, s.IdentifierAuthority[5])
	for i := 0; i < int(s.SubAuthorityCount); i++ {
		ans += fmt.Sprintf("-%d", binary.BigEndian.Uint32(s.SubAuthority[i*4:i*4+4]))
	}
	return ans
}

func NewSAMRRPCSID(data []byte) (SAMRRPCSID, error) {
	r := SAMR_RPC_SID{}
	if len(data) < 6 {
		return r, fmt.Errorf("Bad SAMR data: %s", string(data))
	}
	lData := make([]byte, len(data)) //avoid mutate
	copy(lData, data)

	r.Revision = lData[0]
	r.SubAuthorityCount = lData[1]
	lData = lData[2:]
	copy(r.IdentifierAuthority[:], lData[:6])
	lData = lData[6:]
	r.SubLen = int(r.SubAuthorityCount) * 4
	r.SubAuthority = make([]byte, len(lData))
	copy(r.SubAuthority, lData)
	return r, nil
}
