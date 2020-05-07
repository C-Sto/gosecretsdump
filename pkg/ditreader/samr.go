package ditreader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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

type SAMRKerbStoredCredNew struct {
	/*
	   structure = (
	       ('Revision','<H=4'),
	       ('Flags','<H=0'),
	       ('CredentialCount','<H=0'),
	       ('ServiceCredentialCount','<H=0'),
	       ('OldCredentialCount','<H=0'),
	       ('OlderCredentialCount','<H=0'),
	       ('DefaultSaltLength','<H=0'),
	       ('DefaultSaltMaximumLength','<H=0'),
	       ('DefaultSaltOffset','<L=0'),
	       ('DefaultIterationCount','<L=0'),
	       ('Buffer',':'),
	   )
	*/
	Revision, Flags, CredentialCount,
	ServiceCredentialCount, OldCredentialCount,
	OlderCredentialCount, DefaultSaltLength,
	DefaultSaltMaximumLength uint16
	DefaultSaltOffset, DefaultIterationCount uint32
	Buffer                                   []byte
}

func NewSAMRKerbStoredCredNew(d []byte) SAMRKerbStoredCredNew {
	r := SAMRKerbStoredCredNew{}
	curs := 0
	r.Revision = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.Flags = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.CredentialCount = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.ServiceCredentialCount = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.OldCredentialCount = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.OlderCredentialCount = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.DefaultSaltLength = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.DefaultSaltMaximumLength = binary.LittleEndian.Uint16(getAndMoveCursor(d, &curs, 2))
	r.DefaultSaltOffset = binary.LittleEndian.Uint32(getAndMoveCursor(d, &curs, 4))
	r.DefaultIterationCount = binary.LittleEndian.Uint32(getAndMoveCursor(d, &curs, 4))
	r.Buffer = d[curs:]

	return r
}

type SAMRKerbKeyDataNew struct {
	Reserved1, Reserved2 uint16
	Reserved3, IterationCount,
	KeyType, KeyLength, KeyOffset uint32
}

func NewSAMRKerbKeyDataNew(d []byte) SAMRKerbKeyDataNew {
	kd := SAMRKerbKeyDataNew{}
	binary.Read(bytes.NewReader(d), binary.LittleEndian, &kd)
	return kd
}

func getAndMoveCursor(data []byte, curs *int, size int) []byte {
	d := data[*curs : *curs+size]
	*curs += size
	return d
}

func NewSAMRUserProperties(data []byte) SAMRUserProperties {
	r := SAMRUserProperties{}
	//	lData := make([]byte, len(data)) //avoid mutate
	//	copy(lData, data)
	curs := 0

	r.Reserved1 = binary.LittleEndian.Uint32(getAndMoveCursor(data, &curs, 4))
	r.Length = binary.LittleEndian.Uint32(getAndMoveCursor(data, &curs, 4))
	r.Reserved2 = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
	r.Reserved3 = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
	copy(r.Reserved4[:], data[curs:curs+96])
	curs += 96
	r.PropertySignature = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
	if len(data) > curs+2 {
		r.PropertyCount = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
		//fill properties
		for i := uint16(0); i < r.PropertyCount; i++ {
			np := SAMRUserProperty{}
			np.NameLength = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
			np.ValueLength = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
			np.Reserved = binary.LittleEndian.Uint16(getAndMoveCursor(data, &curs, 2))
			np.PropertyName = data[curs : curs+int(np.NameLength)]
			curs += int(np.NameLength)
			np.PropertyValue = data[curs : curs+int(np.ValueLength)]
			curs += int(np.ValueLength)
			r.Properties = append(r.Properties, np)
		}
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
	var ans strings.Builder

	ans.WriteString(fmt.Sprintf("S-%d-%d", s.Revision, s.IdentifierAuthority[5]))
	for i := 0; i < int(s.SubAuthorityCount); i++ {
		ans.WriteString(fmt.Sprintf("-%d", binary.BigEndian.Uint32(s.SubAuthority[i*4:i*4+4])))
	}
	return ans.String()
}

func (s SAMRRPCSID) Rid() uint32 {
	l := s.SubAuthorityCount
	return binary.BigEndian.Uint32(s.SubAuthority[(l-1)*4 : (l-1)*4+4])
}

func NewSAMRRPCSID(data []byte) (SAMRRPCSID, error) {
	r := SAMRRPCSID{}
	if len(data) < 6 {
		return r, fmt.Errorf("Bad SAMR data: %s", string(data))
	}
	curs := 0

	r.Revision = data[0]
	r.SubAuthorityCount = data[1]

	getAndMoveCursor(data, &curs, 2)
	copy(r.IdentifierAuthority[:], getAndMoveCursor(data, &curs, 6))
	r.SubLen = int(r.SubAuthorityCount) * 4
	r.SubAuthority = data[curs:] // make([]byte, len(data[curs:]))
	//copy(r.SubAuthority, data[curs:])
	return r, nil
}
