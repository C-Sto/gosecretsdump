package esent

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type cat_entry struct {
	esent_leaf_entry
	Header esent_data_definition_header        //??
	Record esent_catalog_data_definition_entry //??
}
type table struct {
	Name       string
	TableEntry esent_leaf_entry
	Columns    *OrderedMap_cat_entry        //map[string]cat_entry
	Indexes    *OrderedMap_esent_leaf_entry //map[string]esent_leaf_entry
	Longvalues *OrderedMap_esent_leaf_entry //map[string]esent_leaf_entry
}

type esent_page_header struct {
	CheckSum                     uint64
	ECCCheckSum                  uint32
	LastModificationTime         uint64
	PreviousPageNumber           uint32
	NextPageNumber               uint32
	FatherDataPage               uint32
	AvailableDataSize            uint16
	AvailableUncommittedDataSize uint16
	FirstAvailableDataOffset     uint16
	FirstAvailablePageTag        uint16
	PageFlags                    uint32
	ExtendedCheckSum1            uint64
	ExtendedCheckSum2            uint64
	ExtendedCheckSum3            uint64
	PageNumber                   uint64
	Unknown                      uint64

	Len uint16
}

type esent_jet_sig struct {
	Random       uint32
	CreationTime uint64
	NetBiosName  [16]byte
}

type esent_db_header struct {
	//thank god there is no dynamic fields in this structure
	CheckSum                   uint32
	Signature                  [4]byte //"\xef\xcd\xab\x89'),
	Version                    uint32
	FileType                   uint32
	DBTime                     uint64
	DBSignature                esent_jet_sig //:',ESENT_JET_SIGNATURE),
	DBState                    uint32
	ConsistentPosition         uint64
	ConsistentTime             uint64
	AttachTime                 uint64
	AttachPosition             uint64
	DetachTime                 uint64
	DetachPosition             uint64
	LogSignature               esent_jet_sig //:',ESENT_JET_SIGNATURE),
	Unknown                    uint32
	PreviousBackup             [24]byte
	PreviousIncBackup          [24]byte
	CurrentFullBackup          [24]byte
	ShadowingDisables          uint32
	LastObjectID               uint32
	WindowsMajorVersion        uint32
	WindowsMinorVersion        uint32
	WindowsBuildNumber         uint32
	WindowsServicePackNumber   uint32
	FileFormatRevision         uint32
	PageSize                   uint32
	RepairCount                uint32
	RepairTime                 uint64
	Unknown2                   [28]byte
	ScrubTime                  uint64
	RequiredLog                uint64
	UpgradeExchangeFormat      uint32
	UpgradeFreePages           uint32
	UpgradeSpaceMapPages       uint32
	CurrentShadowBackup        [24]byte
	CreationFileFormatVersion  uint32
	CreationFileFormatRevision uint32
	Unknown3                   [16]byte
	OldRepairCount             uint32
	ECCCount                   uint32
	LastECCTime                uint64
	OldECCFixSuccessCount      uint32
	ECCFixErrorCount           uint32
	LastECCFixErrorTime        uint64
	OldECCFixErrorCount        uint32
	BadCheckSumErrorCount      uint32
	LastBadCheckSumTime        uint64
	OldCheckSumErrorCount      uint32
	CommittedLog               uint32
	PreviousShadowCopy         [24]byte
	PreviousDifferentialBackup [24]byte
	Unknown4                   [40]byte
	NLSMajorVersion            uint32
	NLSMinorVersion            uint32
	Unknown5                   [148]byte
	UnknownFlags               uint32
}

type esent_branch_entry struct {
	CommonPageKeySize uint16

	LocalPageKeySize uint16
	LocalPageKey     []byte // ":"
	ChildPageNumber  uint32
}

func (e esent_branch_entry) Init(flags uint16, ldata []byte) esent_branch_entry {
	r := esent_branch_entry{}
	//zzzz
	data := make([]byte, len(ldata))
	copy(data, ldata)
	//take first 2 bytes of data if common flag is set
	if flags&TAG_COMMON > 0 {
		r.CommonPageKeySize = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
	}
	//fill the structure with remaining data
	//first element is the pagekeysize
	r.LocalPageKeySize = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	//then the pagekey (determined by the pagekeysize)
	r.LocalPageKey = data[:r.LocalPageKeySize]
	data = data[r.LocalPageKeySize:]
	//then we have the childpagenumber (this should be the rest of the data??)
	r.ChildPageNumber = binary.LittleEndian.Uint32(data[:])

	return r
}

type esent_leaf_entry struct {
	CommonPageKeySize uint16

	LocalPageKeySize uint16
	//_LocalPageKey    string //nil
	LocalPageKey []byte // ":"
	EntryData    []byte // ":"
}

func (e esent_leaf_entry) Init(flags uint16, inData []byte) esent_leaf_entry {
	r := esent_leaf_entry{}
	data := make([]byte, len(inData))

	copy(data, inData)
	//take first 2 bytes of data if common flag is set
	if flags&TAG_COMMON > 0 {
		r.CommonPageKeySize = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
	}
	//fill the structure with remaining data
	//first element is the pagekeysize
	r.LocalPageKeySize = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	//then the pagekey (determined by the pagekeysize)
	r.LocalPageKey = data[:r.LocalPageKeySize]
	data = data[r.LocalPageKeySize:]
	//then we have the data (this should be the rest of the data??)
	r.EntryData = data[:]
	return r
}

type esent_data_definition_header struct {
	LastFixedSize        uint8
	LastVariableDataType uint8
	VariableSizeOffset   uint16
}

type esent_catalog_data_definition_entry struct {
	Fixed   fixed_catalog_data_definition_entry
	Columns columns_catalog_data_definition_entry
	Other   other_catalog_data_definition_entry
	Table   table_catalog_data_definition_entry
	Index   index_catalog_data_definition_entry
	LV      lV_catalog_data_definition_entry
	Common  common_catalog_data_definition_entry
}

func (e esent_catalog_data_definition_entry) Init(inData []byte) (esent_catalog_data_definition_entry, error) {

	data := make([]byte, len(inData))
	copy(data, inData)

	r := esent_catalog_data_definition_entry{}
	//fill in fixed
	buffer := bytes.NewBuffer(data[:10])
	err := binary.Read(buffer, binary.LittleEndian, &r.Fixed)
	if err != nil {
		panic(err)
	}
	data = data[10:]

	//this is where it gets hairy :(
	if r.Fixed.Type == CATALOG_TYPE_COLUMN {
		//only one with no 'other' section
		//fill in column stuff
		buffer := bytes.NewBuffer(data[:16])
		err := binary.Read(buffer, binary.LittleEndian, &r.Columns)
		if err != nil {
			panic(err)
		}
		data = data[16:]
	} else {

		//fill in 'other'
		r.Other.FatherDataPageNumber = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]

		if r.Fixed.Type == CATALOG_TYPE_TABLE {
			//do 'table stuff'
			r.Table.SpaceUsage = binary.LittleEndian.Uint32(data[:4])
			data = data[4:]
		} else if r.Fixed.Type == CATALOG_TYPE_INDEX {
			//index stuff
			buffer := bytes.NewBuffer(data[:12])
			err := binary.Read(buffer, binary.LittleEndian, &r.Index)
			if err != nil {
				panic(err)
			}
			data = data[12:]
		} else if r.Fixed.Type == CATALOG_TYPE_LONG_VALUE {
			r.LV.SpaceUsage = binary.LittleEndian.Uint32(data[:4])
			data = data[4:]
		} else if r.Fixed.Type == CATALOG_TYPE_CALLBACK {
			panic("lol no")
		} else {
			return esent_catalog_data_definition_entry{}, errors.New("Unkown Type")
		}
	}
	//fill in common stuff
	r.Common.Trailing = data[:]

	return r, nil
}

type fixed_catalog_data_definition_entry struct {
	FatherDataPageID uint32
	Type             uint16
	Identifier       uint32
}
type columns_catalog_data_definition_entry struct {
	ColumnType  uint32
	SpaceUsage  uint32
	ColumnFlags uint32
	CodePage    uint32
}
type other_catalog_data_definition_entry struct {
	FatherDataPageNumber uint32
}
type table_catalog_data_definition_entry struct {
	SpaceUsage uint32
}
type index_catalog_data_definition_entry struct {
	SpaceUsage uint32
	IndexFlags uint32
	Locale     uint32
}
type lV_catalog_data_definition_entry struct {
	SpaceUsage uint32
}
type common_catalog_data_definition_entry struct {
	Trailing []byte
}

type cursorRecord struct {
	Identifier uint8
	SpaceUsage uint32
	ColumnType int
	CodePage   int
}

type cursorColumn struct {
	Record cursorRecord
}

type cursorTable struct {
	Columns map[string]cursorColumn
}

type Cursor struct {
	CurrentTag           uint32
	FatherDataPageNumber uint32
	CurrentPageData      esent_page
	TableData            table
}

type Esent_record struct {
	Column map[string]esent_recordVal
}

//alternative way of doing this (and probably better) would be casting everything back
//to a byte array that can be cleanly printed.
type esent_recordVal struct {
	TupVal [][]byte
	BytVal []byte
	StrVal string
	Typ    string

	Bit       bool
	UnsByt    byte
	Short     int16
	Long      int32
	Curr      uint64
	IEEESingl float32
	IEEEDoubl float64
	DateTim   uint64
	// nils for binary, text, longbin, longtext and slv?
	UnsLng  uint32
	LngLng  uint64
	Guid    [16]byte
	UnsShrt uint16
	/*
		Byt
		Tup
		Str

		Nil
		Bit
		UnsByt
		Short
		Long
		Curr
		IEEESingl
		IEEEDoub
		DateTim
		Bin
		Txt
		LongBin
		LongTxt
		SLV
		UnsLng
		LngLng
		Guid
		UnsShrt
		Max
	*/
}

func (e esent_recordVal) Unpack(t uint32, in_data []byte) esent_recordVal {
	data := make([]byte, len(in_data))
	copy(data, in_data)
	r := esent_recordVal{}

	switch t {
	case JET_coltypNil:
		r.Typ = "Nil"
	case JET_coltypBit:
		r.Typ = "Bit"
	case JET_coltypUnsignedByte:
		r.Typ = "UnsByt"
	case JET_coltypShort:
		r.Typ = "Short"
	case JET_coltypLong:
		r.Typ = "Long"
	case JET_coltypCurrency:
		r.Typ = "Curr"
	case JET_coltypIEEESingle:
		r.Typ = "IEEESingl"
	case JET_coltypIEEEDouble:
		r.Typ = "IEEEDoubl"
	case JET_coltypDateTime:
		r.Typ = "DateTim"
	case JET_coltypBinary:
		r.Typ = "Bin"
	case JET_coltypText:
		r.Typ = "Txt"
	case JET_coltypLongBinary:
		r.Typ = "LongBin"
	case JET_coltypLongText:
		r.Typ = "LongTxt"
	case JET_coltypSLV:
		r.Typ = "SLV"
	case JET_coltypUnsignedLong:
		r.Typ = "UnsLng"
	case JET_coltypLongLong:
		r.Typ = "LngLng"
	case JET_coltypGUID:
		r.Typ = "GUID"
	case JET_coltypUnsignedShort:
		r.Typ = "UnsShrt"
	case JET_coltypMax:
		r.Typ = "Max"
	}
	if len(data) < 1 {
		return r
	}
	buf := bytes.NewReader(data)
	switch t {
	case JET_coltypBit:
		if data[0] > 0 {
			r.Bit = true
		} else {
			r.Bit = false
		}
	case JET_coltypUnsignedByte:
		r.UnsByt = data[0]
	case JET_coltypShort:
		binary.Read(buf, binary.LittleEndian, &r.Short)
	case JET_coltypLong:
		binary.Read(buf, binary.LittleEndian, &r.Long)
	case JET_coltypCurrency:
		binary.Read(buf, binary.LittleEndian, &r.Curr)
	case JET_coltypIEEESingle:
		binary.Read(buf, binary.LittleEndian, &r.IEEESingl)
	case JET_coltypIEEEDouble:
		binary.Read(buf, binary.LittleEndian, &r.IEEEDoubl)
	case JET_coltypDateTime:
		binary.Read(buf, binary.LittleEndian, &r.DateTim)
	case JET_coltypUnsignedLong:
		binary.Read(buf, binary.LittleEndian, &r.UnsLng)
	case JET_coltypLongLong:
		binary.Read(buf, binary.LittleEndian, &r.LngLng)
	case JET_coltypGUID:
		binary.Read(buf, binary.LittleEndian, &r.Guid)
	case JET_coltypUnsignedShort:
		binary.Read(buf, binary.LittleEndian, &r.UnsShrt)
	case JET_coltypBinary:
		fallthrough
	case JET_coltypText:
		fallthrough
	case JET_coltypLongBinary:
		fallthrough
	case JET_coltypLongText:
		fallthrough
	case JET_coltypSLV:
		fallthrough
	case JET_coltypNil:
		fallthrough
	case JET_coltypMax:
		fallthrough
	// 'None' length? just store it as a hex string ok ????
	default:
		//store as raw bytes here to avoid conversion overhead
		r.BytVal = data
		//store as hex string here for legacy compatibility
		//r.StrVal = hex.EncodeToString(data) // (removed during optimisations)
	}
	return r
}

type tag_item struct {
	TaggedOffset uint16
	TagLen       uint16
	Flags        uint16
}

type taggedItems struct {
	M map[uint16]tag_item
	O []uint16
}

type OrderedMap_cat_entry struct {
	values map[string]cat_entry
	keys   []string
}

func (o *OrderedMap_cat_entry) Add(key string, value cat_entry) {
	_, exists := o.values[key]
	if !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

type OrderedMap_esent_leaf_entry struct {
	values map[string]esent_leaf_entry
	keys   []string
}

func (o *OrderedMap_esent_leaf_entry) Add(key string, value esent_leaf_entry) {
	_, exists := o.values[key]
	if !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}
