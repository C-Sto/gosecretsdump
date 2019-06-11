package esent

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

type cat_entry struct {
	esent_leaf_entry
	Header esent_data_definition_header        //??
	Record esent_catalog_data_definition_entry //??
}
type table struct {
	Name       string
	TableEntry esent_leaf_entry
	Columns    *cat_entries //map[string]cat_entr
	//Indexes    *OrderedMap_esent_leaf_entry //map[string]esent_leaf_entry
	//Longvalues *OrderedMap_esent_leaf_entry //map[string]esent_leaf_entry
	//data       map[string]interface{}
	//columns    []string
}

/*
func newTable(name string) table {
	return table{
		Name: name,
		data: make(map[string]interface{}),
	}
}

func (t *table) AddColumn(s string) {
	t.data[s] = nil
	t.columns = append(t.columns, s)
}

func (t table) AddData(s string, v interface{}) {
	t.data[s] = v
}

func (t table) Columns() []string {
	return t.columns
}

func (t table) Get(s string) {

}
//*/
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
	column map[string]*esent_recordVal
}

func NewRecord(i int) Esent_record {
	return Esent_record{column: make(map[string]*esent_recordVal, i)}
}

func (e *Esent_record) DeleteColumn(c string) {
	//delete(e.column, c)
}

func (e *Esent_record) ConvTup(c string) {
	r := e.column[c]
	if r == nil {
		//e.column[c] = &esent_recordVal{}
		return
	}
	if r.GetType() == Tup {
		r.ConvTup()
	}
}

func (e *esent_recordVal) ConvTup() {
	e.val = e.tupVal[0]
	e.typ = Byt
}

func (e *Esent_record) UnpackInline(column string, t uint32) {
	r := e.column[column]
	if r == nil {
		//e.column[column] = &esent_recordVal{}
		return
	}
	r.UnpackInline(t)
}

//SetString sets the codepage of the specified column on the record, and marks the record as a 'string'
func (e *Esent_record) SetString(column string, codePage uint32) error {
	if e.column[column] == nil {
		//this should probably be a proper error
		return nil
	}
	if _, ok := stringCodePages[codePage]; !ok { //known decoding type
		return errors.New("unknown codepage")
	}
	e.column[column].SetString(codePage)
	return nil
}

func (v *esent_recordVal) SetString(codePage uint32) {
	v.typ = Str
	v.codePage = codePage
}

//}

func (e *Esent_record) UpdateBytVal(b []byte, column string) {
	if len(b) < 1 {
		return
	}
	if _, ok := e.column[column]; !ok {
		e.column[column] = &esent_recordVal{}
	}
	e.column[column].UpdateBytVal(b)
}

func (e *Esent_record) GetLongVal(column string) (int32, bool) {
	v, ok := e.column[column]
	if ok {
		return v.Long(), ok
	}
	return 0, ok
}

func (e esent_recordVal) Long() int32 {
	return int32(binary.LittleEndian.Uint32(e.val))
}

func (e *Esent_record) GetBytVal(column string) ([]byte, bool) {
	v, ok := e.column[column]
	if ok {
		return v.Bytes(), ok
	}
	return nil, ok
}

func (e esent_recordVal) Bytes() []byte {
	return e.val
}

func (e *Esent_record) StrVal(column string) (string, bool) {
	v, ok := e.column[column]
	if ok {
		return v.String(), ok
	}
	return "", ok
}

func (v esent_recordVal) String() string {
	if v.codePage == 20127 { //ascii
		//v easy
		//record.Column[column] = esent_recordVal{Typ: "Str", StrVal: string(record.Column[column].BytVal)}
		return string(v.val)
	} else if v.codePage == 1200 { //unicode oh boy
		//unicode utf16le
		d := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		b, err := d.Bytes(v.val)
		if err != nil {
			panic(err)
		}
		return string(b)
		//record.Column[column] = esent_recordVal{Typ: "Str", StrVal: string(b)}
	} else if v.codePage == 1252 {
		//fmt.Println("DO WESTERN!!", string(record.Column[column].BytVal))
		d := charmap.Windows1252.NewDecoder()
		b, err := d.Bytes(v.val)
		if err != nil {
			panic(err)
		}
		return string(b)
		//western... idk yet
	}
	return ""
}

func (e *Esent_record) GetRecord(column string) (*esent_recordVal, bool) {
	v, ok := e.column[column]
	if ok {
		return v, ok
	}
	return nil, ok
}

//alternative way of doing this (and probably better) would be casting everything back
//to a byte array that can be cleanly printed.
type esent_recordVal struct {
	tupVal [][]byte
	val    []byte
	//strVal   string
	codePage uint32
	typ      recordTyp

	//bit       bool
	//unsByt    byte
	//short     int16
	//long      int32
	//curr      uint64
	//iEEESingl float32
	//iEEEDoubl float64
	//dateTim   uint64
	// nils for binary, text, longbin, longtext and slv?
	//unsLng  uint32
	//lngLng  uint64
	//guid    [16]byte
	//unsShrt uint16
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

//Data types possible in an esent database
const (
	Byt recordTyp = iota
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
)

type recordTyp int

func (e *esent_recordVal) UpdateBytVal(d []byte) {
	if e == nil {
		e = &esent_recordVal{}
	}
	e.typ = Byt
	e.val = d
}

func (e esent_recordVal) GetType() recordTyp {
	return e.typ
}

func (r *esent_recordVal) UnpackInline(t uint32) {
	if len(r.val) < 1 {
		return
	}
	switch t {
	case JET_coltypNil:
		r.typ = Nil
	case JET_coltypBit:
		r.typ = Bit
	case JET_coltypUnsignedByte:
		r.typ = UnsByt
	case JET_coltypShort:
		r.typ = Short
	case JET_coltypLong:
		r.typ = Long
	case JET_coltypCurrency:
		r.typ = Curr
	case JET_coltypIEEESingle:
		r.typ = IEEESingl
	case JET_coltypIEEEDouble:
		r.typ = IEEEDoub
	case JET_coltypDateTime:
		r.typ = DateTim
	case JET_coltypBinary:
		r.typ = Bin
	case JET_coltypText:
		r.typ = Txt
	case JET_coltypLongBinary:
		r.typ = LongBin
	case JET_coltypLongText:
		r.typ = LongTxt
	case JET_coltypSLV:
		r.typ = SLV
	case JET_coltypUnsignedLong:
		r.typ = UnsLng
	case JET_coltypLongLong:
		r.typ = LngLng
	case JET_coltypGUID:
		r.typ = Guid
	case JET_coltypUnsignedShort:
		r.typ = UnsShrt
	case JET_coltypMax:
		r.typ = Max
	}
}

type tag_item struct {
	TaggedOffset uint16
	TagLen       uint16
	Flags        uint16
}

type taggedItems struct {
	//all of the tagged items
	M map[uint16]tag_item
	O []uint16
}

func (t *taggedItems) Add(tag tag_item, k uint16) {
	//NOT THREAD SAFE
	t.O = append(t.O, k)
	t.M[k] = tag
}

func (t *taggedItems) Parse() {
	prevKey := t.O[0]

	for i := 1; i < len(t.O); i++ {
		vals0 := t.M[prevKey]
		vals := t.M[t.O[i]]
		t.M[prevKey] = tag_item{
			TaggedOffset: vals0.TaggedOffset,
			TagLen:       vals.TaggedOffset - vals0.TaggedOffset,
			Flags:        vals0.Flags,
		}
		prevKey = t.O[i]
	}
}

type cat_entries struct {
	values []cat_entry
	keys   []string
}

func (o *cat_entries) Add(key string, value cat_entry) {
	o.keys = append(o.keys, key)
	o.values = append(o.values, value)
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
