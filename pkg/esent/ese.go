package esent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/text/encoding/charmap"

	"golang.org/x/text/encoding/unicode"
)

//props to agsolino for doing the original impacket version of this. The file format is clearly a mindfuck, and it would not have been easy.

//todo: update to handle massive files better (so we don't saturate memory too bad)
type fileInMem struct {
	data     []byte
	lastread int
}

func (f *fileInMem) Read(start, count int) []byte {
	if start > len(f.data) {
		return nil
	}
	r := make([]byte, count)
	if start+count > len(f.data) {
		copy(r, f.data[start:len(f.data)])
	} else {
		copy(r, f.data[start:start+count])
	}
	f.lastread = start + count
	return r
}

type Esedb struct {
	//options?
	filename     string
	pageSize     uint32
	db           *fileInMem
	dbHeader     esent_db_header
	totalPages   uint64
	tables       map[string]table
	currentTable string
	isRemote     bool

	StringCodePages map[uint32]string //standin for const lookup/enum thing
}

func (e Esedb) Init(fn string) Esedb {
	//create the esedb structure
	r := Esedb{
		filename:        fn,
		pageSize:        pageSize,
		tables:          make(map[string]table),
		isRemote:        false,
		StringCodePages: make(map[uint32]string),
	}

	//add the codepages to the map, for better printing
	r.StringCodePages[1200] = "utf-16le"
	r.StringCodePages[20127] = "ascii"
	r.StringCodePages[1252] = "cp1252"

	//read the file into memory
	f, err := os.Open(fn)
	if err != nil {
		panic(err)
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	f.Close()
	r.db = &fileInMem{data, 0}

	//'mount' the database (parse the file)
	r.mountDb()
	return r
}

//OpenTable opens a table, and returns a cursor pointing to the current parsing state
func (e *Esedb) OpenTable(s string) *Cursor {
	r := Cursor{} //this feels like it can be optimised

	//if the table actually exists
	if v, ok := e.tables[s]; ok {
		entry := v.TableEntry
		//set the header
		ddHeader := esent_data_definition_header{}
		buffer := bytes.NewBuffer(entry.EntryData)
		err := binary.Read(buffer, binary.LittleEndian, &ddHeader)
		if err != nil {
			panic(err)
		}

		//initialise the catalog entry
		catEnt, err := esent_catalog_data_definition_entry{}.Init(entry.EntryData[4:])
		if err != nil {
			panic(err)
		}

		//determine the page number to retreive
		pageNum := catEnt.Other.FatherDataPageNumber
		var page esent_page
		var done = false
		for !done {
			page = e.getPage(pageNum)
			if page.record.FirstAvailablePageTag <= 1 {
				//no records
				break
			}
			for i := uint16(1); i < page.record.FirstAvailablePageTag; i++ {
				if page.record.PageFlags&FLAGS_LEAF == 0 {
					flags, data := page.getTag(int(i))
					branchEntry := esent_branch_entry{}.Init(flags, data)
					pageNum = branchEntry.ChildPageNumber
					break
				} else {
					done = true
					break
				}
			}
		}
		cursor := Cursor{
			TableData:            e.tables[s],
			FatherDataPageNumber: catEnt.Other.FatherDataPageNumber,
			CurrentPageData:      page,
			CurrentTag:           0,
		}
		return &cursor
	}

	return &r
}

func (e *Esedb) mountDb() {
	//the first page is the dbheader
	e.dbHeader = e.getMainHeader()
	e.pageSize = e.dbHeader.PageSize

	// this was a gross way of working out how many pages the file has...
	fileLen := len(e.db.data)
	pages := fileLen / int(e.pageSize)
	e.totalPages = uint64(pages - 2) //unsure why -2 at this stage, I assume first page is header and last page is tail?

	//this is where everything actually gets parsed out
	e.parseCatalog(CATALOG_PAGE_NUMBER) //4  ?
}

func (e *Esedb) parseCatalog(pagenum uint32) {
	//parse all pages starting at pagenum, and add to the in-memory table

	//get the page
	page := e.getPage(pagenum)

	//parse the page
	e.parsePage(page)

	//Iterate over each tag in the branch
	for i := 1; i < int(page.record.FirstAvailablePageTag); i++ {
		//get the tag flags, and data
		flags, data := page.getTag(i)
		//if we are looking at a branch page
		if page.record.PageFlags&FLAGS_LEAF == 0 {
			//create the branch entry from the flags and data retreived
			branchEntry := esent_branch_entry{}.Init(flags, data)
			//walk along the branch, and parse any referenced pages
			e.parseCatalog(branchEntry.ChildPageNumber)
		}
	}
}
func (e *Esedb) parsePage(page esent_page) {
	//baseOffset := page.record.Len // useless line?
	if page.record.PageFlags&FLAGS_LEAF == 0 || //not a leaf, don't care
		page.record.PageFlags&FLAGS_LEAF > 0 && (page.record.PageFlags&FLAGS_SPACE_TREE > 0 ||
			page.record.PageFlags&FLAGS_INDEX > 0 || page.record.PageFlags&FLAGS_LONG_VALUE > 0) {
		return
	}

	//must be table entry
	for tagnum := 1; tagnum < int(page.record.FirstAvailablePageTag); tagnum++ {
		flags, data := page.getTag(tagnum)
		leafEntry := esent_leaf_entry{}.Init(flags, data)
		e.addLeaf(leafEntry)
	}
}

const NONE = "NoneReturn"

func (e *Esedb) GetNextRow(c *Cursor) (Esent_record, error) {
	c.CurrentTag++
	// increment cursor pointer to look for 'next' tag

	//getnexttag starts here
	page := c.CurrentPageData
	var err error
	if c.CurrentTag >= uint32(page.record.FirstAvailablePageTag) {
		err = errors.New("ignore") //nil
	}

	if page.record.PageFlags&FLAGS_LEAF == 0 || //not a leaf, don't care
		page.record.PageFlags&FLAGS_LEAF > 0 && (page.record.PageFlags&FLAGS_SPACE_TREE > 0 ||
			page.record.PageFlags&FLAGS_INDEX > 0 || page.record.PageFlags&FLAGS_LONG_VALUE > 0) {
		err = errors.New("ignore")
	}

	//should handle none tag better zz
	if err != nil && err.Error() != "ignore" {
		panic(err)
	}

	if err != nil && err.Error() == "ignore" { //tag is none
		page := c.CurrentPageData
		if page.record.NextPageNumber == 0 { //no more pages :(
			return Esent_record{}, err
		}

		c.CurrentPageData = e.getPage(page.record.NextPageNumber)
		c.CurrentTag = 0
		return e.GetNextRow(c) //lol recursion

	}

	flags, data := page.getTag(int(c.CurrentTag))
	tag := esent_leaf_entry{}.Init(flags, data)
	return e.tagToRecord(c, tag.EntryData), nil
}

func lessThanLFS(record *Esent_record, column string, tag []byte, fixedSizeOffset *uint32, cRecord *esent_catalog_data_definition_entry) {
	//# Fixed Size column data type, still available data
	record.Column[column] = esent_recordVal{Typ: "Byt", BytVal: tag[*fixedSizeOffset:][:cRecord.Columns.SpaceUsage]}
	*fixedSizeOffset += cRecord.Columns.SpaceUsage
}

func variableDataType(cRecord *esent_catalog_data_definition_entry, tag []byte, vDataBytesProcessed *uint8, vsOffset uint16, prevItemLen *uint16, record *Esent_record, column string) {
	//  # Variable data type
	index := cRecord.Fixed.Identifier - 127 - 1
	itemLen := binary.LittleEndian.Uint16(tag[vsOffset+uint16(index)*2:][:2])
	if itemLen&0x8000 != 0 {
		//empty item
		itemLen = uint16(*prevItemLen)
		record.Column = nil
	} else {
		itemValue := tag[vsOffset+uint16(*vDataBytesProcessed):][:itemLen-*prevItemLen]
		record.Column[column] = esent_recordVal{Typ: "Byt", BytVal: itemValue}
		*vDataBytesProcessed += uint8(itemLen - *prevItemLen)
		*prevItemLen = itemLen
	}
}

func overtwofiddy(column string, record *Esent_record, cRecord *esent_catalog_data_definition_entry, taggedI *taggedItems, taggedItemsParsed *bool, vDataBytesProcessed uint8, vsOffset uint16, tag []byte, version, rev, pageSize uint32) {
	//check if parsed lol?
	if !*taggedItemsParsed && (uint16(vDataBytesProcessed)+vsOffset) < uint16(len(tag)) {
		index := uint16(vDataBytesProcessed) + vsOffset
		endOfVS := pageSize
		firstOffsetTag := (binary.LittleEndian.Uint16(tag[index+2:][:2]) & 0x3fff) + uint16(vDataBytesProcessed) + vsOffset
		for {
			taggedIdent := binary.LittleEndian.Uint16(tag[index:][:2])
			index += 2
			taggedOffset := (binary.LittleEndian.Uint16(tag[index:][:2]) & 0x3fff)
			var flagsPresent uint16
			/*
				if e.dbHeader.Version == 0x620 &&
					e.dbHeader.FileFormatRevision >= 17 && e.dbHeader.PageSize > 8192 {
			*/
			if version == 0x620 && rev >= 17 && pageSize > 8192 {
				flagsPresent = 1
			} else {
				flagsPresent = (binary.LittleEndian.Uint16(tag[index:][:2]) & 0x4000)
			}
			index += 2
			if uint32(taggedOffset) < endOfVS {
				endOfVS = uint32(taggedOffset)
			}
			taggedI.Add(tag_item{
				TaggedOffset: taggedOffset,
				TagLen:       uint16(len(tag)),
				Flags:        flagsPresent,
			}, taggedIdent)

			if index >= firstOffsetTag {
				break
			}
		}
		taggedI.Parse()
		*taggedItemsParsed = true

	}
	if cRecordItem, ok := taggedI.M[uint16(cRecord.Fixed.Identifier)]; ok {
		offsetItem := uint16(vDataBytesProcessed) + vsOffset + cRecordItem.TaggedOffset
		itemSize := cRecordItem.TagLen
		//if item has flags, skip for some reason?
		itemFlag := int16(0)
		if cRecordItem.Flags > 0 {
			itemFlag = int16(tag[offsetItem : offsetItem+1][0])
			offsetItem++
			itemSize--
		} else {
			itemFlag = 0
		}
		if itemFlag&TAGGED_DATA_TYPE_COMPRESSED != 0 {
			//log an error? idk
			delete(record.Column, column) // record.Column[column] = nil
		} else if itemFlag&TAGGED_DATA_TYPE_MULTI_VALUE != 0 {
			//todo parse mutli vals properly or something?
			//log an error??
			if itemSize > uint16(len(tag[offsetItem:])) {
				itemSize = uint16(len(tag[offsetItem:]))
			}
			dst := make([]byte, len(tag[offsetItem:][:itemSize])*2)
			hex.Encode(dst, tag[offsetItem:][:itemSize])

			record.Column[column] = esent_recordVal{
				Typ:    "Byt",
				BytVal: dst,
			}
		} else {
			if itemSize > uint16(len(tag))-offsetItem {
				itemSize = uint16(len(tag)) - offsetItem
			}
			record.Column[column] = esent_recordVal{Typ: "Byt", BytVal: tag[offsetItem:][:itemSize]}
		}
	} else {
		delete(record.Column, column) // record.Column[column] = nil
	}

}

func (e *Esedb) tagToRecord(c *Cursor, tag []byte) Esent_record {
	record := Esent_record{Column: make(map[string]esent_recordVal)}
	taggedI := taggedItems{M: make(map[uint16]tag_item), O: []uint16{}}
	taggedItemsParsed := false

	ddHeader := esent_data_definition_header{}
	buffer := bytes.NewBuffer(tag)
	err := binary.Read(buffer, binary.LittleEndian, &ddHeader)
	if err != nil {
		panic(err)
	}

	vDataBytesProcessed := (ddHeader.LastVariableDataType - 127) * 2
	prevItemLen := uint16(0)
	//tagLen := uint16(len(tag))
	fixedSizeOffset := uint32(4) //len ddheader
	vsOffset := ddHeader.VariableSizeOffset
	columns := c.TableData.Columns

	for _, column := range columns.keys {
		cRecord := columns.values[column].Record
		if cRecord.Fixed.Identifier <= uint32(ddHeader.LastFixedSize) {
			lessThanLFS(&record, column, tag, &fixedSizeOffset, &cRecord)
		} else if 127 < cRecord.Fixed.Identifier && cRecord.Fixed.Identifier <= uint32(ddHeader.LastVariableDataType) {
			variableDataType(&cRecord, tag, &vDataBytesProcessed, vsOffset, &prevItemLen, &record, column)
		} else if cRecord.Fixed.Identifier > 255 {
			overtwofiddy(column, &record, &cRecord, &taggedI, &taggedItemsParsed, vDataBytesProcessed, vsOffset, tag, e.dbHeader.Version, e.dbHeader.FileFormatRevision, e.pageSize)
		} else {
			delete(record.Column, column) // record.Column[column] = nil
		}

		/*
			    if type(record[column]) is tuple:
			# A multi value data, we won't decode it, just leave it this way
		*/
		if record.Column[column].Typ == "Tup" {
			t := record.Column[column].TupVal[0]
			record.Column[column] = esent_recordVal{Typ: "Byt", BytVal: t}
		}

		if cRecord.Columns.ColumnType == JET_coltypText || cRecord.Columns.ColumnType == JET_coltypLongText {
			//handle strings arapantly??
			if _, ok := record.Column[column]; ok { //not nil/empty
				if _, ok := e.StringCodePages[cRecord.Columns.CodePage]; !ok { //known decoding type
					panic("unknown codepage or something? idk")
				}
				//decode the thing aaaaaaa
				if cRecord.Columns.CodePage == 20127 { //ascii
					//v easy
					record.Column[column] = esent_recordVal{Typ: "Str", StrVal: string(record.Column[column].BytVal)}
				} else if cRecord.Columns.CodePage == 1200 { //unicode oh boy
					//unicode utf16le
					d := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
					b, err := d.Bytes(record.Column[column].BytVal)
					if err != nil {
						panic(err)
					}
					record.Column[column] = esent_recordVal{Typ: "Str", StrVal: string(b)}
				} else if cRecord.Columns.CodePage == 1252 {
					//fmt.Println("DO WESTERN!!", string(record.Column[column].BytVal))
					d := charmap.Windows1252.NewDecoder()
					b, err := d.Bytes(record.Column[column].BytVal)
					if err != nil {
						panic(err)
					}
					record.Column[column] = esent_recordVal{Typ: "Str", StrVal: string(b)}
					//western... idk yet
				} else {
					fmt.Println("UNKNOWN STRING?")
					panic("aa")
				}
				//stringDecoder = StringCodePages[columnRecord['CodePage']]
				//it's already a string, probably in a weird format... I'll deal with this later I Guess?
				//record.Column[column]
			}
		} else {
			record.Column[column] = esent_recordVal{}.Unpack(cRecord.Columns.ColumnType, record.Column[column].BytVal)
		}

	}
	return record
}

func (e *Esedb) addLeaf(l esent_leaf_entry) {
	ddHeader := esent_data_definition_header{}
	buffer := bytes.NewBuffer(l.EntryData)
	err := binary.Read(buffer, binary.LittleEndian, &ddHeader)
	if err != nil {
		panic(err)
	}

	catEntry, err := esent_catalog_data_definition_entry{}.Init(l.EntryData[4:])
	if err != nil {
		//can't parse the entry good, ignore it lol
		fmt.Println("SOME ADDLEAFE ERROR", err)
		return
	}

	itemName := e.parseItemName(l)

	//create table
	if catEntry.Fixed.Type == CATALOG_TYPE_TABLE {
		//t := newTable(string(itemName))
		///*
		t := table{}
		t.TableEntry = l
		t.Columns = &OrderedMap_cat_entry{values: make(map[string]cat_entry)}                  // make(map[string]cat_entry)
		t.Indexes = &OrderedMap_esent_leaf_entry{values: make(map[string]esent_leaf_entry)}    //make(map[string]esent_leaf_entry)
		t.Longvalues = &OrderedMap_esent_leaf_entry{values: make(map[string]esent_leaf_entry)} //make(map[string]esent_leaf_entry)
		//*/
		//longvals
		e.tables[string(itemName)] = t
		e.currentTable = string(itemName)
	} else if catEntry.Fixed.Type == CATALOG_TYPE_COLUMN {
		col := cat_entry{

			esent_leaf_entry: esent_leaf_entry{
				CommonPageKeySize: l.CommonPageKeySize,

				LocalPageKeySize: l.LocalPageKeySize,
				LocalPageKey:     l.LocalPageKey,
				EntryData:        l.EntryData,
			},
			Header: ddHeader,
			Record: catEntry,
		}
		//e.tables[e.currentTable].AddColumn(string(itemName))
		e.tables[e.currentTable].Columns.Add(string(itemName), col)

	} else if catEntry.Fixed.Type == CATALOG_TYPE_INDEX {

		//if e.tables[e.currentTable].Columns == nil {
		return
		//}
		//e.tables[e.currentTable].Indexes.Add(string(itemName), l)

	} else if catEntry.Fixed.Type == CATALOG_TYPE_LONG_VALUE {

		//if e.tables[e.currentTable].Columns == nil {
		//	return
		//}
		lvLen := binary.LittleEndian.Uint16(l.EntryData[ddHeader.VariableSizeOffset:][:2])
		lvName := []byte{}

		if len(l.EntryData[ddHeader.VariableSizeOffset:]) > 7 {
			lvName = l.EntryData[ddHeader.VariableSizeOffset:][7:][:lvLen]
		}
		e.tables[e.currentTable].Longvalues.Add(string(lvName), l)
		//e.tables[e.currentTable].AddData(string(lvName), l)

	} else {
		panic("lol idk during add item??????")
	}
}

func (e *Esedb) parseItemName(l esent_leaf_entry) []byte {
	ddHeader := esent_data_definition_header{}
	buffer := bytes.NewBuffer(l.EntryData)
	err := binary.Read(buffer, binary.LittleEndian, &ddHeader)
	if err != nil {
		panic(err)
	}
	entries := uint8(0)
	if ddHeader.LastVariableDataType > 127 {
		entries = ddHeader.LastVariableDataType - 127
	} else {
		entries = ddHeader.LastVariableDataType
	}
	entryLen := binary.LittleEndian.Uint16(l.EntryData[ddHeader.VariableSizeOffset:][:2])
	entryName := l.EntryData[ddHeader.VariableSizeOffset:][2*entries:][:entryLen]
	return entryName
}

func (e *Esedb) getMainHeader() esent_db_header {
	data := e.db.Read(0, int(e.pageSize))
	dbhd := esent_db_header{}
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.LittleEndian, &dbhd)
	if err != nil {
		panic(err)
	}
	return dbhd
}

//retreives a page of data from the file?
func (e *Esedb) getPage(pageNum uint32) esent_page {
	r := esent_page{}
	data := e.db.Read((int(pageNum)+1)*int(e.pageSize), int(e.pageSize))

	//for some reason python version ensures the page is full/
	//'while len(data) < pagesize' etc
	//I'm not sure that will ever happen if you're reading properly

	if pageNum <= 0 {
		panic("NOT ALLOWED TO READ FIRST PAGE AS THIS! USE GETDBHEADER OR WHATEVER IT WAS")
	}

	r.dbHeader = e.dbHeader
	r.data = data

	if data != nil {
		r.record = r.getHeader(data)
	}
	return r
}
