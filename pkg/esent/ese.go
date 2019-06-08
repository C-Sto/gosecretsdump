package esent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
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
}

var stringCodePages = map[uint32]string{
	1200:  "utf-16le",
	20127: "ascii",
	1252:  "cp1252",
} //standin for const lookup/enum thing

func (e Esedb) Init(fn string) Esedb {
	//create the esedb structure
	r := Esedb{
		filename: fn,
		pageSize: pageSize,
		tables:   make(map[string]table),
		isRemote: false,
	}

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

		if e.tables[e.currentTable].Columns == nil {
			return
		}
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
