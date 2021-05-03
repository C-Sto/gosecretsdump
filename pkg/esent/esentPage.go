package esent

import (
	"encoding/binary"
	"fmt"
)

type esent_page struct {
	dbHeader esent_db_header
	data     []byte
	record   esent_page_header
	cached   bool
	//reads    uint64
}

// func (p esent_page) getData(start uint16, size int) []byte {
// 	//so that I can brain the pythonic indexing stuff
// 	//-1 in size indicates 'to the end'
// 	//negative start means 'len(data)+start'
// 	//fmt.Println(-4 * int(p.record.FirstAvailablePageTag))
// 	s := len(p.data) - int(start*4)

// 	if size == -1 {
// 		return p.data[s:] // size = len(p.data) - start
// 	}
// 	//o := make([]byte, size)
// 	//copy(o, p.data[start:start+size])
// 	return p.data[s : int(start)+size]
// }

func (p *esent_page) getHeader() error {
	//decide on record type (ugh)
	p.record = esent_page_header{}
	//data := make([]byte, len(inData))
	//copy(data, inData)
	p.record.Len = 40 //all record lengths are 40, except the extended
	cursor := 0

	if p.dbHeader.Version < 0x620 || (p.dbHeader.Version == 0x620 && p.dbHeader.FileFormatRevision < 0x0b) {
		//make it xp
		//r.recordType = "structure_2003_SP0"
		p.record.CheckSum = uint64(binary.LittleEndian.Uint32(p.data[cursor : cursor+4]))
		//data = data[4:]
		cursor += 4
		p.record.PageNumber = uint64(binary.LittleEndian.Uint32(p.data[cursor : cursor+4]))
		cursor += 4
	} else if p.dbHeader.Version == 0x620 && p.dbHeader.FileFormatRevision < 0x11 {
		//2k3 sp1 and later
		//r.recordType = "structure_0x620_0x0b"
		p.record.CheckSum = uint64(binary.LittleEndian.Uint32(p.data[cursor : cursor+4]))
		cursor += 4
		p.record.ECCCheckSum = binary.LittleEndian.Uint32(p.data[cursor : cursor+4])
		cursor += 4
	} else {
		//7 and later
		//r.recordType = "structure_win7"
		p.record.CheckSum = binary.LittleEndian.Uint64(p.data[cursor : cursor+8])
		//data = data[8:]
		cursor += 8
	}

	//do common (all)
	p.record.LastModificationTime = binary.LittleEndian.Uint64(p.data[cursor : cursor+8])
	cursor += 8
	p.record.PreviousPageNumber = binary.LittleEndian.Uint32(p.data[cursor : cursor+4])
	cursor += 4
	p.record.NextPageNumber = binary.LittleEndian.Uint32(p.data[cursor : cursor+4])
	cursor += 4
	p.record.FatherDataPage = binary.LittleEndian.Uint32(p.data[cursor : cursor+4])
	cursor += 4
	p.record.AvailableDataSize = binary.LittleEndian.Uint16(p.data[cursor : cursor+2])
	cursor += 2
	p.record.AvailableUncommittedDataSize = binary.LittleEndian.Uint16(p.data[cursor : cursor+2])
	cursor += 2
	p.record.FirstAvailableDataOffset = binary.LittleEndian.Uint16(p.data[cursor : cursor+2])
	cursor += 2
	p.record.FirstAvailablePageTag = binary.LittleEndian.Uint16(p.data[cursor : cursor+2])
	cursor += 2
	p.record.PageFlags = binary.LittleEndian.Uint32(p.data[cursor : cursor+4])
	cursor += 4

	//check for extended
	if p.dbHeader.PageSize > 8192 {
		p.record.Len = 0
		return fmt.Errorf("not implemented: windows 7 extended")
		//do win7 extended
	}
	return nil
}

func (p *esent_page) getTag(i int) (pageFlags uint16, tagData []byte, err error) {
	if int(p.record.FirstAvailablePageTag) < i {
		return 0, nil, fmt.Errorf("trying to grab tag??? 0x%x", i)
	}
	//len(self.record) calls __len()__ on a Structure object, which just returns len(self.data).
	//I manually (print/echo debugging ftw) looked at the structures to work it out,
	//because doing len on a structure to work out how big it is is pita. It's 40, unless extended pagesize.

	//the tags are 4 bytes each, seek to the first avail pagetag and drop the data before the tag
	startIndex := len(p.data) - int(4*(i+1))
	tag := p.data[startIndex : startIndex+4]

	valsize := binary.LittleEndian.Uint16(tag[:2]) & 0x1fff
	pageFlags = (binary.LittleEndian.Uint16(tag[2:]) & 0xe000) >> 13
	valueOffset := binary.LittleEndian.Uint16(tag[2:]) & 0x1fff

	tagData = p.data[p.record.Len+valueOffset:][:valsize]
	//copy(tagData, p.data[p.record.Len+valueOffset:][:valsize])

	return pageFlags, tagData, nil
}
