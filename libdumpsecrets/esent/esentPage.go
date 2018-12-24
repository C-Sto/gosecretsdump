package esent

import (
	"encoding/binary"
	"fmt"
)

type esent_page struct {
	dbHeader esent_db_header
	data     []byte
	record   esent_page_header
}

func (p esent_page) getData(start, size int) []byte {
	//so that I can brain the pythonic indexing stuff
	//-1 in size indicates 'to the end'
	//negative start means 'len(data)+start'
	if start < 0 {
		start = len(p.data) + start
	}

	if size == -1 {
		size = len(p.data) - start
	}
	o := make([]byte, size)
	copy(o, p.data[start:start+size])
	return o
}

func (p esent_page) getHeader(inData []byte) esent_page_header {
	//decide on record type (ugh)
	data := make([]byte, len(inData))
	copy(data, inData)
	r := esent_page_header{}
	r.Len = 40 //all record lengths are 40, except the extended

	var err error
	if p.dbHeader.Version < 0x620 || (p.dbHeader.Version == 0x620 && p.dbHeader.FileFormatRevision < 0x0b) {
		//make it xp
		//r.recordType = "structure_2003_SP0"
		r.CheckSum = uint64(binary.LittleEndian.Uint32(data[:4]))
		data = data[4:]
		r.PageNumber = uint64(binary.LittleEndian.Uint32(data[:4]))
		data = data[4:]
	} else if p.dbHeader.Version == 0x620 && p.dbHeader.FileFormatRevision < 0x11 {
		//2k3 sp1 and later
		//r.recordType = "structure_0x620_0x0b"
		r.CheckSum = uint64(binary.LittleEndian.Uint32(data[:4]))
		data = data[4:]
		r.ECCCheckSum = binary.LittleEndian.Uint32(data[:4])
		data = data[4:]
	} else {
		//7 and later
		//r.recordType = "structure_win7"
		r.CheckSum = binary.LittleEndian.Uint64(data[:8])
		data = data[8:]
	}

	//do common (all)
	r.LastModificationTime = binary.LittleEndian.Uint64(data[:8])
	data = data[8:]
	r.PreviousPageNumber = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]
	r.NextPageNumber = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]
	r.FatherDataPage = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]
	r.AvailableDataSize = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	r.AvailableUncommittedDataSize = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	r.FirstAvailableDataOffset = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	r.FirstAvailablePageTag = binary.LittleEndian.Uint16(data[:2])
	data = data[2:]
	r.PageFlags = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]

	//check for extended
	if p.dbHeader.PageSize > 8192 {
		r.Len = 0
		fmt.Println("DO WIN 7 EXTENDED OK")
		panic("Not implemented")
		//do win7 extended
	}

	if err != nil {
		panic(err)
	}

	return r
}

func (p *esent_page) getTag(i int) (pageFlags uint16, tagData []byte) {
	if int(p.record.FirstAvailablePageTag) < i {
		panic("trying to grab tag??? 0x" + string(i))
	}
	baseOffset := p.record.Len
	//len(self.record) calls __len()__ on a Structure object, which just returns len(self.data).
	//I manually (print/echo debugging ftw) looked at the structures to work it out,
	//because doing len on a structure to work out how big it is is pita. It's 40, unless extended pagesize.

	//the tags are 4 bytes each, seek to the first avail pagetag and drop the data before the tag
	tags := p.getData(-4*int(p.record.FirstAvailablePageTag), -1)

	//we are only interested in a single tag (which appears to be specified from the end of the data structure?)
	// drop everyhing we don't care about
	for x := 0; x < i; x++ {
		tags = tags[:len(tags)-4]
	}
	//the tag should now be the last 4 bytes
	tag := tags[len(tags)-4:] //this can probably be unrolled and one-lined

	valsize := binary.LittleEndian.Uint16(tag[:2]) & 0x1fff
	pageFlags = (binary.LittleEndian.Uint16(tag[2:]) & 0xe000) >> 13
	valueOffset := binary.LittleEndian.Uint16(tag[2:]) & 0x1fff

	tagData = make([]byte, len(p.data[baseOffset+valueOffset:][:valsize]))
	copy(tagData, p.data[baseOffset+valueOffset:][:valsize])

	return pageFlags, tagData
}
