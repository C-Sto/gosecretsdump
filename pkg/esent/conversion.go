package esent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

func (e *Esedb) tagToRecord(c *Cursor, tag []byte) Esent_record {
	record := NewRecord(len(c.TableData.Columns.keys))
	//record := Esent_record{Column: make(map[string]*esent_recordVal, len(c.TableData.Columns.keys))}
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

	for i, column := range c.TableData.Columns.keys {
		cRecord := c.TableData.Columns.values[i].Record
		if cRecord.Fixed.Identifier <= uint32(ddHeader.LastFixedSize) {
			record.UpdateBytVal(tag[fixedSizeOffset:][:cRecord.Columns.SpaceUsage], column)
			fixedSizeOffset += cRecord.Columns.SpaceUsage
		} else if 127 < cRecord.Fixed.Identifier && cRecord.Fixed.Identifier <= uint32(ddHeader.LastVariableDataType) {
			variableDataType(&cRecord, tag, &vDataBytesProcessed, vsOffset, &prevItemLen, &record, column)
		} else if cRecord.Fixed.Identifier > 255 {
			overtwofiddy(column, &record, &cRecord, &taggedI, &taggedItemsParsed, vDataBytesProcessed, vsOffset, tag, e.dbHeader.Version, e.dbHeader.FileFormatRevision, e.pageSize)
		} else {
			record.DeleteColumn(column)
		}

		/*
			    if type(record[column]) is tuple:
			# A multi value data, we won't decode it, just leave it this way
		*/
		record.ConvTup(column)

		if cRecord.Columns.ColumnType == JET_coltypText || cRecord.Columns.ColumnType == JET_coltypLongText {
			record.SetString(column, cRecord.Columns.CodePage)
		} else {
			record.UnpackInline(column, cRecord.Columns.ColumnType)
			//record.Column[column].UnpackInline(cRecord.Columns.ColumnType)
			//v.UnpackInline(cRecord.Columns.ColumnType)
		}

	}
	return record
}

func variableDataType(cRecord *esent_catalog_data_definition_entry, tag []byte, vDataBytesProcessed *uint8, vsOffset uint16, prevItemLen *uint16, record *Esent_record, column string) {
	//  # Variable data type
	index := cRecord.Fixed.Identifier - 127 - 1
	itemLen := binary.LittleEndian.Uint16(tag[vsOffset+uint16(index)*2:][:2])
	if itemLen&0x8000 != 0 {
		//empty item
		itemLen = uint16(*prevItemLen)
		//record.Column = nil

	} else {

		record.UpdateBytVal(tag[vsOffset+uint16(*vDataBytesProcessed):][:itemLen-*prevItemLen], column)
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
			record.DeleteColumn(column)
			//delete(record.Column, column) // record.Column[column] = nil
		} else if itemFlag&TAGGED_DATA_TYPE_MULTI_VALUE != 0 {
			//todo parse mutli vals properly or something?
			//log an error??
			if itemSize > uint16(len(tag[offsetItem:])) {
				itemSize = uint16(len(tag[offsetItem:]))
			}
			buf := make([]byte, len(tag[offsetItem:][:itemSize])*2)
			hex.Encode(buf, tag[offsetItem:][:itemSize])

			record.UpdateBytVal(buf, column)

		} else {
			if itemSize > uint16(len(tag))-offsetItem {
				itemSize = uint16(len(tag)) - offsetItem
			}
			record.UpdateBytVal(tag[offsetItem:][:itemSize], column)
			//record.Column[column].UpdateBytVal(tag[offsetItem:][:itemSize])
		}
	} else {
		record.DeleteColumn(column)
		//delete(record.Column, column) // record.Column[column] = nil
	}

}
