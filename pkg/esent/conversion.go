package esent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

func (e *Esedb) tagToRecord(c *Cursor, tag []byte) Esent_record {
	record := NewRecord(len(c.TableData.Columns.keys))
	//record := Esent_record{Column: make(map[string]*esent_recordVal, len(c.TableData.Columns.keys))}
	taggedI := taggedItems{}
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
	for i := 0; i < len(c.TableData.Columns.keys); i++ {
		var val *esent_recordVal
		//for i, column := range c.TableData.Columns.keys {
		cRecord := &c.TableData.Columns.values[i].Record
		column := c.TableData.Columns.keys[i]
		//fmt.Println("VALB4", val, exists)
		if cRecord.Fixed.Identifier <= uint32(ddHeader.LastFixedSize) {
			if val == nil {
				val = record.GetRecord(column)
			}
			val.UpdateBytVal(tag[fixedSizeOffset:][:cRecord.Columns.SpaceUsage])
			//record.UpdateBytVal(tag[fixedSizeOffset:][:cRecord.Columns.SpaceUsage], column)
			fixedSizeOffset += cRecord.Columns.SpaceUsage
		} else if 127 < cRecord.Fixed.Identifier && cRecord.Fixed.Identifier <= uint32(ddHeader.LastVariableDataType) {
			//  # Variable data type
			index := cRecord.Fixed.Identifier - 127 - 1
			itemLen := binary.LittleEndian.Uint16(tag[vsOffset+uint16(index)*2:][:2])
			if itemLen&0x8000 != 0 {
				//empty item
				itemLen = uint16(prevItemLen)
				//record.Column = nil

			} else {
				if val == nil {
					val = record.GetNilRecord(column)
				}
				val.UpdateBytVal(tag[vsOffset+uint16(vDataBytesProcessed):][:itemLen-prevItemLen])
				//record.UpdateBytVal(tag[vsOffset+uint16(vDataBytesProcessed):][:itemLen-prevItemLen], column)
				vDataBytesProcessed += uint8(itemLen - prevItemLen)
				prevItemLen = itemLen
			}
		} else if cRecord.Fixed.Identifier > 255 {
			var cRecordItem *tag_item
			var ok bool
			if !taggedItemsParsed && (uint16(vDataBytesProcessed)+vsOffset) < uint16(len(tag)) {
				parseTaggedItems(vDataBytesProcessed, vsOffset, tag, e.dbHeader.Version, e.dbHeader.FileFormatRevision, pageSize, &taggedI, &taggedItemsParsed, uint16(cRecord.Fixed.Identifier), cRecordItem, &ok)
			}
			if !ok {
				for i := 0; i < len(taggedI.O); i++ {
					if uint16(cRecord.Fixed.Identifier) == taggedI.O[i] {
						cRecordItem = taggedI.M[i]
						ok = true
					}
				}
			}
			if ok && cRecordItem != nil {
				//if cRecordItem, ok = taggedI.M[uint16(cRecord.Fixed.Identifier)]; ok {
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
					//delete too slow
					//record.DeleteColumn(column)
				} else if itemFlag&TAGGED_DATA_TYPE_MULTI_VALUE != 0 {
					//todo parse mutli vals properly or something?
					//log an error??
					itemSize = uint16(len(tag[offsetItem:]))

					buf := make([]byte, len(tag[offsetItem:][:itemSize])*2)
					hex.Encode(buf, tag[offsetItem:][:itemSize])
					if val == nil {
						val = record.GetRecord(column)
					}
					val.UpdateBytVal(buf)
					//record.UpdateBytVal(buf, column)

				} else {
					if itemSize > uint16(len(tag))-offsetItem {
						itemSize = uint16(len(tag)) - offsetItem
					}
					if val == nil {
						val = record.GetRecord(column)
					}
					//record.UpdateBytVal(tag[offsetItem:offsetItem+itemSize], column)

					val.UpdateBytVal(tag[offsetItem:][:itemSize])
					//record.Column[column].UpdateBytVal(tag[offsetItem:][:itemSize])
				}
			}
		} else {
			//record.DeleteColumn(column)
		}

		/*
			    if type(record[column]) is tuple:
			# A multi value data, we won't decode it, just leave it this way
		*/
		if val != nil {
			//record.UnpackInline(column, cRecord.Columns)
			val.UnpackInline(cRecord.Columns)
		}
		//fmt.Println("after!", exists)
		//fmt.Println(record.GetRecord(column))
		//panic("cats")

	}
	return record
}

func parseTaggedItems(vDataBytesProcessed uint8, vsOffset uint16, tag []byte, version, rev, pageSize uint32, taggedI *taggedItems, taggedItemsParsed *bool, ident uint16, crecordItem *tag_item, ok *bool) {
	index := uint16(vDataBytesProcessed) + vsOffset //start index of the items to parse
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
		tagItem := tag_item{
			TaggedOffset: taggedOffset,
			TagLen:       uint16(len(tag)),
			Flags:        flagsPresent,
		}
		taggedI.Add(&tagItem, taggedIdent)

		if l := len(taggedI.O); l > 1 {
			taggedI.M[l-2].TagLen = taggedI.M[l-1].TaggedOffset - taggedI.M[l-2].TaggedOffset
		}

		if taggedIdent == ident { //uint16(cRecord.Fixed.Identifier)
			crecordItem = &tagItem
			*ok = true
		}
		if index >= firstOffsetTag {
			break
		}
	}
	*taggedItemsParsed = true
}
