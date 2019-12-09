package ntfsdump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"

	"github.com/c-sto/gosecretsdump/pkg/logger"
	"golang.org/x/text/encoding/unicode"
)

//this has primarily been ported from https://github.com/kusano/ntfsdump/blob/master/ntfsdump.cpp

type FileNameMetadata struct {
	ParentDirectory, DateCreated,
	DateModified, DateMFTModified,
	DateAccessed, LogicalSize,
	DiskSize int64
	Flag, ReparseValue   uint32
	NameLength, NameType byte
}

type FileName struct {
	Metadata FileNameMetadata
	Name     []byte
}

func NewFileName(b []byte) FileName {
	ret := FileName{}
	buff := bytes.NewReader(b)
	binary.Read(buff, binary.LittleEndian, &ret.Metadata)
	ret.Name = make([]byte, ret.Metadata.NameLength*2)
	buff.Read(ret.Name)
	//logger.Logger.Sugar().Infof("%+v %s", ret, ret.Name)
	return ret
}

type RecordHeader struct {
	Signature [4]byte
	UpdateOffset,
	UpdateNumber uint16
	LogFile int64
	SequenceNumber,
	HardLinkCount,
	AttributeOffset,
	Flag uint16
	UsedSize,
	AllocatedSize uint32
	BaseRecord      int64
	NextAttributeID uint16
	Unsed           [2]byte
	MFTRecord       uint32
}

type Run struct {
	Offset int64
	Length int64
}

func Test() {
	l := logger.Logger.Sugar()
	// Open
	//p, err := syscall.UTF16PtrFromString("\\\\?\\c:")
	drive := []byte("\\\\?\\_:")
	drive[4] = 'c'

	l.Info("sent", string(drive), "to thing")
	//p, err := syscall.UTF16PtrFromString(string(drive))
	p, err := syscall.UTF16PtrFromString("\\\\?\\c:")
	if err != nil {
		panic(err)
	}

	x, err := syscall.CreateFile(
		p,                    //filename
		syscall.GENERIC_READ, //desiredaccess
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, //sharemode
		nil,                   //security attribs
		syscall.OPEN_EXISTING, //creation disposition
		0,                     //flags and attribs
		0)                     //templatefile

	if err != nil {
		l.Panic(err)
	}

	l.Info("Got file handle: ", x)
	//x := syscall.Handle(r0)

	syscall.SetFilePointer(x, 0, new(int32), syscall.FILE_BEGIN)

	lolbytes := [0x200]byte{}
	loldone := new(uint32)
	e := syscall.ReadFile(
		x,
		lolbytes[:],
		loldone,
		nil)
	if e != nil {
		l.Panic(e)
	}
	sec := BootSector{}
	binary.Read(bytes.NewReader(lolbytes[:]), binary.LittleEndian, &sec)
	//fmt.Printf("\n%+v\n", sec)
	l.Infof("%s", string(sec.OEMID[:]))
	/*if (memcmp(bootSector.oemID, "NTFS    ", 8) != 0)
	  throw _T("Volume is not NTFS");*/
	if !bytes.HasPrefix(sec.OEMID[:], []byte("NTFS")) {
		l.Panic("Not NTFS")
	}
	clusterSize := sec.BytePerSector * uint16(sec.SectorPerCluster)
	recordSize := uint16(1 << -sec.ClusterPerRecord)
	if sec.ClusterPerRecord > 0 {
		recordSize = uint16(sec.ClusterPerRecord) * clusterSize
	}
	totalCluster := sec.TotalSector / int64(sec.SectorPerCluster)

	l.Infof("Byte/Sec: %x", sec.BytePerSector)
	l.Infof("Sector/Cluster: %x", sec.SectorPerCluster)
	l.Infof("Total Sector: %x", sec.TotalSector)
	l.Infof("Cluster of MFT: %x", sec.MFTCluster)
	l.Infof("Cluster/Record: %x", sec.ClusterPerRecord)
	l.Infof("Cluster Size: %x", clusterSize)
	l.Infof("Record Size: %x", recordSize)
	l.Infof("TotalCluster: %x", totalCluster)

	MFTRunList := []Run{}
	MFTSize := int64(0)
	MFTStage := readRunList(
		x,
		0,
		0x80,
		[]Run{Run{int64(sec.MFTCluster), 24 * int64(recordSize) / int64(clusterSize)}},
		recordSize,
		clusterSize,
		sec.BytePerSector,
		totalCluster,
		&MFTRunList,
		&MFTSize,
	)
	l.Info(MFTRunList)
	l.Infof("MFTSTAGE: %d", MFTStage)
	if MFTStage == 0 || MFTStage == 1 {
		l.Errorf("MFT stage is %d (expecting above 1)", MFTStage)
	}
	l.Infof("MFT Size: %d", MFTSize)
	recordNumber := MFTSize / int64(recordSize)
	l.Infof("Record Number: %d", recordNumber)
	l.Infof("MFT runlist: %d", len(MFTRunList))
	for _, run := range MFTRunList {
		l.Infof("  %16x %16x", run.Offset, run.Length)
	}

	l.Info("Reading file list, beacause why not:")
	record := make([]byte, recordSize)
	rh := RecordHeader{}
	binary.Read(bytes.NewReader(record), binary.LittleEndian, &rh)
	for ri := int64(0); (ri < recordNumber) && ri < 10; ri++ {
		tmpStr := strings.Builder{}
		tmpStr.WriteString(fmt.Sprintf("%12d", ri))
		//l.Infof("%12d", ri)
		//try
		e := readRecord(x, ri, MFTRunList, recordSize, clusterSize, sec.BytePerSector, record)
		if e != nil {
			panic(e) //\l.Error(e)
		}
		binary.Read(bytes.NewReader(record), binary.LittleEndian, &rh)
		/* if (memcmp(recordHeader->signature, "FILE", 4) !=  0)
						   {
						       _tprintf(_T(" -\n"));
						       continue;
		                   }*/
		if !bytes.HasPrefix(rh.Signature[:], []byte("FILE")) {
			l.Infof(tmpStr.String() + " -")
			continue
		}
		if rh.BaseRecord != 0 {
			l.Infof(tmpStr.String()+"  Extension for %d", rh.BaseRecord&0xffffffffffff)
			continue
		}
		//tmpStr.Reset()
		switch rh.Flag {
		case 0:
			tmpStr.WriteString(" x    ")
		case 1:
			tmpStr.WriteString("      ")
		case 2:
			tmpStr.WriteString(" x dir")
		case 3:
			tmpStr.WriteString("   dir")
		default:
			tmpStr.WriteString(" ?????")

		}

		tmpBuf := findAttribute(&rh, recordSize, 0x30,
			record,
			func(a []byte) bool {
				nm := AttributeHeader{}
				binary.Read(bytes.NewReader(a), binary.LittleEndian, &nm)
				//l.Infof("%+v", nm)
				if nm.NRFlag != 0 {
					l.Error("Non resident filename I guess")
				}
				fn := NewFileName(a[nm.NameOffset:])
				return fn.Metadata.NameType != 0x02
			},
		)
		name := AttributeHeader{}
		binary.Read(bytes.NewReader(tmpBuf), binary.LittleEndian, &name)
		content := NewFileName(tmpBuf[name.NameOffset:])
		strval, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(content.Name)
		l.Infof(tmpStr.String()+" %s (%d)", strval, name.AttributeID)
	}

}

func parseRunList(runlist []byte, rlSize uint32, totalCluster int64) []Run {
	res := []Run{}
	p := 0
	offset := int64(0)
	logger.Logger.Sugar().Infof("%x", runlist[:50])
	for runlist[p] != 0x00 {
		lenLength := int(runlist[p] & 0xf)
		lenOffset := int(runlist[p] >> 4)
		p++
		logger.Logger.Sugar().Infof("%x", runlist[p:p+10])
		if lenLength > 8 {
			logger.Logger.Sugar().Panic("length not understood")
		}
		lng := int64(0)
		for i := uint64(0); i < uint64(lenLength); i++ {
			lng |= int64(runlist[p]) << (8 * i)
			p++
		}
		logger.Logger.Sugar().Infof("%x", runlist[p:p+10])
		offdiff := int64(0)
		for i := uint64(0); i < uint64(lenOffset); i++ {
			offdiff |= int64(runlist[p]) << (8 * i)
			logger.Logger.Sugar().Infof("%x %x", offdiff, runlist[p])
			p++
		}
		logger.Logger.Sugar().Infof("%x", runlist[p:p+10])
		//if offdiff >= (uint64(1) << ((lenOffset * 8) - 1)) {
		//	offdiff -= uint64(1) << (lenOffset * 8)
		//}
		offset += offdiff
		if offset < 0 || totalCluster <= int64(offset) {
			logger.Logger.Sugar().Errorf("Invalid data run: total cluster %d offset %d", totalCluster, offset)
		}
		logger.Logger.Sugar().Infof("adding run offset: %x length: %x", offset, lng)
		res = append(res, Run{Offset: offset, Length: lng})
	}
	return res
}

func readRunList(h syscall.Handle, recordIndex int64, typeID uint16, MFTRunList []Run, recordSize uint16, clusterSize uint16, sectorSize uint16, totalCluster int64, runList *[]Run, contentSize *int64) int {
	record := make([]byte, recordSize)
	readRecord(h, recordIndex, MFTRunList, recordSize, clusterSize, sectorSize, record)
	rh := RecordHeader{}
	binary.Read(bytes.NewReader(record), binary.LittleEndian, &rh)
	logger.Logger.Sugar().Infof("%+v", rh)
	tmpBuff := findAttribute(&rh, recordSize, 0x20, record, func([]byte) bool { return true })
	stage := 0
	logger.Logger.Sugar().Info("tmp buff len:", len(tmpBuff))
	if tmpBuff == nil {
		logger.Logger.Sugar().Infof("Null NR attrlist %x", typeID)
		//record = make([]byte, recordSize)
		tmpBuff = findAttribute(&rh, recordSize, typeID, record, func([]byte) bool { return true })
		if tmpBuff == nil {
			return 0
		}
		attrHeader := AttributeHeader{}
		binary.Read(bytes.NewReader(tmpBuff), binary.LittleEndian, &attrHeader)
		if attrHeader.NRFlag == 0 {
			stage = 1
		} else {
			nrHeader := AttributeHeaderNonResident{}
			binary.Read(bytes.NewReader(tmpBuff), binary.LittleEndian, &nrHeader)
			logger.Logger.Sugar().Infof("%+v", nrHeader)
			stage = 2 //non resident??
			*runList = parseRunList(
				tmpBuff[nrHeader.DataRunOffset:],
				uint32(nrHeader.AttributeHeader.Length-uint32(nrHeader.DataRunOffset)),
				totalCluster,
			)
			if contentSize != nil {
				*contentSize = nrHeader.RealSize
			}
		}
	} else {
		logger.Logger.Panic("Not yet implemented")
	}

	return stage
}

func readRecord(h syscall.Handle, recordIndex int64, MFTRunList []Run, recordSize uint16, clusterSize uint16, sectorSize uint16, buffer []byte) error {
	logger.Logger.Sugar().Infof("READING RECORD %d", recordIndex)
	sectorOffset := recordIndex * int64(recordSize) / int64(sectorSize)
	sectornumber := recordSize / sectorSize
	for sector := uint16(0); sector < sectornumber; sector++ {
		cluster := int64(sectorOffset+int64(sector)) / int64(clusterSize/sectorSize)
		vcn := int64(0)
		offset := int64(-1)

		for _, run := range MFTRunList {
			if cluster < vcn+run.Length {
				offset = (run.Offset+cluster-vcn)*int64(clusterSize) + int64(sectorOffset+int64(sector))*int64(sectorSize)%int64(clusterSize)
				break
			}
			vcn += run.Length
		}
		if offset == -1 {
			return fmt.Errorf("Unable to read file record")
		}
		seek(h, offset)
		var read uint32
		e := syscall.ReadFile(h, buffer[sector*sectorSize:(sector*sectorSize)+sectorSize], &read, nil)
		//logger.Logger.Sugar().Info("Bytes Read: ", read)
		if e != nil {
			return e
		}
	}
	fixRecord(buffer, recordSize, sectorSize)
	return nil
}

func findAttribute(record *RecordHeader, recordSize, typeID uint16, buffer []byte, condition func([]byte) bool) []byte {
	p := uint32(record.AttributeOffset)
	for {
		//logger.Logger.Sugar().Infof("P: %d, %d", p, len(buffer))
		//sizeof (AttributeHeaderR) = 16 bytes
		if p+16 > uint32(len(buffer)) {
			break
		}
		hdr := AttributeHeader{}
		binary.Read(bytes.NewReader(buffer[p:]), binary.LittleEndian, &hdr)
		//logger.Logger.Sugar().Infof("hdr %+v", hdr)
		//logger.Logger.Sugar().Infof("byts: %+v", buffer[p:])

		if hdr.TypeID == 0xffffffff {
			break
		}
		if hdr.TypeID == uint32(typeID) &&
			p+hdr.Length <= uint32(recordSize) &&
			condition(buffer[p:]) {
			return buffer[p:]
		}
		p += hdr.Length
	}
	return nil
}

func fixRecord(buffer []byte, recordSize uint16, sectorSize uint16) {
	header := RecordHeader{}
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &header)
	/*
	   Read the record from disk
	   Check the magic number is correct
	   Read the Update Sequence Number
	   Compare it against the last two bytes of every sector
	   Copy the contents of the Update Sequence Array to the correct places
	*/
	for i := uint16(1); i <= 8; i++ {
		targSec := i * sectorSize
		if 0 == bytes.Compare(buffer[targSec-2:targSec], buffer[header.UpdateOffset:header.UpdateOffset+2]) {
			buffer[targSec-2] = buffer[header.UpdateOffset+(i*2)]
			buffer[targSec-1] = buffer[header.UpdateOffset+(i*2)+1]

		}
		//logger.Logger.Sugar().Infof("Sec: %x last: %x fixup: %x real: %x fixed: %x %x ",
		//targSec,
		//buffer[targSec-2:targSec],
		//buffer[header.UpdateOffset:header.UpdateOffset+2],
		//buffer[header.UpdateOffset+(i*2):header.UpdateOffset+(i*2)+2],
		//buffer[targSec-2], buffer[header.UpdateOffset+(i*2)],
		//)
	}
}

func seek(h syscall.Handle, position int64) {
	newl, e := syscall.Seek(h, position, 0)
	if e != nil {
		logger.Logger.Sugar().Panic("Seek error", e)
	}
	if newl != position {
		logger.Logger.Sugar().Error("Seek position not the same?", newl, position)
	}
}
