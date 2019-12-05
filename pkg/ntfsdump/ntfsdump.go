package ntfsdump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/c-sto/gosecretsdump/pkg/logger"
	"go.uber.org/zap"
)

//this has primarily been ported from https://github.com/kusano/ntfsdump/blob/master/ntfsdump.cpp

type BootSector struct {
	Jump             [3]byte
	OEMID            [8]byte
	BytePerSector    uint16
	SectorPerCluster uint8
	Reserved         [2]byte
	Zero1            [3]byte
	Unused1          [2]byte
	MediaDescriptor  byte
	Zeros2           [2]byte
	SectorPerTrack   uint16
	HeadNumber       uint16
	HiddenSector     uint32
	Unused2          [8]byte
	TotalSector      uint64
	MFTCluster       int64
	MFTMirrCluster   uint64
	ClusterPerRecord int8
	Unused3          [3]byte
	ClusterPerBlock  int8
	Unused4          [3]byte
	SerialNumber     uint64
	CheckSum         uint32
	BootCode         [0x1aa]byte
	EndMarker        [2]byte
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

	fmt.Println("sent", string(drive), "to thing")
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
		panic(err)
	}
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
		panic(e)
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
	totalCluster := sec.TotalSector / uint64(sec.SectorPerCluster)

	l.Infof("Byte/Sec: %d", sec.BytePerSector)
	l.Infof("Sector/Cluster: %d", sec.SectorPerCluster)
	l.Infof("Total Sector: %d", sec.TotalSector)
	l.Infof("Cluster of MFT: %d", sec.MFTCluster)
	l.Infof("Cluster/Record: %d", sec.ClusterPerRecord)
	l.Infof("Cluster Size: %d", clusterSize)
	l.Infof("Record Size: %d", recordSize)
	l.Infof("TotalCluster: %d", totalCluster)

	MFTRunList := []Run{Run{sec.MFTCluster, 24 * int64(recordSize) / int64(clusterSize)}}
	MFTSize := uint64(0)
	MFTStage := readRunList(
		x,
		0,
		0x80,
		MFTRunList,
		recordSize,
		clusterSize,
		sec.BytePerSector,
		totalCluster,
		MFTRunList,
		&MFTSize,
	)
	l.Infof("MFTSTAGE: %d", MFTStage)

}

func readRunList(h syscall.Handle, recordIndex uint64, typeID uint16, MFTRunList []Run, recordSize uint16, clusterSize uint16, sectorSize uint16, totalCluster uint64, runList []Run, contentSize *uint64) int {

	record := make([]byte, recordSize)
	readRecord(h, recordIndex, MFTRunList, recordSize, clusterSize, sectorSize, record)

	return 0
}

func readRecord(h syscall.Handle, recordIndex uint64, MFTRunList []Run, recordSize uint16, clusterSize uint16, sectorSize uint16, buffer []byte) {
	sectorOffset := recordIndex * uint64(recordSize) / uint64(sectorSize)
	sectornumber := recordSize / sectorSize
	for sector := uint16(0); sector < sectornumber; sector++ {
		cluster := int64(sectorOffset+uint64(sector)) / int64(clusterSize/sectorSize)
		vcn := int64(0)
		offset := int64(-1)

		for _, run := range MFTRunList {
			if cluster < vcn+run.Length {
				offset = (run.Offset+cluster-vcn)*int64(clusterSize) + int64(sectorOffset+uint64(sector))*int64(sectorSize)%int64(clusterSize)
				break
			}
			vcn += run.Length
		}
		if offset == -1 {
			zap.S().Panic("Aaaaa")
		}
		seek(h, int32(offset))
		var read uint32
		e := syscall.ReadFile(h, buffer[sector*sectorSize:(sector*sectorSize)+sectorSize], &read, nil)
		logger.Logger.Sugar().Info("Bytes Read: ", read)
		if e != nil {
			logger.Logger.Error(e.Error())
		}
	}
	fixRecord(buffer, recordSize, sectorSize)

}

func findAttribute(record *RecordHeader, recordSize, typeID uint16, condition func([]byte) bool) {

}

func fixRecord(buffer []byte, recordSize uint16, sectorSize uint16) {
	header := RecordHeader{}
	binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &header)
	logger.Logger.Sugar().Infof("%+v", header)
}

func seek(h syscall.Handle, position int32) {
	var res int32
	_, e := syscall.SetFilePointer(h, position, &res, 1)
	if e != nil {
		logger.Logger.Sugar().Panic(e)
	}
}

/*
struct BootSector
{
    BYTE        jump[3];
    BYTE        oemID[8];
    WORD        bytePerSector;
    BYTE        sectorPerCluster;
    BYTE        reserved[2];
    BYTE        zero1[3];
    BYTE        unused1[2];
    BYTE        mediaDescriptor;
    BYTE        zeros2[2];
    WORD        sectorPerTrack;
    WORD        headNumber;
    DWORD       hiddenSector;
    BYTE        unused2[8];
    LONGLONG    totalSector;
    LONGLONG    MFTCluster;
    LONGLONG    MFTMirrCluster;
    signed char clusterPerRecord;
    BYTE        unused3[3];
    signed char clusterPerBlock;
    BYTE        unused4[3];
    LONGLONG    serialNumber;
    DWORD       checkSum;
    BYTE        bootCode[0x1aa];
    BYTE        endMarker[2];
};

struct RecordHeader
{
    BYTE        signature[4];
    WORD        updateOffset;
    WORD        updateNumber;
    LONGLONG    logFile;
    WORD        sequenceNumber;
    WORD        hardLinkCount;
    WORD        attributeOffset;
    WORD        flag;
    DWORD       usedSize;
    DWORD       allocatedSize;
    LONGLONG    baseRecord;
    WORD        nextAttributeID;
    BYTE        unsed[2];
    DWORD       MFTRecord;
};

struct AttributeHeaderR
{
    DWORD       typeID;
    DWORD       length;
    BYTE        formCode;
    BYTE        nameLength;
    WORD        nameOffset;
    WORD        flag;
    WORD        attributeID;
    DWORD       contentLength;
    WORD        contentOffset;
    WORD        unused;
};

struct AttributeHeaderNR
{
    DWORD       typeID;
    DWORD       length;
    BYTE        formCode;
    BYTE        nameLength;
    WORD        nameOffset;
    WORD        flag;
    WORD        attributeID;
    LONGLONG    startVCN;
    LONGLONG    endVCN;
    WORD        runListOffset;
    WORD        compressSize;
    DWORD       zero;
    LONGLONG    contentDiskSize;
    LONGLONG    contentSize;
    LONGLONG    initialContentSize;
};

struct FileName
{
    LONGLONG    parentDirectory;
    LONGLONG    dateCreated;
    LONGLONG    dateModified;
    LONGLONG    dateMFTModified;
    LONGLONG    dateAccessed;
    LONGLONG    logicalSize;
    LONGLONG    diskSize;
    DWORD       flag;
    DWORD       reparseValue;
    BYTE        nameLength;
    BYTE        nameType;
    BYTE        name[1];
};

struct AttributeRecord
{
    DWORD       typeID;
    WORD        recordLength;
    BYTE        nameLength;
    BYTE        nameOffset;
    LONGLONG    lowestVCN;
    LONGLONG    recordNumber;
    WORD        sequenceNumber;
    WORD        reserved;
};

#pragma pack(pop)

struct Run
{
    LONGLONG    offset;
    LONGLONG    length;
    Run(): offset(0LL), length(0LL) {}
    Run(LONGLONG offset, LONGLONG length): offset(offset), length(length) {}
};

void seek(HANDLE h, ULONGLONG position)
{
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)position;

    LARGE_INTEGER result;
    if (!SetFilePointerEx(h, pos, &result, SEEK_SET) ||
        pos.QuadPart != result.QuadPart)
        throw "Failed to seek";
}

LPBYTE findAttribute(RecordHeader *record, DWORD recordSize, DWORD typeID,
    function<bool(LPBYTE)> condition = [&](LPBYTE){return true;})
{
    LPBYTE p = LPBYTE(record) + record->attributeOffset;
    while (true)
    {
        if (p + sizeof (AttributeHeaderR) > LPBYTE(record) + recordSize)
            break;

        AttributeHeaderR *header = (AttributeHeaderR *)p;
        if (header->typeID == 0xffffffff)
            break;

        if (header->typeID == typeID &&
            p + header->length <= LPBYTE(record) + recordSize &&
            condition(p))
            return p;

        p += header->length;
    }
    return NULL;
}

vector<Run> parseRunList(BYTE *runList, DWORD runListSize, LONGLONG totalCluster)
{
    vector<Run> result;

    LONGLONG offset = 0LL;

    LPBYTE p = runList;
    while (*p != 0x00)
    {
        if (p + 1 > runList + runListSize)
            throw _T("Invalid data run");

        int lenLength = *p&0xf;
        int lenOffset = *p>>4;
        p++;

        if (p + lenLength + lenOffset > runList + runListSize ||
            lenLength >= 8  ||
            lenOffset >= 8)
            throw _T("Invalid data run");

        if (lenOffset == 0)
            throw _T("Sparse file is not supported");

        ULONGLONG length = 0;
        for (int i=0; i<lenLength; i++)
            length |= *p++ << (i*8);

        LONGLONG offsetDiff = 0;
        for (int i=0; i<lenOffset; i++)
            offsetDiff |= *p++ << (i*8);
        if (offsetDiff >= (1LL<<((lenOffset*8)-1)))
            offsetDiff -= 1LL<<(lenOffset*8);

        offset += offsetDiff;

        if (offset<0 || totalCluster<=offset)
            throw _T("Invalid data run");

        result.push_back(Run(offset, length));
    }

    return result;
}

void fixRecord(BYTE *buffer, DWORD recordSize, DWORD sectorSize)
{
    RecordHeader *header = (RecordHeader *)buffer;
    LPWORD update = LPWORD(buffer + header->updateOffset);

    if (LPBYTE(update + header->updateNumber) > buffer + recordSize)
        throw _T("Update sequence number is invalid");

    for (int i=1; i<header->updateNumber; i++)
        *LPWORD(buffer + i*sectorSize - 2) = update[i];
}

void readRecord(HANDLE h, LONGLONG recordIndex, const vector<Run> &MFTRunList,
    DWORD recordSize, DWORD clusterSize, DWORD sectorSize, BYTE *buffer)
{
    LONGLONG sectorOffset = recordIndex * recordSize / sectorSize;
    DWORD sectorNumber = recordSize / sectorSize;

    for (DWORD sector=0; sector<sectorNumber; sector++)
    {
        LONGLONG cluster = (sectorOffset + sector) / (clusterSize / sectorSize);
        LONGLONG vcn = 0LL;
        LONGLONG offset = -1LL;

        for (const Run &run: MFTRunList)
        {
            if (cluster < vcn + run.length)
            {
                offset = (run.offset + cluster - vcn) * clusterSize
                    + (sectorOffset + sector) * sectorSize % clusterSize;
                break;
            }
            vcn += run.length;
        }
        if (offset == -1LL)
            throw _T("Failed to read file record");

        seek(h, offset);
        DWORD read;
        if (!ReadFile(h, buffer+sector*sectorSize, sectorSize, &read, NULL) ||
            read != sectorSize)
            throw _T("Failed to read file record");
    }

    fixRecord(buffer, recordSize, sectorSize);
}

//  read a run list of typeID of recordIndex
//  return stage of the attribute
int readRunList(HANDLE h, LONGLONG recordIndex, DWORD typeID,
    const vector<Run> &MFTRunList, DWORD recordSize, DWORD clusterSize,
    DWORD sectorSize, LONGLONG totalCluster, vector<Run> *runList,
    LONGLONG *contentSize=NULL)
{
    vector<BYTE> record(recordSize);
    readRecord(h, recordIndex, MFTRunList, recordSize, clusterSize, sectorSize,
        &record[0]);

    RecordHeader *recordHeader = (RecordHeader *)&record[0];
    AttributeHeaderNR *attrListNR = (AttributeHeaderNR *)findAttribute(
        recordHeader, recordSize, 0x20);    //  $Attribute_List

    int stage = 0;

    if (attrListNR == NULL)
    {
        //  no attribute list
        AttributeHeaderNR *headerNR = (AttributeHeaderNR *)findAttribute(
            recordHeader, recordSize, typeID);
        if (headerNR == NULL)
            return 0;

        if (headerNR->formCode == 0)
        {
            //  the attribute is resident
            stage = 1;
        }
        else
        {
            //  the attribute is non-resident
            stage = 2;

            vector<Run> runListTmp = parseRunList(
                LPBYTE(headerNR) + headerNR->runListOffset,
                headerNR->length - headerNR->runListOffset, totalCluster);

            runList->resize(runListTmp.size());
            for (size_t i=0; i<runListTmp.size(); i++)
                (*runList)[i] = runListTmp[i];

            if (contentSize != NULL)
                *contentSize = headerNR->contentSize;
        }
    }
    else
    {
        vector<BYTE> attrListData;

        if (attrListNR->formCode == 0)
        {
            //  attribute list is resident
            stage = 3;

            AttributeHeaderR *attrListR = (AttributeHeaderR *)attrListNR;
            attrListData.resize(attrListR->contentLength);
            memcpy(
                &attrListData[0],
                LPBYTE(attrListR) + attrListR->contentOffset,
                attrListR->contentLength);
        }
        else
        {
            //  attribute list is non-resident
            stage = 4;

            if (attrListNR->compressSize != 0)
                throw _T("Compressed non-resident attribute list is not "
                    "supported");

            vector<Run> attrRunList = parseRunList(
                LPBYTE(attrListNR) + attrListNR->runListOffset,
                attrListNR->length - attrListNR->runListOffset, totalCluster);

            attrListData.resize(attrListNR->contentSize);
            vector<BYTE> cluster(clusterSize);
            LONGLONG p = 0;
            for (Run &run: attrRunList)
            {
                //  some clusters are reserved
                if (p >= attrListNR->contentSize)
                    break;

                seek(h, run.offset*clusterSize);
                for (LONGLONG i=0; i<run.length && p<attrListNR->contentSize; i++)
                {
                    DWORD read = 0;
                    if (!ReadFile(h, &cluster[0], clusterSize, &read, NULL) ||
                        read != clusterSize)
                        throw _T("Failed to read attribute list non-resident "
                            "data");
                    LONGLONG s = min(attrListNR->contentSize - p, clusterSize);
                    memcpy(&attrListData[p], &cluster[0], s);
                    p += s;
                }
            }
        }

        AttributeRecord *attr = NULL;
        LONGLONG runNum = 0;
        if (contentSize != NULL)
            *contentSize = -1;
        for (
            LONGLONG p = 0;
            p + sizeof(AttributeRecord) <= attrListData.size();
            p += attr->recordLength)
        {
            attr = (AttributeRecord *)&attrListData[p];
            if (attr->typeID == typeID)
            {
                vector<BYTE> extRecord(recordSize);
                RecordHeader *extRecordHeader = (RecordHeader *)&extRecord[0];

                readRecord(h, attr->recordNumber & 0xffffffffffffLL, MFTRunList,
                    recordSize, clusterSize, sectorSize, &extRecord[0]);
                if (memcmp(extRecordHeader->signature, "FILE", 4) != 0)
                    throw _T("Extenion record is invalid");

                AttributeHeaderNR *extAttr = (AttributeHeaderNR *)findAttribute(
                    extRecordHeader, recordSize, typeID);
                if (extAttr == NULL)
                    throw _T("Attribute is not found in extension record");
                if (extAttr->formCode == 0)
                    throw _T("Attribute in extension record is resident");

                if (contentSize != NULL && *contentSize == -1)
                    *contentSize = extAttr->contentSize;

                vector<Run> runListTmp = parseRunList(
                    LPBYTE(extAttr) + extAttr->runListOffset,
                    extAttr->length - extAttr->runListOffset, totalCluster);

                runList->resize(runNum + runListTmp.size());
                for (size_t i=0; i<runListTmp.size(); i++)
                    (*runList)[runNum+i] = runListTmp[i];
                runNum += runListTmp.size();
            }
        }
    }
    return stage;
}

int main()
{
    LPWSTR *argv = NULL;
    HANDLE h = INVALID_HANDLE_VALUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    int result = -1;

    try
    {
        _tsetlocale(LC_ALL, _T(""));

        //  Argument
        int argc;
        argv = CommandLineToArgvW(GetCommandLine(), &argc);

        TCHAR drive[] = _T("C");
        LONGLONG targetRecord = -1;
        LPWSTR outputFile = NULL;

        switch (argc)
        {
        case 2:
            drive[4] = argv[1][0];
            break;
        case 4:
            drive[4] = argv[1][0];
            targetRecord = _tstoi64(argv[2]);
            outputFile = argv[3];
            break;
        default:
            _tprintf(_T("Usage:\n"));
            _tprintf(_T("  ntfsdump DriveLetter\n"));
            _tprintf(_T("  ntfsdump DriveLetter RecordIndex OutputFileName\n"));
            throw 0;
        }

        //  Open
        h = CreateFile(
            drive,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (h == INVALID_HANDLE_VALUE)
            throw _T("Failed to open drive");

        //  Boot Sector
        BootSector bootSector;
        DWORD read;
        if (!ReadFile(h, &bootSector, sizeof bootSector, &read, NULL) ||
            read != sizeof bootSector)
            throw _T("Failed to read boot sector");

        printf("OEM ID: \"%s\"\n", bootSector.oemID);
        if (memcmp(bootSector.oemID, "NTFS    ", 8) != 0)
            throw _T("Volume is not NTFS");

        DWORD sectorSize = bootSector.bytePerSector;
        DWORD clusterSize = bootSector.bytePerSector * bootSector.sectorPerCluster;
        DWORD recordSize = bootSector.clusterPerRecord >= 0 ?
            bootSector.clusterPerRecord * clusterSize :
            1 << -bootSector.clusterPerRecord;
        LONGLONG totalCluster = bootSector.totalSector / bootSector.sectorPerCluster;

        _tprintf(_T("Byte/Sector: %u\n"), sectorSize);
        _tprintf(_T("Sector/Cluster: %u\n"), bootSector.sectorPerCluster);
        _tprintf(_T("Total Sector: %llu\n"), bootSector.totalSector);
        _tprintf(_T("Cluster of MFT: %llu\n"), bootSector.MFTCluster);
        _tprintf(_T("Cluster/Record: %u\n"), bootSector.clusterPerRecord);
        _tprintf(_T("Cluster Size: %u\n"), clusterSize);
        _tprintf(_T("Record Size: %u\n"), recordSize);

        //  Read MFT size and run list
        vector<Run> MFTRunList(1, Run(
            bootSector.MFTCluster,
            24*recordSize/clusterSize));
        LONGLONG MFTSize = 0LL;
        int MFTStage = readRunList(
            h,
            0,      //  $MFT
            0x80,   //  $Data
            MFTRunList,
            recordSize,
            clusterSize,
            sectorSize,
            totalCluster,
            &MFTRunList,
            &MFTSize);

        _tprintf(_T("MFT stage: %d\n"), MFTStage);
        if (MFTStage==0 || MFTStage==1)
            throw _T("MFT stage is 1");
        _tprintf(_T("MFT size: %llu\n"), MFTSize);
        ULONGLONG recordNumber = MFTSize / recordSize;
        _tprintf(_T("Record number: %llu\n"), recordNumber);
        _tprintf(_T("MFT run list: %lld\n"), MFTRunList.size());
        for (Run &run: MFTRunList)
            _tprintf(_T("  %16llx %16llx\n"), run.offset, run.length);

        if (argc == 2)
        {
            //  Read file list
            _tprintf(_T("File List:\n"));

            vector<BYTE> record(recordSize);
            RecordHeader *recordHeader = (RecordHeader *)&record[0];

            for (ULONGLONG recordIndex=0; recordIndex<recordNumber; recordIndex++)
            {
                _tprintf(_T("%12lld"), recordIndex);
                try
                {
                    readRecord(h, recordIndex, MFTRunList, recordSize,
                        clusterSize, sectorSize, &record[0]);

                    if (memcmp(recordHeader->signature, "FILE", 4) !=  0)
                    {
                        _tprintf(_T(" -\n"));
                        continue;
                    }

                    if (recordHeader->baseRecord != 0LL)
                    {
                        _tprintf(_T(" extension for %llu\n"),
                            recordHeader->baseRecord & 0xffffffffffff);
                        continue;
                    }

                    switch (recordHeader->flag)
                    {
                    case 0x0000: _tprintf(_T(" x    "));  break;
                    case 0x0001: _tprintf(_T("      "));  break;
                    case 0x0002: _tprintf(_T(" x dir"));  break;
                    case 0x0003: _tprintf(_T("   dir"));  break;
                    default:     _tprintf(_T(" ?????"));
                    }

                    AttributeHeaderR *name = (AttributeHeaderR *)findAttribute(
                        recordHeader, recordSize, 0x30,
                        [&](LPBYTE a) -> bool
                        {
                            AttributeHeaderR *name = (AttributeHeaderR *)a;
                            if (name->formCode != 0)
                                throw _T("Non-esident $File_Name is not supported");
                            FileName *content =(FileName *)(a + name->contentOffset);
                            if (LPBYTE(content) + sizeof (FileName)
                                > &record[0] + recordSize)
                                throw _T("$File_Name size is invalid");

                            //  0x02 = DOS Name
                            return content->nameType != 0x02;
                        }
                    );
                    //  $File_Name outside the record is not supported
                    if (name == NULL)
                        throw _T("Failed to find $File_Name attribute");

                    FileName *content =(FileName *)(LPBYTE(name)
                        + name->contentOffset);
                    if (content->name + content->nameLength
                        > &record[0] + recordSize)
                        throw _T("$File_Name size is invalid");

                    _tprintf(_T(" %.*s\n"), content->nameLength,
                        (LPTSTR)content->name);
                }
                catch (LPCTSTR error)
                {
                    _tprintf(_T(" %s\n"), error);
                }
            }
        }
        if (argc == 4)
        {
            //  Read file
            _tprintf(_T("Record index: %llu\n"), targetRecord);
            _tprintf(_T("Output file name: %s\n"), outputFile);

            vector<Run> runList;
            LONGLONG contentSize;
            int stage = readRunList(
                h,
                targetRecord,
                0x80,   //  $Data
                MFTRunList,
                recordSize,
                clusterSize,
                sectorSize,
                totalCluster,
                &runList,
                &contentSize);
            if (stage == 0)
                throw _T("Not found attribute $Data");

            switch (stage)
            {
            case 1: _tprintf(_T("Stage: 1 ($Data is resident)\n")); break;
            case 2: _tprintf(_T("Stage: 2 ($Data is non-resident)\n")); break;
            case 3: _tprintf(_T("Stage: 3 ($Attribute_List is resident)\n")); break;
            case 4: _tprintf(_T("Stage: 4 ($Attribute_List is non-resident)\n")); break;
            }

            output = CreateFile(outputFile, GENERIC_WRITE, FILE_SHARE_READ,
                NULL, CREATE_ALWAYS, 0, NULL);
            if (output == INVALID_HANDLE_VALUE)
                throw _T("Failed to open output file");

            if (stage ==  1)
            {
                vector<BYTE> record(recordSize);
                RecordHeader *recordHeader = (RecordHeader *)&record[0];

                readRecord(h, targetRecord, MFTRunList, recordSize, clusterSize,
                    sectorSize, &record[0]);

                AttributeHeaderR *data = (AttributeHeaderR *)findAttribute(
                    recordHeader, recordSize, 0x80);

                _tprintf(_T("File size: %u\n"), data->contentLength);

                if (data->contentOffset + data->contentLength > data->length)
                    throw _T("File size is too large");

                DWORD written;
                if (!WriteFile(output, LPBYTE(data)+data->contentOffset,
                    data->contentLength, &written, NULL) ||
                    written != data->contentLength)
                    throw _T("Failed to write output file");
            }
            else
            {
                vector<BYTE> cluster(clusterSize);
                LONGLONG writeSize = 0;

                _tprintf(_T("Run list: %lld\n"), runList.size());
                for (Run &run: runList)
                {
                    _tprintf(_T("  %16llx %16llx\n"), run.offset, run.length);

                    seek(h, run.offset*clusterSize);
                    for (LONGLONG i=0; i<run.length; i++)
                    {
                        if (writeSize + run.length > contentSize)
                            throw _T("File size error");

                        if (!ReadFile(h, &cluster[0], clusterSize, &read, NULL) ||
                            read != clusterSize)
                            throw _T("Failed to read cluster");

                        DWORD s = DWORD(min(contentSize - writeSize, clusterSize));
                        DWORD written;
                        if (!WriteFile(output, &cluster[0], s, &written, NULL) ||
                            written != s)
                            throw _T("Failed to write output file");
                        writeSize += s;
                    }
                }
                if (writeSize != contentSize)
                {
                    _tprintf(_T("Expected size: %llu\n"), contentSize);
                    _tprintf(_T("Actual size: %llu\n"), writeSize);
                    throw _T("File size error");
                }
            }
            _tprintf(_T("Success\n"));
        }

        result = 0;
    }
    catch (LPWSTR error)
    {
        _tprintf(_T("Error: %s\n"), error);
    }
    catch (...)
    {
        _tprintf(_T("Unkown Error\n"));
    }

    if (argv != NULL)
        GlobalFree(argv);
    if (h != NULL)
        CloseHandle(h);
    if (output != NULL)
        CloseHandle(output);

    return result;
}
*/
