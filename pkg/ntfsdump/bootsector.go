package ntfsdump

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
	TotalSector      int64
	MFTCluster       int64
	MFTMirrCluster   uint64
	ClusterPerRecord byte
	Unused3          [3]byte
	ClusterPerBlock  int8
	Unused4          [3]byte
	SerialNumber     uint64
	CheckSum         uint32
	BootCode         [0x1aa]byte
	EndMarker        [2]byte
}
