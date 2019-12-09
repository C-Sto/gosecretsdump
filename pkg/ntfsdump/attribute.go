package ntfsdump

type AttributeHeader struct {
	TypeID, Length                uint32
	NRFlag, NameLength            byte
	NameOffset, Flag, AttributeID uint16
}

type AttributeHeaderResident struct {
	AttributeHeader      AttributeHeader
	AttrLen              uint32
	AttrOffset           uint16 //should always be 0x18
	IndexedFlag, Padding byte
}

type AttributeHeaderNonResident struct {
	AttributeHeader                AttributeHeader
	StartingVCN, LastVCN           int64
	DataRunOffset, CompressionSize uint16
	Padding                        uint32
	AttribAllocatedSize,
	RealSize,
	InitialisedDataSize int64
}
