package esent

const pageSize = 8192

//# Constants

const FILE_TYPE_DATABASE = 0
const FILE_TYPE_STREAMING_FILE = 1

//# Database state
const JET_dbstateJustCreated = 1
const JET_dbstateDirtyShutdown = 2
const JET_dbstateCleanShutdown = 3
const JET_dbstateBeingConverted = 4
const JET_dbstateForceDetach = 5

//# Page Flags
const FLAGS_ROOT = 1
const FLAGS_LEAF = 2
const FLAGS_PARENT = 4
const FLAGS_EMPTY = 8
const FLAGS_SPACE_TREE = 0x20
const FLAGS_INDEX = 0x40
const FLAGS_LONG_VALUE = 0x80
const FLAGS_NEW_FORMAT = 0x2000
const FLAGS_NEW_CHECKSUM = 0x2000

//# Tag Flags
const TAG_UNKNOWN = 0x1
const TAG_DEFUNCT = 0x2
const TAG_COMMON = 0x4

//# Fixed Page Numbers
const DATABASE_PAGE_NUMBER = 1
const CATALOG_PAGE_NUMBER = 4
const CATALOG_BACKUP_PAGE_NUMBER = 24

//# Fixed FatherDataPages
const DATABASE_FDP = 1
const CATALOG_FDP = 2
const CATALOG_BACKUP_FDP = 3

//# Catalog Types
const CATALOG_TYPE_TABLE = 1
const CATALOG_TYPE_COLUMN = 2
const CATALOG_TYPE_INDEX = 3
const CATALOG_TYPE_LONG_VALUE = 4
const CATALOG_TYPE_CALLBACK = 5

//# Column Types
const JET_coltypNil = 0
const JET_coltypBit = 1
const JET_coltypUnsignedByte = 2
const JET_coltypShort = 3
const JET_coltypLong = 4
const JET_coltypCurrency = 5
const JET_coltypIEEESingle = 6
const JET_coltypIEEEDouble = 7
const JET_coltypDateTime = 8
const JET_coltypBinary = 9
const JET_coltypText = 10
const JET_coltypLongBinary = 11
const JET_coltypLongText = 12
const JET_coltypSLV = 13
const JET_coltypUnsignedLong = 14
const JET_coltypLongLong = 15
const JET_coltypGUID = 16
const JET_coltypUnsignedShort = 17
const JET_coltypMax = 18

//# Tagged Data Type Flags
const TAGGED_DATA_TYPE_VARIABLE_SIZE = 1
const TAGGED_DATA_TYPE_COMPRESSED = 2
const TAGGED_DATA_TYPE_STORED = 4
const TAGGED_DATA_TYPE_MULTI_VALUE = 8
const TAGGED_DATA_TYPE_WHO_KNOWS = 10

//# Code pages
const CODEPAGE_UNICODE = 1200
const CODEPAGE_ASCII = 20127
const CODEPAGE_WESTERN = 1252

const CODEPAGE_UNICODE_S = "utf-16le"
const CODEPAGE_ASCII_S = "ascii"
const CODEPAGE_WESTERN_s = "cp1252"
