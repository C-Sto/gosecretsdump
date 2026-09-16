package esent

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"
)

// A tag is a view into a page, so its capacity can exceed its record length.
func oversizedLeafPage() *esent_page {
	p := &esent_page{data: make([]byte, pageSize)}
	p.record = esent_page_header{Len: 40, PageFlags: FLAGS_LEAF, FirstAvailablePageTag: 2}
	binary.LittleEndian.PutUint16(p.data[40:42], 1210)
	binary.LittleEndian.PutUint16(p.data[pageSize-8:pageSize-6], 19)
	return p
}

func TestInitReturnsCatalogLeafError(t *testing.T) {
	// Only the header and one catalog page are needed; no real database data.
	header := esent_db_header{Version: 0x620, FileFormatRevision: 0x11, PageSize: pageSize}
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	database := make([]byte, 8*pageSize)
	copy(database, encoded.Bytes())
	p := oversizedLeafPage()
	binary.LittleEndian.PutUint16(p.data[34:36], 2)
	binary.LittleEndian.PutUint32(p.data[36:40], FLAGS_LEAF)
	copy(database[5*pageSize:], p.data)
	f, err := ioutil.TempFile("", "esent-leaf-*.dit")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil {
			t.Error(err)
		}
	}()
	if _, err := f.Write(database); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Esedb{}).Init(f.Name()); err == nil {
		t.Fatal("expected initialization to return the malformed catalog error")
	}
}

func TestGetNextRowRejectsOversizedLeafKey(t *testing.T) {
	c := &Cursor{CurrentPageData: oversizedLeafPage()}
	if _, err := (&Esedb{}).GetNextRow(c); err == nil {
		t.Fatal("expected an error for a key extending beyond its record")
	}
}

func TestParseCatalogReturnsLeafError(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		name := "root"
		if recursive {
			name = "child"
		}
		t.Run(name, func(t *testing.T) {
			e := &Esedb{db: &fileInMem{pages: make([]*esent_page, 8)}}
			e.db.pages[5] = oversizedLeafPage()
			if recursive {
				branch := &esent_page{data: make([]byte, pageSize)}
				branch.record = esent_page_header{Len: 40, FirstAvailablePageTag: 2}
				binary.LittleEndian.PutUint32(branch.data[42:46], 5)
				binary.LittleEndian.PutUint16(branch.data[pageSize-8:pageSize-6], 6)
				e.db.pages[6] = e.db.pages[5]
				e.db.pages[5] = branch
			}
			if err := e.parseCatalog(CATALOG_PAGE_NUMBER); err == nil {
				t.Fatal("expected the catalog to return the malformed leaf error")
			}
		})
	}
}
