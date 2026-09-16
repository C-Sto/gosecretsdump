package esent

import (
	"bytes"
	"testing"
)

func TestLeafEntryRejectsTruncatedData(t *testing.T) {
	oversized := make([]byte, 19, 2048)
	oversized[0], oversized[1] = 0xba, 0x04 // 1210-byte key in a 19-byte record.
	tests := []struct {
		name  string
		flags uint16
		data  []byte
	}{
		{"empty", 0, nil},
		{"short local length", 0, []byte{1}},
		{"empty common length", TAG_COMMON, nil},
		{"short common length", TAG_COMMON, []byte{1}},
		{"missing local length", TAG_COMMON, []byte{1, 0}},
		{"short local length with common key", TAG_COMMON, []byte{1, 0, 1}},
		{"key exceeds record", 0, []byte{2, 0, 'a'}},
		{"key exceeds record with common key", TAG_COMMON, []byte{1, 0, 2, 0, 'a'}},
		{"capacity exceeds record length", 0, oversized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := (esent_leaf_entry{}).Init(tt.flags, tt.data); err == nil {
				t.Fatal("expected a malformed leaf entry error")
			}
		})
	}
}

func TestLeafEntryValidData(t *testing.T) {
	tests := []struct {
		name   string
		flags  uint16
		data   []byte
		common uint16
		key    []byte
		entry  []byte
	}{
		{"empty key and value", 0, []byte{0, 0}, 0, nil, nil},
		{"empty key", 0, []byte{0, 0, 'v'}, 0, nil, []byte("v")},
		{"key and value", 0, []byte{1, 0, 'k', 'v'}, 0, []byte("k"), []byte("v")},
		{"key at record boundary", 0, []byte{1, 0, 'k'}, 0, []byte("k"), nil},
		{"common prefix", TAG_COMMON, []byte{100, 0, 1, 0, 'k', 'v'}, 100, []byte("k"), []byte("v")},
		{"common prefix and empty local key", TAG_COMMON, []byte{100, 0, 0, 0, 'v'}, 100, nil, []byte("v")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (esent_leaf_entry{}).Init(tt.flags, tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if got.CommonPageKeySize != tt.common || int(got.LocalPageKeySize) != len(tt.key) ||
				!bytes.Equal(got.LocalPageKey, tt.key) || !bytes.Equal(got.EntryData, tt.entry) {
				t.Fatalf("unexpected leaf entry: %+v", got)
			}
		})
	}
}
