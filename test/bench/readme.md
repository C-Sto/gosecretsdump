# Benchmarking

To benchmark, simply run `go test -bench=. -benchtime=30s -benchmem` within this directory.

This will run the test database for 30 seconds, and output some metrics along the lines of:
```
goos: darwin
goarch: amd64
pkg: github.com/c-sto/gosecretsdump/test/bench
BenchmarkProgram-8           100         318444527 ns/op        243728234 B/op    212065 allocs/op
PASS
ok      github.com/c-sto/gosecretsdump/test/bench       32.501s
```

In order to include CPU profiling information with the benchmark (handy to work out what is taking so much got dang processing power!), we can include the profile parameter. The command becomes: `go test -bench=. -benchtime=30s -benchmem -cpuprofile cpu.prof`

We can then use the pprof file generated to investigate performance sinks. `go tool pprof cpu.prof`. Using the 'web' command will output a svg file that is viewable in the browser etc if the 'dot' package is installed. See pprof.svg for an example.
```
Type: cpu
Time: Jun 11, 2019 at 5:19pm (AWST)
Duration: 32.03s, Total samples = 31s (96.78%)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top
Showing nodes accounting for 23420ms, 75.55% of 31000ms total
Dropped 173 nodes (cum <= 155ms)
Showing top 10 nodes out of 107
      flat  flat%   sum%        cum   cum%
    6500ms 20.97% 20.97%     6500ms 20.97%  runtime.pthread_cond_signal
    4510ms 14.55% 35.52%     7540ms 24.32%  runtime.mapaccess1_faststr
    2990ms  9.65% 45.16%     2990ms  9.65%  runtime.aeshashbody
    2820ms  9.10% 54.26%     4880ms 15.74%  runtime.mapaccess2
    1520ms  4.90% 59.16%     1520ms  4.90%  runtime.pthread_cond_timedwait_relative_np
    1460ms  4.71% 63.87%     1460ms  4.71%  runtime.pthread_cond_wait
    1380ms  4.45% 68.32%    19150ms 61.77%  github.com/c-sto/gosecretsdump/pkg/esent.(*Esedb).tagToRecord
     780ms  2.52% 70.84%     7480ms 24.13%  github.com/c-sto/gosecretsdump/pkg/esent.overtwofiddy
     780ms  2.52% 73.35%      780ms  2.52%  runtime.memclrNoHeapPointers
     680ms  2.19% 75.55%      680ms  2.19%  runtime.add
(pprof) list tagToRecord
Total: 31s
ROUTINE ======================== github.com/c-sto/gosecretsdump/pkg/esent.(*Esedb).tagToRecord in /Users/c_sto/go/src/github.com/c-sto/gosecretsdump/pkg/esent/conversion.go
     1.38s     19.15s (flat, cum) 61.77% of Total
         .          .      4:   "bytes"
         .          .      5:   "encoding/binary"
         .          .      6:   "encoding/hex"
         .          .      7:)
         .          .      8:
      40ms       40ms      9:func (e *Esedb) tagToRecord(c *Cursor, tag []byte) Esent_record {
         .      1.72s     10:   record := NewRecord(len(c.TableData.Columns.keys))
         .          .     11:   //record := Esent_record{Column: make(map[string]*esent_recordVal, len(c.TableData.Columns.keys))}
         .       20ms     12:   taggedI := taggedItems{M: make(map[uint16]tag_item), O: []uint16{}}
         .          .     13:   taggedItemsParsed := false
         .          .     14:
         .       10ms     15:   ddHeader := esent_data_definition_header{}
         .       30ms     16:   buffer := bytes.NewBuffer(tag)
         .       70ms     17:   err := binary.Read(buffer, binary.LittleEndian, &ddHeader)
         .          .     18:   if err != nil {
         .          .     19:           panic(err)
         .          .     20:   }
         .          .     21:
         .          .     22:   vDataBytesProcessed := (ddHeader.LastVariableDataType - 127) * 2
         .          .     23:   prevItemLen := uint16(0)
         .          .     24:   //tagLen := uint16(len(tag))
         .          .     25:   fixedSizeOffset := uint32(4) //len ddheader
         .          .     26:   vsOffset := ddHeader.VariableSizeOffset
         .          .     27:
     300ms      300ms     28:   for i, column := range c.TableData.Columns.keys {
     190ms      530ms     29:           cRecord := c.TableData.Columns.values[i].Record
      50ms       50ms     30:           if cRecord.Fixed.Identifier <= uint32(ddHeader.LastFixedSize) {
     160ms      300ms     31:                   record.UpdateBytVal(tag[fixedSizeOffset:][:cRecord.Columns.SpaceUsage], column)
         .          .     32:                   fixedSizeOffset += cRecord.Columns.SpaceUsage
      30ms       30ms     33:           } else if 127 < cRecord.Fixed.Identifier && cRecord.Fixed.Identifier <= uint32(ddHeader.LastVariableDataType) {
         .          .     34:                   variableDataType(&cRecord, tag, &vDataBytesProcessed, vsOffset, &prevItemLen, &record, column)
      20ms       20ms     35:           } else if cRecord.Fixed.Identifier > 255 {
     500ms      7.98s     36:                   overtwofiddy(column, &record, &cRecord, &taggedI, &taggedItemsParsed, vDataBytesProcessed, vsOffset, tag, e.dbHeader.Version, e.dbHeader.FileFormatRevision, e.pageSize)
         .          .     37:           } else {
         .          .     38:                   record.DeleteColumn(column)
         .          .     39:           }
         .          .     40:
         .          .     41:           /*
         .          .     42:                       if type(record[column]) is tuple:
         .          .     43:                   # A multi value data, we won't decode it, just leave it this way
         .          .     44:           */
      30ms      4.80s     45:           record.ConvTup(column)
         .          .     46:
      20ms       20ms     47:           if cRecord.Columns.ColumnType == JET_coltypText || cRecord.Columns.ColumnType == JET_coltypLongText {
      30ms      1.21s     48:                   record.SetString(column, cRecord.Columns.CodePage)
         .          .     49:           } else {
      10ms      2.02s     50:                   record.UnpackInline(column, cRecord.Columns.ColumnType)
         .          .     51:                   //record.Column[column].UnpackInline(cRecord.Columns.ColumnType)
         .          .     52:                   //v.UnpackInline(cRecord.Columns.ColumnType)
         .          .     53:           }
         .          .     54:
         .          .     55:   }
(pprof) 
```