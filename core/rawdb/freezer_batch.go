// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"fmt"
	"sync/atomic"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/rlp"
	"github.com/golang/snappy"
)

// This is the maximum amount of data that will be buffered in memory
// for a single freezer table batch.
// 当冻结数据库中一张表缓存的数据超过2M的时候向硬盘写入数据
const freezerBatchBufferLimit = 2 * 1024 * 1024

// freezerBatch is a write operation of multiple items on a freezer.
type freezerBatch struct {
	tables map[string]*freezerTableBatch
}

func newFreezerBatch(f *freezer) *freezerBatch {
	batch := &freezerBatch{tables: make(map[string]*freezerTableBatch, len(f.tables))}
	for kind, table := range f.tables {
		batch.tables[kind] = table.newBatch()
	}
	return batch
}

// Append adds an RLP-encoded item of the given kind.
func (batch *freezerBatch) Append(kind string, num uint64, item interface{}) error {
	return batch.tables[kind].Append(num, item)
}

// AppendRaw adds an item of the given kind.
func (batch *freezerBatch) AppendRaw(kind string, num uint64, item []byte) error {
	return batch.tables[kind].AppendRaw(num, item)
}

// reset initializes the batch.
// 重置冻结库缓存，就是调用内部五张表的reset方法
func (batch *freezerBatch) reset() {
	for _, tb := range batch.tables {
		tb.reset()
	}
}

// commit is called at the end of a write operation and
// writes all remaining data to tables.
// 将冻结库缓存写入冻结数据库
func (batch *freezerBatch) commit() (item uint64, writeSize int64, err error) {
	// Check that count agrees on all batches.
	item = uint64(math.MaxUint64)
	for name, tb := range batch.tables {
		if item < math.MaxUint64 && tb.curItem != item {
			return 0, 0, fmt.Errorf("table %s is at item %d, want %d", name, tb.curItem, item)
		}
		item = tb.curItem
	}

	// Commit all table batches.
	// 遍历每个冻结表缓存对象，依次调用commit方法，然后记录下来总共写入的数据量
	for _, tb := range batch.tables {
		if err := tb.commit(); err != nil {
			return 0, 0, err
		}
		writeSize += tb.totalBytes
	}
	return item, writeSize, nil
}

// freezerTableBatch is a batch for a freezer table.
type freezerTableBatch struct {
	t *freezerTable

	// 如果没启用压缩这个字段就是nil
	sb          *snappyBuffer
	// RLP编码时使用的缓存
	encBuffer   writeBuffer
	// 保存在缓存中的数据
	dataBuffer  []byte
	// 在缓存中的数据对应的索引信息
	indexBuffer []byte
	// 下一条数据要写入的位置，初始化为冻结数据表的数据条数，随着Batch中不断写入数值不断增加
	curItem     uint64 // expected index of next append
	// 记录已经向冻结表缓存中写入了多少字节的数据，在appendItem函数中记录
	totalBytes  int64  // counts written bytes since reset
}

// newBatch creates a new batch for the freezer table.
// 由freezerTable对象创建一个freezerTableBatch
func (t *freezerTable) newBatch() *freezerTableBatch {
	batch := &freezerTableBatch{t: t}
	// 如果是压缩表，需要为压缩数据生成缓存
	if !t.noCompression {
		batch.sb = new(snappyBuffer)
	}
	batch.reset()
	return batch
}

// reset clears the batch for reuse.
// 重置一个冻结表缓存对象，生成该对象的时候也可以用来初始化
func (batch *freezerTableBatch) reset() {
	batch.dataBuffer = batch.dataBuffer[:0]
	batch.indexBuffer = batch.indexBuffer[:0]
	// 初始化位置为冻结数据表内的数据条数
	batch.curItem = atomic.LoadUint64(&batch.t.items)
	batch.totalBytes = 0
}

// Append rlp-encodes and adds data at the end of the freezer table. The item number is a
// precautionary parameter to ensure data correctness, but the table will reject already
// existing data.
// 向冻结表缓存中添加一条数据，item是数据的序号起校验作用，data会被编码为RLP编码
func (batch *freezerTableBatch) Append(item uint64, data interface{}) error {
	// 校验序号是否正确
	if item != batch.curItem {
		return fmt.Errorf("%w: have %d want %d", errOutOrderInsertion, item, batch.curItem)
	}

	// Encode the item.
	// 计算RLP编码
	batch.encBuffer.Reset()
	if err := rlp.Encode(&batch.encBuffer, data); err != nil {
		return err
	}
	encItem := batch.encBuffer.data
	// 将数据压缩
	if batch.sb != nil {
		encItem = batch.sb.compress(encItem)
	}
	// 将最终的数据写入缓存，等待写入冻结数据库
	return batch.appendItem(encItem)
}

// AppendRaw injects a binary blob at the end of the freezer table. The item number is a
// precautionary parameter to ensure data correctness, but the table will reject already
// existing data.
// 向冻结表缓存中添加一条数据，item是数据的序号起校验作用，直接将data的原始内容写入冻结数据库
func (batch *freezerTableBatch) AppendRaw(item uint64, blob []byte) error {
	if item != batch.curItem {
		return fmt.Errorf("%w: have %d want %d", errOutOrderInsertion, item, batch.curItem)
	}

	encItem := blob
	if batch.sb != nil {
		encItem = batch.sb.compress(blob)
	}
	return batch.appendItem(encItem)
}

func (batch *freezerTableBatch) appendItem(data []byte) error {
	// Check if item fits into current data file.
	// 新数据的长度
	itemSize := int64(len(data))
	// 新数据将要在数据文件上的开始位置：硬盘上数据的长度+缓存中数据的长度
	itemOffset := batch.t.headBytes + int64(len(batch.dataBuffer))
	// 判断新加的数据写入后是否需要切换数据文件
	if itemOffset+itemSize > int64(batch.t.maxFileSize) {
		// It doesn't fit, go to next file first.
		// 需要切换数据文件，将之前的数据都写入到磁盘上
		if err := batch.commit(); err != nil {
			return err
		}
		// 然后切换数据文件
		if err := batch.t.advanceHead(); err != nil {
			return err
		}
		// 新数据将被写入到全新的数据文件，所以偏移位置是0
		itemOffset = 0
	}

	// Put data to buffer.
	// 将新数据加入缓存
	batch.dataBuffer = append(batch.dataBuffer, data...)
	// 记录写入的数据总量
	batch.totalBytes += itemSize

	// Put index entry to buffer.
	// 记录新数据的索引信息
	entry := indexEntry{filenum: batch.t.headId, offset: uint32(itemOffset + itemSize)}
	batch.indexBuffer = entry.append(batch.indexBuffer)
	// 表中数据加一
	batch.curItem++

	// 尝试一下是否需要将缓存写入冻结数据库
	return batch.maybeCommit()
}

// maybeCommit writes the buffered data if the buffer is full enough.
// 判断是否达到了缓存数据的上限，达到上限后写入冻结数据库
func (batch *freezerTableBatch) maybeCommit() error {
	if len(batch.dataBuffer) > freezerBatchBufferLimit {
		return batch.commit()
	}
	return nil
}

// commit writes the batched items to the backing freezerTable.
// 将缓存中的数据写入到冻结数据库
func (batch *freezerTableBatch) commit() error {
	// Write data.
	// 向数据文件写入缓存的数据
	_, err := batch.t.head.Write(batch.dataBuffer)
	if err != nil {
		return err
	}
	// 用于metrics统计
	dataSize := int64(len(batch.dataBuffer))
	// 清空数据缓存
	batch.dataBuffer = batch.dataBuffer[:0]

	// Write index.
	// 向索引文件写入缓存的索引信息
	_, err = batch.t.index.Write(batch.indexBuffer)
	if err != nil {
		return err
	}
	// 用于metrics统计
	indexSize := int64(len(batch.indexBuffer))
	// 清空索引缓存
	batch.indexBuffer = batch.indexBuffer[:0]

	// Update headBytes of table.
	// 更新冻结数据表中保存的数据文件大小
	batch.t.headBytes += dataSize
	// 更新冻结数据表中保存的数据条数
	atomic.StoreUint64(&batch.t.items, batch.curItem)

	// Update metrics.
	batch.t.sizeGauge.Inc(dataSize + indexSize)
	batch.t.writeMeter.Mark(dataSize + indexSize)
	return nil
}

// snappyBuffer writes snappy in block format, and can be reused. It is
// reset when WriteTo is called.
// 压缩缓存对象，将压缩的数据保存在内部的字节数组中
// 每次压缩的数据都复用这个字节数组，可以减少内存分配
type snappyBuffer struct {
	dst []byte
}

// compress snappy-compresses the data.
// 压缩输入的数据到内部的缓存中
func (s *snappyBuffer) compress(data []byte) []byte {
	// The snappy library does not care what the capacity of the buffer is,
	// but only checks the length. If the length is too small, it will
	// allocate a brand new buffer.
	// To avoid that, we check the required size here, and grow the size of the
	// buffer to utilize the full capacity.
	// 尽可能地复用内部的dst字节数组，减少内存分配
	if n := snappy.MaxEncodedLen(len(data)); len(s.dst) < n {
		if cap(s.dst) < n {
			s.dst = make([]byte, n)
		}
		s.dst = s.dst[:n]
	}

	s.dst = snappy.Encode(s.dst, data)
	return s.dst
}

// writeBuffer implements io.Writer for a byte slice.
// 一个写入缓存，实现了io.Writer接口，可以通过Reset方法复用内部的字节数组，减少内存分配
type writeBuffer struct {
	data []byte
}

func (wb *writeBuffer) Write(data []byte) (int, error) {
	wb.data = append(wb.data, data...)
	return len(data), nil
}

func (wb *writeBuffer) Reset() {
	wb.data = wb.data[:0]
}
