// Copyright 2014 The go-ethereum Authors
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

// Package ethdb defines the interfaces for an Ethereum data store.
// 定义了数据库需要使用的接口
// 只需要实现了这些接口就可以定义一种新的数据库
// 调用memorydb.New或者leveldb.New来创建一个数据库对象
package ethdb

import "io"

// KeyValueReader wraps the Has and Get method of a backing data store.
type KeyValueReader interface {
	// Has retrieves if a key is present in the key-value data store.
	Has(key []byte) (bool, error)

	// Get retrieves the given key if it's present in the key-value data store.
	Get(key []byte) ([]byte, error)
}

// KeyValueWriter wraps the Put method of a backing data store.
type KeyValueWriter interface {
	// Put inserts the given value into the key-value data store.
	Put(key []byte, value []byte) error

	// Delete removes the key from the key-value data store.
	Delete(key []byte) error
}

// Stater wraps the Stat method of a backing data store.
type Stater interface {
	// Stat returns a particular internal stat of the database.
	Stat(property string) (string, error)
}

// Compacter wraps the Compact method of a backing data store.
type Compacter interface {
	// Compact flattens the underlying data store for the given key range. In essence,
	// deleted and overwritten versions are discarded, and the data is rearranged to
	// reduce the cost of operations needed to access them.
	//
	// A nil start is treated as a key before all keys in the data store; a nil limit
	// is treated as a key after all keys in the data store. If both is nil then it
	// will compact entire data store.
	// start代表要压缩开始key,limit代表要压缩结束key
	// start=nil代表从第一个key开始压缩
	// limit=nil代表压缩到最后一个key
	Compact(start []byte, limit []byte) error
}

// KeyValueStore contains all the methods required to allow handling different
// key-value data stores backing the high level database.
// 包含操作键值数据库的所有方法
type KeyValueStore interface {
	KeyValueReader
	KeyValueWriter
	Batcher
	Iteratee
	Stater
	Compacter
	io.Closer
}

// AncientReader contains the methods required to read from immutable ancient data.
type AncientReader interface {
	// HasAncient returns an indicator whether the specified data exists in the
	// ancient store.
	// 判断冻结数据库中的kind表中是否有第number项数据
	HasAncient(kind string, number uint64) (bool, error)

	// Ancient retrieves an ancient binary blob from the append-only immutable files.
	// 查询冻结数据库中kind表的第number项数据
	Ancient(kind string, number uint64) ([]byte, error)

	// AncientRange retrieves multiple items in sequence, starting from the index 'start'.
	// It will return
	//  - at most 'count' items,
	//  - at least 1 item (even if exceeding the maxBytes), but will otherwise
	//   return as many items as fit into maxBytes.
	AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error)

	// Ancients returns the ancient item numbers in the ancient store.
	// 获取冻结数据库的数据总条数
	Ancients() (uint64, error)

	// AncientSize returns the ancient size of the specified category.
	// 获取冻结数据库占用的空间大小
	AncientSize(kind string) (uint64, error)
}

// AncientBatchReader is the interface for 'batched' or 'atomic' reading.
type AncientBatchReader interface {
	AncientReader

	// ReadAncients runs the given read operation while ensuring that no writes take place
	// on the underlying freezer.
	ReadAncients(fn func(AncientReader) error) (err error)
}

// AncientWriter contains the methods required to write to immutable ancient data.
type AncientWriter interface {
	// ModifyAncients runs a write operation on the ancient store.
	// If the function returns an error, any changes to the underlying store are reverted.
	// The integer return value is the total size of the written data.
	// 用于向冻结数据库写入数据
	ModifyAncients(func(AncientWriteOp) error) (int64, error)

	// TruncateAncients discards all but the first n ancient data from the ancient store.
	// 保留冻结数据库的前n条数据，后面的数据被删除
	TruncateAncients(n uint64) error

	// Sync flushes all in-memory ancient store data to disk.
	// 执行过写入操作要进行同步
	Sync() error
}

// AncientWriteOp is given to the function argument of ModifyAncients.
// 作为ModifyAncients传入的回调函数的参数，由core/rawdb/freezer_batch.go文件中的freezerBatch对象实现
type AncientWriteOp interface {
	// Append adds an RLP-encoded item.
	Append(kind string, number uint64, item interface{}) error

	// AppendRaw adds an item without RLP-encoding it.
	AppendRaw(kind string, number uint64, item []byte) error
}

// Reader contains the methods required to read data from both key-value as well as
// immutable ancient data.
// Reader对键值数据库和旧数据都能读
type Reader interface {
	KeyValueReader
	AncientBatchReader
}

// Writer contains the methods required to write data to both key-value as well as
// immutable ancient data.
// Writer对键值数据库和旧数据都能写
type Writer interface {
	KeyValueWriter
	AncientWriter
}

// AncientStore contains all the methods required to allow handling different
// ancient data stores backing immutable chain data store.
// 旧数据的读写器
type AncientStore interface {
	AncientBatchReader
	AncientWriter
	io.Closer
}

// Database contains all the methods required by the high level database to not
// only access the key-value data store but also the chain freezer.
// Database实现了对键值数据库和旧数据的所有操作
type Database interface {
	Reader
	Writer
	Batcher
	Iteratee
	Stater
	Compacter
	io.Closer
}
