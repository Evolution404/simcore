// Copyright 2018 The go-ethereum Authors
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
	"github.com/Evolution404/simcore/ethdb"
)
// 使用NewTable创建表对象
// 不同的表对象可以基于同一个键值对数据库对象
// 不同的表对象可以使用相同的key不会引起冲突
//   就是在键值对里通过前缀区分,前缀已经在内部封装,外部就相当于可以在不同的表使用相同的key

// table is a wrapper around a database that prefixes each key access with a pre-
// configured string.
// 利用键值对模拟表结构,所有存进去的key都有固定的前缀
type table struct {
	db     ethdb.Database
	prefix string
}

// NewTable returns a database object that prefixes all keys with a given string.
// 输入数据库对象和前缀,创建一个表格对象
func NewTable(db ethdb.Database, prefix string) ethdb.Database {
	return &table{
		db:     db,
		prefix: prefix,
	}
}

// Close is a noop to implement the Database interface.
// table对象为了实现Database接口必须实现一个Close方法
func (t *table) Close() error {
	return nil
}

// Has retrieves if a prefixed version of a key is present in the database.
// 加上前缀再搜索
func (t *table) Has(key []byte) (bool, error) {
	return t.db.Has(append([]byte(t.prefix), key...))
}

// Get retrieves the given prefixed key if it's present in the database.
func (t *table) Get(key []byte) ([]byte, error) {
	return t.db.Get(append([]byte(t.prefix), key...))
}

// HasAncient is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) HasAncient(kind string, number uint64) (bool, error) {
	return t.db.HasAncient(kind, number)
}

// Ancient is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Ancient(kind string, number uint64) ([]byte, error) {
	return t.db.Ancient(kind, number)
}

// AncientRange is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	return t.db.AncientRange(kind, start, count, maxBytes)
}

// Ancients is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Ancients() (uint64, error) {
	return t.db.Ancients()
}

// AncientSize is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) AncientSize(kind string) (uint64, error) {
	return t.db.AncientSize(kind)
}

// ModifyAncients runs an ancient write operation on the underlying database.
func (t *table) ModifyAncients(fn func(ethdb.AncientWriteOp) error) (int64, error) {
	return t.db.ModifyAncients(fn)
}

func (t *table) ReadAncients(fn func(reader ethdb.AncientReader) error) (err error) {
	return t.db.ReadAncients(fn)
}

// TruncateAncients is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) TruncateAncients(items uint64) error {
	return t.db.TruncateAncients(items)
}

// Sync is a noop passthrough that just forwards the request to the underlying
// database.
func (t *table) Sync() error {
	return t.db.Sync()
}

// Put inserts the given value into the database at a prefixed version of the
// provided key.
// Put时自动给key加上前缀
func (t *table) Put(key []byte, value []byte) error {
	return t.db.Put(append([]byte(t.prefix), key...), value)
}

// Delete removes the given prefixed key from the database.
// 删除也是删除加上key后的键
func (t *table) Delete(key []byte) error {
	return t.db.Delete(append([]byte(t.prefix), key...))
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
// 搜索的是表的前缀再加上输入前缀的key
// 返回的对象也是表自己实现的迭代器
// 使用tableIterator的原因在于Key方法要能正确返回去掉表前缀的key
func (t *table) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	// 两个前缀合并
	innerPrefix := append([]byte(t.prefix), prefix...)
	iter := t.db.NewIterator(innerPrefix, start)
	return &tableIterator{
		iter:   iter,
		prefix: t.prefix,
	}
}

// Stat returns a particular internal stat of the database.
func (t *table) Stat(property string) (string, error) {
	return t.db.Stat(property)
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
// 压缩一张表内的数据，start和limit指定范围
func (t *table) Compact(start []byte, limit []byte) error {
	// If no start was specified, use the table prefix as the first value
	if start == nil {
		start = []byte(t.prefix)
	} else {
		start = append([]byte(t.prefix), start...)
	}
	// If no limit was specified, use the first element not matching the prefix
	// as the limit
	// 如果limit是nil，代表要压缩整张表的数据，需要将limit设置为表的最后一条数据
	// 最后一条数据其实就是将前缀的最后一个字节加一，但是有可能加一后溢出，所以溢出后要继续将前一个字节加一
	if limit == nil {
		limit = []byte(t.prefix)
		// 从最后一个字节开始挨个尝试加一，
		for i := len(limit) - 1; i >= 0; i-- {
			// Bump the current character, stopping if it doesn't overflow
			// 将当前字节加一
			limit[i]++
			// 没有溢出，结束
			if limit[i] > 0 {
				break
			}
			// Character overflown, proceed to the next or nil if the last
			// 如果一直溢出到了第一个字节，相当于是一个全是0xff的字节数组，这张表最后一条数据就是数据库的最后一条数据
			if i == 0 {
				limit = nil
			}
		}
	} else {
		limit = append([]byte(t.prefix), limit...)
	}
	// Range correctly calculated based on table prefix, delegate down
	return t.db.Compact(start, limit)
}

// NewBatch creates a write-only database that buffers changes to its host db
// until a final write is called, each operation prefixing all keys with the
// pre-configured string.
func (t *table) NewBatch() ethdb.Batch {
	return &tableBatch{t.db.NewBatch(), t.prefix}
}

// tableBatch is a wrapper around a database batch that prefixes each key access
// with a pre-configured string.
type tableBatch struct {
	batch  ethdb.Batch
	prefix string
}

// Put inserts the given value into the batch for later committing.
func (b *tableBatch) Put(key, value []byte) error {
	return b.batch.Put(append([]byte(b.prefix), key...), value)
}

// Delete inserts the a key removal into the batch for later committing.
func (b *tableBatch) Delete(key []byte) error {
	return b.batch.Delete(append([]byte(b.prefix), key...))
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *tableBatch) ValueSize() int {
	return b.batch.ValueSize()
}

// Write flushes any accumulated data to disk.
func (b *tableBatch) Write() error {
	return b.batch.Write()
}

// Reset resets the batch for reuse.
func (b *tableBatch) Reset() {
	b.batch.Reset()
}

// tableReplayer is a wrapper around a batch replayer which truncates
// the added prefix.
type tableReplayer struct {
	w      ethdb.KeyValueWriter
	prefix string
}

// Put implements the interface KeyValueWriter.
func (r *tableReplayer) Put(key []byte, value []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Put(trimmed, value)
}

// Delete implements the interface KeyValueWriter.
func (r *tableReplayer) Delete(key []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Delete(trimmed)
}

// Replay replays the batch contents.
func (b *tableBatch) Replay(w ethdb.KeyValueWriter) error {
	// 直接调用b.batch.Replay(w)的话
	// 就会往w里面加入或者删除带有前缀的key
	// 需要再包装一下去掉前缀后再调用KeyValueWriter的Put和Delete方法
	return b.batch.Replay(&tableReplayer{w: w, prefix: b.prefix})
}

// tableIterator is a wrapper around a database iterator that prefixes each key access
// with a pre-configured string.
// 实现这个对象的目的就是因为Key方法要返回一个去掉表前缀的key
type tableIterator struct {
	iter   ethdb.Iterator
	prefix string
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
func (iter *tableIterator) Next() bool {
	return iter.iter.Next()
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
func (iter *tableIterator) Error() error {
	return iter.iter.Error()
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
// 这里返回的key要去掉表的前缀
func (iter *tableIterator) Key() []byte {
	key := iter.iter.Key()
	if key == nil {
		return nil
	}
	return key[len(iter.prefix):]
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
func (iter *tableIterator) Value() []byte {
	return iter.iter.Value()
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
func (iter *tableIterator) Release() {
	iter.iter.Release()
}
