// Copyright 2020 The go-ethereum Authors
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

package trie

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/rlp"
)

var ErrCommitDisabled = errors.New("no database for committing")

var stPool = sync.Pool{
	New: func() interface{} {
		return NewStackTrie(nil)
	},
}

func stackTrieFromPool(db ethdb.KeyValueWriter) *StackTrie {
	st := stPool.Get().(*StackTrie)
	st.db = db
	return st
}

func returnToPool(st *StackTrie) {
	st.Reset()
	stPool.Put(st)
}

// StackTrie is a trie implementation that expects keys to be inserted
// in order. Once it determines that a subtree will no longer be inserted
// into, it will hash it and free up the memory it uses.
// key按照顺序插入的类型
type StackTrie struct {
	nodeType uint8                // node type (as in branch, ext, leaf)
	val      []byte               // value contained by this node if it's a leaf
	key      []byte               // key chunk covered by this (leaf|ext) node
	children [16]*StackTrie       // list of children (for branch and exts)
	db       ethdb.KeyValueWriter // Pointer to the commit db, can be nil
}

// NewStackTrie allocates and initializes an empty trie.
// 新建一个StackTrie对象
// 设置nodeType为emptyNode
// 设置db为输入的db
func NewStackTrie(db ethdb.KeyValueWriter) *StackTrie {
	return &StackTrie{
		// 新建的类型是emptyNode
		nodeType: emptyNode,
		db:       db,
	}
}

// NewFromBinary initialises a serialized stacktrie with the given db.
// 输入字节数组解码为StackTrie
func NewFromBinary(data []byte, db ethdb.KeyValueWriter) (*StackTrie, error) {
	var st StackTrie
	if err := st.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	// If a database is used, we need to recursively add it to every child
	if db != nil {
		st.setDb(db)
	}
	return &st, nil
}

// MarshalBinary implements encoding.BinaryMarshaler
// 返回StackTrie编码后的字节数组
// 使用gob包进行编码,递归编码child
// nil child使用0标记,不为nil的child有前缀1
func (st *StackTrie) MarshalBinary() (data []byte, err error) {
	var (
		b bytes.Buffer
		w = bufio.NewWriter(&b)
	)
	if err := gob.NewEncoder(w).Encode(struct {
		Nodetype uint8
		Val      []byte
		Key      []byte
	}{
		st.nodeType,
		st.val,
		st.key,
	}); err != nil {
		return nil, err
	}
	for _, child := range st.children {
		// child为nil写入0
		if child == nil {
			w.WriteByte(0)
			continue
		}
		// child不是nil先写入一个1
		// 然后对child进行编码
		w.WriteByte(1)
		if childData, err := child.MarshalBinary(); err != nil {
			return nil, err
		} else {
			w.Write(childData)
		}
	}
	w.Flush()
	return b.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
// 输入字节数组解码到StackTrie
func (st *StackTrie) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	return st.unmarshalBinary(r)
}

func (st *StackTrie) unmarshalBinary(r io.Reader) error {
	var dec struct {
		Nodetype uint8
		Val      []byte
		Key      []byte
	}
	// 使用gob包解码二进制流到dec中
	gob.NewDecoder(r).Decode(&dec)
	// 把dec中的数据写入到st中
	st.nodeType = dec.Nodetype
	st.val = dec.Val
	st.key = dec.Key

	var hasChild = make([]byte, 1)
	for i := range st.children {
		// 一次读取一个字节
		// 保存的是0的话继续读取下一个字节
		// 不是0的话解码后面的字节成为StackTrie对象
		if _, err := r.Read(hasChild); err != nil {
			return err
		} else if hasChild[0] == 0 {
			continue
		}
		var child StackTrie
		child.unmarshalBinary(r)
		st.children[i] = &child
	}
	return nil
}

// 设置整棵树中每个节点的db字段
func (st *StackTrie) setDb(db ethdb.KeyValueWriter) {
	st.db = db
	for _, child := range st.children {
		if child != nil {
			child.setDb(db)
		}
	}
}

func newLeaf(key, val []byte, db ethdb.KeyValueWriter) *StackTrie {
	st := stackTrieFromPool(db)
	st.nodeType = leafNode
	st.key = append(st.key, key...)
	st.val = val
	return st
}

func newExt(key []byte, child *StackTrie, db ethdb.KeyValueWriter) *StackTrie {
	st := stackTrieFromPool(db)
	st.nodeType = extNode
	st.key = append(st.key, key...)
	st.children[0] = child
	return st
}

// List all values that StackTrie#nodeType can hold
const (
	emptyNode = iota
	branchNode
	extNode
	leafNode
	hashedNode
)

// TryUpdate inserts a (key, value) pair into the stack trie
// 设置key对应的值为value
// value的长度不能为0,因为StackTrie不支持删除操作
func (st *StackTrie) TryUpdate(key, value []byte) error {
	k := keybytesToHex(key)
	if len(value) == 0 {
		panic("deletion not supported")
	}
	// 去掉k的最后一个元素,也就是去掉terminator
	st.insert(k[:len(k)-1], value)
	return nil
}

func (st *StackTrie) Update(key, value []byte) {
	if err := st.TryUpdate(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// 让StackTrie的各个字段都清空
func (st *StackTrie) Reset() {
	st.db = nil
	st.key = st.key[:0]
	st.val = nil
	for i := range st.children {
		st.children[i] = nil
	}
	st.nodeType = emptyNode
}

// Helper function that, given a full key, determines the index
// at which the chunk pointed by st.keyOffset is different from
// the same chunk in the full key.
// 找到st.key第一处与输入的key不一致的地方
func (st *StackTrie) getDiffIndex(key []byte) int {
	for idx, nibble := range st.key {
		if nibble != key[idx] {
			return idx
		}
	}
	return len(st.key)
}

// Helper function to that inserts a (key, value) pair into
// the trie.
// 向StackTrie中插入一个键值对
func (st *StackTrie) insert(key, value []byte) {
	switch st.nodeType {
	// 分支节点的插入是根据key的第一位来判断在children中的位置
	// 将前面的children就计算哈希,然后递归插入
	case branchNode: /* Branch */
		idx := int(key[0])
		// Unresolve elder siblings
		// 把之前的节点都计算哈希
		for i := idx - 1; i >= 0; i-- {
			if st.children[i] != nil {
				if st.children[i].nodeType != hashedNode {
					st.children[i].hash()
				}
				break
			}
		}
		// Add new child
		// 插入新的节点
		if st.children[idx] == nil {
			st.children[idx] = newLeaf(key[1:], value, st.db)
		} else {
			st.children[idx].insert(key[1:], value)
		}
	case extNode: /* Ext */
		// Compare both key chunks and see where they differ
		diffidx := st.getDiffIndex(key)

		// Check if chunks are identical. If so, recurse into
		// the child node. Otherwise, the key has to be split
		// into 1) an optional common prefix, 2) the fullnode
		// representing the two differing path, and 3) a leaf
		// for each of the differentiated subtrees.
		// 与这个扩展节点完全匹配,递归向子节点插入
		if diffidx == len(st.key) {
			// Ext key and key segment are identical, recurse into
			// the child node.
			st.children[0].insert(key[diffidx:], value)
			return
		}
		// Save the original part. Depending if the break is
		// at the extension's last byte or not, create an
		// intermediate extension or use the extension's child
		// node directly.
		// n用来记录原来的节点
		var n *StackTrie
		if diffidx < len(st.key)-1 {
			n = newExt(st.key[diffidx+1:], st.children[0], st.db)
		} else {
			// Break on the last byte, no need to insert
			// an extension node: reuse the current node
			n = st.children[0]
		}
		// Convert to hash
		n.hash()
		// p用来记录插入生成的分支节点
		// 接下来根据有没有共同前缀来构造分支节点
		// 没有共同前缀直接改造当前节点为分支节点
		// 有共同前缀改造当前节点的children[0],当前节点的key缩短到新前缀
		var p *StackTrie
		// 完全不匹配
		// 当前节点改造成分支节点
		if diffidx == 0 {
			// the break is on the first byte, so
			// the current node is converted into
			// a branch node.
			st.children[0] = nil
			p = st
			st.nodeType = branchNode
		// 有匹配的部分,在children[0]生成一个新的分支节点
		} else {
			// the common prefix is at least one byte
			// long, insert a new intermediate branch
			// node.
			st.children[0] = stackTrieFromPool(st.db)
			st.children[0].nodeType = branchNode
			p = st.children[0]
		}
		// Create a leaf for the inserted part
		o := newLeaf(key[diffidx+1:], value, st.db)

		// Insert both child leaves where they belong:
		// 获得应该在分支节点children中的位置
		origIdx := st.key[diffidx]
		newIdx := key[diffidx]
		p.children[origIdx] = n
		p.children[newIdx] = o
		st.key = st.key[:diffidx]

	case leafNode: /* Leaf */
		// Compare both key chunks and see where they differ
		diffidx := st.getDiffIndex(key)

		// Overwriting a key isn't supported, which means that
		// the current leaf is expected to be split into 1) an
		// optional extension for the common prefix of these 2
		// keys, 2) a fullnode selecting the path on which the
		// keys differ, and 3) one leaf for the differentiated
		// component of each key.
		if diffidx >= len(st.key) {
			panic("Trying to insert into existing key")
		}

		// Check if the split occurs at the first nibble of the
		// chunk. In that case, no prefix extnode is necessary.
		// Otherwise, create that
		// 判断新插入的是不是和现有叶子用公共前缀
		// 有公共前缀需要生成扩展节点
		// 没有公共前缀不需要扩展节点,直接生成分支节点

		// p保存了分支节点,原有节点和插入的节点就保存到该分支节点的两个分支
		var p *StackTrie
		// 没有前缀转换当前节点为分支节点
		if diffidx == 0 {
			// Convert current leaf into a branch
			st.nodeType = branchNode
			p = st
			st.children[0] = nil
		// 有前缀把当前节点转换为扩展节点,然后连接一个新生成的分支节点
		} else {
			// Convert current node into an ext,
			// and insert a child branch node.
			st.nodeType = extNode
			st.children[0] = NewStackTrie(st.db)
			st.children[0].nodeType = branchNode
			p = st.children[0]
		}

		// Create the two child leaves: the one containing the
		// original value and the one containing the new value
		// The child leave will be hashed directly in order to
		// free up some memory.
		origIdx := st.key[diffidx]
		p.children[origIdx] = newLeaf(st.key[diffidx+1:], st.val, st.db)
		p.children[origIdx].hash()

		newIdx := key[diffidx]
		p.children[newIdx] = newLeaf(key[diffidx+1:], value, st.db)

		// Finally, cut off the key part that has been passed
		// over to the children.
		st.key = st.key[:diffidx]
		st.val = nil
	// 插入空节点直接赋值key,val即可
	// 并设置类型为leafNode
	case emptyNode: /* Empty */
		st.nodeType = leafNode
		st.key = key
		st.val = value
	case hashedNode:
		panic("trying to insert into hash")
	default:
		panic("invalid type")
	}
}

// hash() hashes the node 'st' and converts it into 'hashedNode', if possible.
// Possible outcomes:
// 1. The rlp-encoded value was >= 32 bytes:
//  - Then the 32-byte `hash` will be accessible in `st.val`.
//  - And the 'st.type' will be 'hashedNode'
// 2. The rlp-encoded value was < 32 bytes
//  - Then the <32 byte rlp-encoded value will be accessible in 'st.val'.
//  - And the 'st.type' will be 'hashedNode' AGAIN
//
// This method will also:
// set 'st.type' to hashedNode
// clear 'st.key'
// 将st.type修改为hashedNode
// 清空st.key
// 设置st.val为哈希值(如果rlp编码不足32字节保存rlp编码)
func (st *StackTrie) hash() {
	/* Shortcut if node is already hashed */
	if st.nodeType == hashedNode {
		return
	}
	// The 'hasher' is taken from a pool, but we don't actually
	// claim an instance until all children are done with their hashing,
	// and we actually need one
	var h *hasher

	// 计算rlp编码到h.tmp中
	// 清空st.children
	switch st.nodeType {
	case branchNode:
		var nodes [17]node
		for i, child := range st.children {
			if child == nil {
				nodes[i] = nilValueNode
				continue
			}
			child.hash()
			if len(child.val) < 32 {
				nodes[i] = rawNode(child.val)
			} else {
				nodes[i] = hashNode(child.val)
			}
			st.children[i] = nil // Reclaim mem from subtree
			returnToPool(child)
		}
		nodes[16] = nilValueNode
		h = newHasher(false)
		defer returnHasherToPool(h)
		h.tmp.Reset()
		if err := rlp.Encode(&h.tmp, nodes); err != nil {
			panic(err)
		}
	case extNode:
		st.children[0].hash()
		h = newHasher(false)
		defer returnHasherToPool(h)
		h.tmp.Reset()
		var valuenode node
		if len(st.children[0].val) < 32 {
			valuenode = rawNode(st.children[0].val)
		} else {
			valuenode = hashNode(st.children[0].val)
		}
		n := struct {
			Key []byte
			Val node
		}{
			// 扩展节点的key转换为compact格式
			Key: hexToCompact(st.key),
			Val: valuenode,
		}
		if err := rlp.Encode(&h.tmp, n); err != nil {
			panic(err)
		}
		returnToPool(st.children[0])
		st.children[0] = nil // Reclaim mem from subtree
	case leafNode:
		h = newHasher(false)
		defer returnHasherToPool(h)
		h.tmp.Reset()
		st.key = append(st.key, byte(16))
		// 叶子节点需要将key转换为compact格式
		sz := hexToCompactInPlace(st.key)
		n := [][]byte{st.key[:sz], st.val}
		if err := rlp.Encode(&h.tmp, n); err != nil {
			panic(err)
		}
	// emptyNode直接使用提前计算好的哈希
	case emptyNode:
		st.val = emptyRoot.Bytes()
		st.key = st.key[:0]
		st.nodeType = hashedNode
		return
	default:
		panic("Invalid node type")
	}
	st.key = st.key[:0]
	st.nodeType = hashedNode
	// 不足32字节直接返回rlp编码
	if len(h.tmp) < 32 {
		st.val = common.CopyBytes(h.tmp)
		return
	}
	// Write the hash to the 'val'. We allocate a new val here to not mutate
	// input values
	// 计算哈希值
	st.val = make([]byte, 32)
	h.sha.Reset()
	h.sha.Write(h.tmp)
	h.sha.Read(st.val)
	if st.db != nil {
		// TODO! Is it safe to Put the slice here?
		// Do all db implementations copy the value provided?
		st.db.Put(st.val, h.tmp)
	}
}

// Hash returns the hash of the current node
// 执行后st.type变为hashedNode,返回树的哈希值
// st.val执行后可能是rlp编码也可能是哈希
func (st *StackTrie) Hash() (h common.Hash) {
	st.hash()
	if len(st.val) != 32 {
		// If the node's RLP isn't 32 bytes long, the node will not
		// be hashed, and instead contain the  rlp-encoding of the
		// node. For the top level node, we need to force the hashing.
		ret := make([]byte, 32)
		h := newHasher(false)
		defer returnHasherToPool(h)
		h.sha.Reset()
		h.sha.Write(st.val)
		h.sha.Read(ret)
		return common.BytesToHash(ret)
	}
	return common.BytesToHash(st.val)
}

// Commit will firstly hash the entrie trie if it's still not hashed
// and then commit all nodes to the associated database. Actually most
// of the trie nodes MAY have been committed already. The main purpose
// here is to commit the root node.
//
// The associated database is expected, otherwise the whole commit
// functionality should be disabled.
// 把整棵树各个节点 hash->rlp 映射写入数据库
// 返回树根的哈希
func (st *StackTrie) Commit() (common.Hash, error) {
	if st.db == nil {
		return common.Hash{}, ErrCommitDisabled
	}
	st.hash()
	if len(st.val) != 32 {
		// If the node's RLP isn't 32 bytes long, the node will not
		// be hashed (and committed), and instead contain the  rlp-encoding of the
		// node. For the top level node, we need to force the hashing+commit.
		ret := make([]byte, 32)
		h := newHasher(false)
		defer returnHasherToPool(h)
		h.sha.Reset()
		h.sha.Write(st.val)
		h.sha.Read(ret)
		st.db.Put(ret, st.val)
		return common.BytesToHash(ret), nil
	}
	return common.BytesToHash(st.val), nil
}
