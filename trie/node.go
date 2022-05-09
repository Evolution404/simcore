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

package trie

import (
	"fmt"
	"io"
	"strings"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/rlp"
)

var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

// 节点的接口,以下四种节点都要实现这两个方法
type node interface {
	fstring(string) string
	cache() (hashNode, bool)
}

// MPT中有四种类型的节点
type (
	// 分支节点
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)
		flags    nodeFlag
	}
	// 叶子节点或者扩展节点
	// Val是valueNode说明本身是叶子节点
	// Val是fullNode类型说明本身是扩展节点
	shortNode struct {
		Key   []byte
		Val   node
		// 小写字母开头的字段不会被编码到rlp中
		flags nodeFlag
	}
	// 表示fullNode或shortNode的rlp编码的哈希值
	// 代表该节点还没有载入内存
	hashNode []byte
	// MPT中真正存储数据的节点,是叶子节点,不能携带子节点
	valueNode []byte
)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
var nilValueNode = valueNode(nil)

// EncodeRLP encodes a full node into the consensus RLP format.
// 对fullNode进行rlp编码,只编码内部的17个node
func (n *fullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	for i, child := range &n.Children {
		// 修改所有child为nil的项为nilValueNode
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy }
func (n *shortNode) copy() *shortNode { copy := *n; return &copy }

// nodeFlag contains caching-related metadata about a node.
type nodeFlag struct {
	hash  hashNode // cached hash of the node (may be nil)
	dirty bool     // whether the node has changes that must be written to the database
}

// fullNode和shortNode需要缓存哈希
// cache函数分别返回缓存的哈希和dirty
func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }

// hashNode,valueNode不需要缓存哈希
func (n hashNode) cache() (hashNode, bool)  { return nil, true }
func (n valueNode) cache() (hashNode, bool) { return nil, true }

// Pretty printing.
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }

func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind)
	for i, node := range &n.Children {
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i])
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  "))
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind)
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  "))
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n))
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n))
}

// 强制解码到node对象,出现错误直接panic
func mustDecodeNode(hash, buf []byte) node {
	n, err := decodeNode(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node.
// 从rlp编码解码到node对象,输入hash用来给解码对象填充flag字段
// 可以解码short和full两种node对象
// 输入的buf最开始一定是一个列表的rlp编码,该函数只解析最开始的这个列表
// short长度是2,full长度是17
// shortNode的编码
//   [key,node]长度是2,node的编码可能是list或者string类型
//   node是编码是list说明当时编码是直接对对象编码->恢复成对应的对象
//   node是string说明编码的是哈希值->恢复成hashNode
// fullNode的编码
func decodeNode(hash, buf []byte) (node, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c {
	case 2:
		n, err := decodeShort(hash, elems)
		return n, wrapError(err, "short")
	case 17:
		n, err := decodeFull(hash, elems)
		return n, wrapError(err, "full")
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c)
	}
}

// 解码返回shortNode对象
// shortNode需要恢复key和val
// key就保存在编码的第一个字符串,使用SplitString后再调用compactToHex
// val保存在编码的第二个字符串,val可能是hashNode或者valueNode,根据key是否有terminator来判断
func decodeShort(hash, elems []byte) (node, error) {
	// 把shortNode的key读取出来
	kbuf, rest, err := rlp.SplitString(elems)
	if err != nil {
		return nil, err
	}
	flag := nodeFlag{hash: hash}
	// rlp编码里保存的是compact格式
	// 解码之后再转换成hex格式
	key := compactToHex(kbuf)
	// 判断是叶子节点,所以Val字段解码成valueNode类型
	if hasTerm(key) {
		// value node
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		return &shortNode{key, append(valueNode{}, val...), flag}, nil
	}
	// 不是叶子节点,解码成hashNode
	r, _, err := decodeRef(rest)
	if err != nil {
		return nil, wrapError(err, "val")
	}
	return &shortNode{key, r, flag}, nil
}

// 解码返回fullNode对象
func decodeFull(hash, elems []byte) (*fullNode, error) {
	n := &fullNode{flags: nodeFlag{hash: hash}}
	// fullNode的前16个元素必然是hashNode
	for i := 0; i < 16; i++ {
		cld, rest, err := decodeRef(elems)
		if err != nil {
			return n, wrapError(err, fmt.Sprintf("[%d]", i))
		}
		n.Children[i], elems = cld, rest
	}
	// 第17个元素可能保存的是空元素
	val, _, err := rlp.SplitString(elems)
	if err != nil {
		return n, err
	}
	// 保存的不是空元素的话进行赋值
	if len(val) > 0 {
		n.Children[16] = append(valueNode{}, val...)
	}
	return n, nil
}

const hashLen = len(common.Hash{})

// 解码返回hashNode对象
func decodeRef(buf []byte) (node, []byte, error) {
	kind, val, rest, err := rlp.Split(buf)
	if err != nil {
		return nil, buf, err
	}
	// 保存引用节点的时候有三种可能
	//   1. 一般的情况直接保存rlp编码的哈希值
	//   2. rlp编码之后小于等于32字节,为了节省空间还减少一次哈希计算直接保存rlp编码,不再计算哈希
	//   3. 空节点,rlp编码的空字符串
	switch {
	// 列表说明直接保存的rlp编码,rlp编码长度必须小于等于32
	case kind == rlp.List:
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		if size := len(buf) - len(rest); size > hashLen {
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err
		}
		// 解码shortNode或者fullNode
		n, err := decodeNode(nil, buf)
		return n, rest, err
	case kind == rlp.String && len(val) == 0:
		// empty node
		return nil, rest, nil
	// 保存了一个哈希值,是hashNode
	case kind == rlp.String && len(val) == 32:
		return append(hashNode{}, val...), rest, nil
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
type decodeError struct {
	what  error
	stack []string
}

func wrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	return &decodeError{err, []string{ctx}}
}

func (err *decodeError) Error() string {
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
