// Copyright 2019 The go-ethereum Authors
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
	"errors"
	"fmt"
	"sync"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/crypto"
	"golang.org/x/crypto/sha3"
)

// leafChanSize is the size of the leafCh. It's a pretty arbitrary number, to allow
// some parallelism but not incur too much memory overhead.
// 在Trie.Commit中使用 trie.go文件中
// 控制创建的leafCh管道的缓冲区的大小
const leafChanSize = 200

// leaf represents a trie leaf value
// 代表梅克尔树的叶子节点
type leaf struct {
	size int         // size of the rlp data (estimate)
	hash common.Hash // hash of rlp data
	node node        // the node to commit
}

// committer is a type used for the trie Commit operation. A committer has some
// internal preallocated temp space, and also a callback that is invoked when
// leaves are committed. The leafs are passed through the `leafCh`,  to allow
// some level of parallelism.
// By 'some level' of parallelism, it's still the case that all leaves will be
// processed sequentially - onleaf will never be called in parallel or out of order.
// committer内部有预分配的空间tmp
// onleaf将在处理完叶子节点后调用
type committer struct {
	tmp sliceBuffer
	sha crypto.KeccakState

	onleaf LeafCallback
	leafCh chan *leaf
}

// committers live in a global sync.Pool
var committerPool = sync.Pool{
	New: func() interface{} {
		return &committer{
			tmp: make(sliceBuffer, 0, 550), // cap is as large as a full fullNode.
			sha: sha3.NewLegacyKeccak256().(crypto.KeccakState),
		}
	},
}

// newCommitter creates a new committer or picks one from the pool.
func newCommitter() *committer {
	return committerPool.Get().(*committer)
}

func returnCommitterToPool(h *committer) {
	h.onleaf = nil
	h.leafCh = nil
	committerPool.Put(h)
}

// Commit collapses a node down into a hash node and inserts it into the database
// 向db中提交node,返回node压缩后的hashNode
// 输入的n是缓存树的树根
func (c *committer) Commit(n node, db *Database) (hashNode, int, error) {
	if db == nil {
		return nil, 0, errors.New("no db provided")
	}
	// 由于输入的n是缓存树的树根,这里返回的h一定是一个hashNode
	// 因为树根被强制计算了哈希,所以一定有缓存的哈希
	h, committed, err := c.commit(n, db)
	if err != nil {
		return nil, 0, err
	}
	return h.(hashNode), committed, nil
}

// commit collapses a node down into a hash node and inserts it into the database
func (c *committer) commit(n node, db *Database) (node, int, error) {
	// if this path is clean, use available cached data
	hash, dirty := n.cache()
	// 有缓存的哈希,还没被修改过,那么直接返回就得了
	if hash != nil && !dirty {
		return hash, 0, nil
	}
	// Commit children, then parent, and remove remove the dirty flag.
	// 输入的node只要是shortNode或者fullNode就会调用store在其中发送到leafCh中
	// 但是commitLoop中会判断接收的node是不是内嵌了valueNode,只有valueNode才会调用回调
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		collapsed := cn.copy()

		// If the child is fullNode, recursively commit,
		// otherwise it can only be hashNode or valueNode.
		// 处理子节点,hashNode,valueNode不需要特殊处理
		// 子节点是fullNode进行递归的commit
		var childCommitted int
		if _, ok := cn.Val.(*fullNode); ok {
			childV, committed, err := c.commit(cn.Val, db)
			if err != nil {
				return nil, 0, err
			}
			collapsed.Val, childCommitted = childV, committed
		}
		// The key needs to be copied, since we're delivering it to database
		collapsed.Key = hexToCompact(cn.Key)
		hashedNode := c.store(collapsed, db)
		// 可能保存成了hashNode,也可能由于rlp编码长度不足32没变成hashNode
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, childCommitted + 1, nil
		}
		return collapsed, childCommitted, nil
	case *fullNode:
		hashedKids, childCommitted, err := c.commitChildren(cn, db)
		if err != nil {
			return nil, 0, err
		}
		collapsed := cn.copy()
		collapsed.Children = hashedKids

		hashedNode := c.store(collapsed, db)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, childCommitted + 1, nil
		}
		return collapsed, childCommitted, nil
	case hashNode:
		return cn, 0, nil
	default:
		// nil, valuenode shouldn't be committed
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// commitChildren commits the children of the given fullnode
// 输入fullNode,对所有子节点进行提交
// 返回的node前16项都是hashNode,第17项可能valueNode
func (c *committer) commitChildren(n *fullNode, db *Database) ([17]node, int, error) {
	var (
		committed int
		children  [17]node
	)
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		// If it's the hashed child, save the hash value directly.
		// Note: it's impossible that the child in range [0, 15]
		// is a valueNode.
		// 如果是hashNode的话,进行类型转换
		if hn, ok := child.(hashNode); ok {
			children[i] = hn
			continue
		}
		// Commit the child recursively and store the "hashed" value.
		// Note the returned node can be some embedded nodes, so it's
		// possible the type is not hashNode.
		hashed, childCommitted, err := c.commit(child, db)
		if err != nil {
			return children, 0, err
		}
		children[i] = hashed
		committed += childCommitted
	}
	// For the 17th child, it's possible the type is valuenode.
	if n.Children[16] != nil {
		children[16] = n.Children[16]
	}
	return children, committed, nil
}

// store hashes the node n and if we have a storage layer specified, it writes
// the key/value pair to it and tracks any node->child references as well as any
// node->external trie references.
// 输入的n如果cache是nil直接返回n,不会操作leafCh或者db
// 输入的n有cache的话返回缓存的hash
// 在有leafCh的情况下向leafCh发送输入的node
// 如果没有leafCh但是db不是nil的话调用db.insert
func (c *committer) store(n node, db *Database) node {
	// Larger nodes are replaced by their hash and stored in the database.
	var (
		hash, _ = n.cache()
		size    int
	)
	if hash == nil {
		// This was not generated - must be a small node stored in the parent.
		// In theory, we should apply the leafCall here if it's not nil(embedded
		// node usually contains value). But small value(less than 32bytes) is
		// not our target.
		return n
	} else {
		// We have the hash already, estimate the RLP encoding-size of the node.
		// The size is used for mem tracking, does not need to be exact
		size = estimateSize(n)
	}
	// If we're using channel-based leaf-reporting, send to channel.
	// The leaf channel will be active only when there an active leaf-callback
	// 每保存一个叶子就向leafCh发送一个leaf对象
	if c.leafCh != nil {
		c.leafCh <- &leaf{
			size: size,
			hash: common.BytesToHash(hash),
			node: n,
		}
	} else if db != nil {
		// No leaf-callback used, but there's still a database. Do serial
		// insertion
		db.lock.Lock()
		db.insert(common.BytesToHash(hash), size, n)
		db.lock.Unlock()
	}
	return hash
}

// commitLoop does the actual insert + leaf callback for nodes.
// 从c.leafCh不断接收叶子节点
func (c *committer) commitLoop(db *Database) {
	// 当管道被关闭的时候for停止
	for item := range c.leafCh {
		var (
			hash = item.hash
			size = item.size
			n    = item.node
		)
		// We are pooling the trie nodes into an intermediate memory cache
		db.lock.Lock()
		db.insert(hash, size, n)
		db.lock.Unlock()

		// 只有内嵌了valueNode的才能调用回调函数
		if c.onleaf != nil {
			switch n := n.(type) {
			case *shortNode:
				if child, ok := n.Val.(valueNode); ok {
					c.onleaf(nil, nil, child, hash)
				}
			case *fullNode:
				// For children in range [0, 15], it's impossible
				// to contain valueNode. Only check the 17th child.
				if n.Children[16] != nil {
					c.onleaf(nil, nil, n.Children[16].(valueNode), hash)
				}
			}
		}
	}
}

// 输入原始数据data,计算data的哈希值,然后返回hashNode
func (c *committer) makeHashNode(data []byte) hashNode {
	n := make(hashNode, c.sha.Size())
	c.sha.Reset()
	c.sha.Write(data)
	c.sha.Read(n)
	return n
}

// estimateSize estimates the size of an rlp-encoded node, without actually
// rlp-encoding it (zero allocs). This method has been experimentally tried, and with a trie
// with 1000 leafs, the only errors above 1% are on small shortnodes, where this
// method overestimates by 2 or 3 bytes (e.g. 37 instead of 35)
// 估算一棵树进行rlp编码后的大小
func estimateSize(n node) int {
	// 估算过程中把rlp编码的前缀长度都当成3
	// 也就是说预计各个元素的长度都大于55
	switch n := n.(type) {
	case *shortNode:
		// A short node contains a compacted key, and a value.
		// 加三是rlp编码的前缀
		return 3 + len(n.Key) + estimateSize(n.Val)
	case *fullNode:
		// A full node contains up to 16 hashes (some nils), and a key
		s := 3
		for i := 0; i < 16; i++ {
			if child := n.Children[i]; child != nil {
				s += estimateSize(child)
			} else {
				s++
			}
		}
		return s
	case valueNode:
		return 1 + len(n)
	case hashNode:
		return 1 + len(n)
	default:
		panic(fmt.Sprintf("node type %T", n))
	}
}
