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

package trie

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/core/rawdb"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/metrics"
	"github.com/Evolution404/simcore/rlp"
)

var (
	memcacheCleanHitMeter   = metrics.NewRegisteredMeter("trie/memcache/clean/hit", nil)
	memcacheCleanMissMeter  = metrics.NewRegisteredMeter("trie/memcache/clean/miss", nil)
	memcacheCleanReadMeter  = metrics.NewRegisteredMeter("trie/memcache/clean/read", nil)
	memcacheCleanWriteMeter = metrics.NewRegisteredMeter("trie/memcache/clean/write", nil)

	memcacheDirtyHitMeter   = metrics.NewRegisteredMeter("trie/memcache/dirty/hit", nil)
	memcacheDirtyMissMeter  = metrics.NewRegisteredMeter("trie/memcache/dirty/miss", nil)
	memcacheDirtyReadMeter  = metrics.NewRegisteredMeter("trie/memcache/dirty/read", nil)
	memcacheDirtyWriteMeter = metrics.NewRegisteredMeter("trie/memcache/dirty/write", nil)

	memcacheFlushTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/flush/time", nil)
	memcacheFlushNodesMeter = metrics.NewRegisteredMeter("trie/memcache/flush/nodes", nil)
	memcacheFlushSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/flush/size", nil)

	memcacheGCTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/gc/time", nil)
	memcacheGCNodesMeter = metrics.NewRegisteredMeter("trie/memcache/gc/nodes", nil)
	memcacheGCSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/gc/size", nil)

	memcacheCommitTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/commit/time", nil)
	memcacheCommitNodesMeter = metrics.NewRegisteredMeter("trie/memcache/commit/nodes", nil)
	memcacheCommitSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/commit/size", nil)
)

// Database is an intermediate write layer between the trie data structures and
// the disk database. The aim is to accumulate trie writes in-memory and only
// periodically flush a couple tries to disk, garbage collecting the remainder.
//
// Note, the trie Database is **not** thread safe in its mutations, but it **is**
// thread safe in providing individual, independent node access. The rationale
// behind this split design is to provide read access to RPC handlers and sync
// servers even while the trie is executing expensive garbage collection.
// Database类型是保存在内存中的梅克尔树与保存在硬盘中的数据库的中间层
// 数据先写入到内存中,积累到足够数量再写入到硬盘中
type Database struct {
	diskdb ethdb.KeyValueStore // Persistent storage for matured trie nodes

	// 缓存一些节点
	// Put函数中会将最近提交的节点放入cleans
	// 每次访问硬盘数据库拿到的节点数据也会放入cleans
	// 也就是最近使用的数据就加入到缓存中
	// fastcache会自动管理保存在内部的数据,这里使用只需要关心加入缓存
	cleans  *fastcache.Cache            // GC friendly memory cache of clean node RLPs
	// 对梅克尔树中的节点进行引用计数
	dirties map[common.Hash]*cachedNode // Data and references relationships of dirty trie nodes
	// flush-list双向链表
	// 在Cap函数中按照从oldest到newest的顺序写入
	oldest  common.Hash                 // Oldest tracked node, flush-list head
	newest  common.Hash                 // Newest tracked node, flush-list tail

	preimages map[common.Hash][]byte // Preimages of nodes from the secure trie

	// gc数据每次commit后会归零
	// gc相关数据只在dereference中使用
	gctime  time.Duration      // Time spent on garbage collection since last commit
	gcnodes uint64             // Nodes garbage collected since last commit
	gcsize  common.StorageSize // Data storage garbage collected since last commit

	// flush数据每次commit后会归零
	// 记录自从上次commit至今写入硬盘总共使用的时间
	flushtime  time.Duration      // Time spent on data flushing since last commit
	// 记录自从上次commit至今已经写入硬盘的节点个数
	flushnodes uint64             // Nodes flushed since last commit
	// 记录自从上次commit至今已经写入硬盘的总大小
	flushsize  common.StorageSize // Data storage flushed since last commit

	dirtiesSize   common.StorageSize // Storage size of the dirty node cache (exc. metadata)
	childrenSize  common.StorageSize // Storage size of the external children tracking
	preimagesSize common.StorageSize // Storage size of the preimages cache

	lock sync.RWMutex
}

// rawNode is a simple binary blob used to differentiate between collapsed trie
// nodes and already encoded RLP binary blobs (while at the same time store them
// in the same cache fields).
// 用于区分collapsed节点和rlp编码后的节点
// rawNode代表原始的节点,保存了rlp编码
type rawNode []byte

func (n rawNode) cache() (hashNode, bool)   { panic("this should never end up in a live trie") }
func (n rawNode) fstring(ind string) string { panic("this should never end up in a live trie") }

// rawNode类型本身就保存的是rlp编码,所以直接写入
func (n rawNode) EncodeRLP(w io.Writer) error {
	_, err := w.Write(n)
	return err
}

// rawFullNode represents only the useful data content of a full node, with the
// caches and flags stripped out to minimize its data storage. This type honors
// the same RLP encoding as the original parent.
type rawFullNode [17]node

// rawFullNode已经去除了flags字段不再支持cache
func (n rawFullNode) cache() (hashNode, bool)   { panic("this should never end up in a live trie") }
func (n rawFullNode) fstring(ind string) string { panic("this should never end up in a live trie") }

func (n rawFullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	for i, child := range n {
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

// rawShortNode represents only the useful data content of a short node, with the
// caches and flags stripped out to minimize its data storage. This type honors
// the same RLP encoding as the original parent.
// 对shortNode的压缩格式
// key保存了compact格式
type rawShortNode struct {
	Key []byte
	Val node
}

func (n rawShortNode) cache() (hashNode, bool)   { panic("this should never end up in a live trie") }
func (n rawShortNode) fstring(ind string) string { panic("this should never end up in a live trie") }

// cachedNode is all the information we know about a single cached trie node
// in the memory database write layer.
// 保存梅克尔树节点在内存数据库中的各种状态
// node的类型可能是rawNode,rawShortNode,rawFullNode
type cachedNode struct {
	// 这里的node可能是rawNode,rawShortNode,rawFullNode
	// rawNode类型保存了rlp编码
	// rawShortNode,rawFullNode是去掉了flags字段后的类型
	// hashNode,valueNode就保存了哈希或者值的字节数组
	node node   // Cached collapsed trie node, or raw rlp data
	size uint16 // Byte size of the useful cached data

	// 这个节点被引用的次数,换句话说也就是父亲的个数
	parents  uint32                 // Number of live nodes referencing this one
	// 记录引用的各个节点的次数
	children map[common.Hash]uint16 // External children referenced by this node

	// 用于flush-list链表,每个cachedNode都在flush-list链表中
	flushPrev common.Hash // Previous node in the flush-list
	flushNext common.Hash // Next node in the flush-list
}

// cachedNodeSize is the raw size of a cachedNode data structure without any
// node data included. It's an approximate size, but should be a lot better
// than not counting them.
var cachedNodeSize = int(reflect.TypeOf(cachedNode{}).Size())

// cachedNodeChildrenSize is the raw size of an initialized but empty external
// reference map.
const cachedNodeChildrenSize = 48

// rlp returns the raw rlp encoded blob of the cached trie node, either directly
// from the cache, or by regenerating it from the collapsed node.
// 获取cachedNode的rlp编码
// 如果是rawNode类型直接返回,否则进行计算编码
func (n *cachedNode) rlp() []byte {
	if node, ok := n.node.(rawNode); ok {
		return node
	}
	blob, err := rlp.EncodeToBytes(n.node)
	if err != nil {
		panic(err)
	}
	return blob
}

// obj returns the decoded and expanded trie node, either directly from the cache,
// or by regenerating it from the rlp encoded blob.
// 从cachedNode转化为shortNode,fullNodee 输入hash用来恢复flags字段
func (n *cachedNode) obj(hash common.Hash) node {
	// rawNode类型从rlp编码进行解码
	if node, ok := n.node.(rawNode); ok {
		return mustDecodeNode(hash[:], node)
	}
	// rawShortNode,rawFullNode的情况根据对象内部的数据进行恢复
	return expandNode(hash[:], n.node)
}

// forChilds invokes the callback for all the tracked children of this node,
// both the implicit ones from inside the node as well as the explicit ones
// from outside the node.
// 对cachedNode的每一个children调用onChild
// 如果n.node不是rawNode还将对n.node整棵树上的hashNode调用onChild
func (n *cachedNode) forChilds(onChild func(hash common.Hash)) {
	for child := range n.children {
		onChild(child)
	}
	if _, ok := n.node.(rawNode); !ok {
		forGatherChildren(n.node, onChild)
	}
}

// forGatherChildren traverses the node hierarchy of a collapsed storage node and
// invokes the callback for all the hashnode children.
// 输入的node是梅克尔树,树中节点由rawFullNode,rawShortNode组成
// 遍历梅克尔树,每遇到一个hashNode输入它的哈希调用onChild
func forGatherChildren(n node, onChild func(hash common.Hash)) {
	switch n := n.(type) {
	case *rawShortNode:
		forGatherChildren(n.Val, onChild)
	case rawFullNode:
		for i := 0; i < 16; i++ {
			forGatherChildren(n[i], onChild)
		}
	case hashNode:
		onChild(common.BytesToHash(n))
	case valueNode, nil, rawNode:
	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// simplifyNode将shortNode,fullNode转化为rawShortNode,rawFullNode
// expandNode将rawShortNode,rawFullNode转化为shortNode,fullNode
// 两者对valueNode,hashNode都不进行操作
// simplifyNode输入rawNode不进行操作,expandNode输入rawNode将报错

// simplifyNode traverses the hierarchy of an expanded memory node and discards
// all the internal caches, returning a node that only contains the raw data.
// 去掉整棵树的flags字段变成rawShortNode和rawFullNode类型
func simplifyNode(n node) node {
	switch n := n.(type) {
	// shortNode丢弃flags字段
	case *shortNode:
		// Short nodes discard the flags and cascade
		return &rawShortNode{Key: n.Key, Val: simplifyNode(n.Val)}

	// fullNode也丢弃flags字段
	case *fullNode:
		// Full nodes discard the flags and cascade
		node := rawFullNode(n.Children)
		for i := 0; i < len(node); i++ {
			if node[i] != nil {
				node[i] = simplifyNode(node[i])
			}
		}
		return node

	case valueNode, hashNode, rawNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// expandNode traverses the node hierarchy of a collapsed storage node and converts
// all fields and keys into expanded memory form.
// 从rawShortNode或者rawFullNode恢复到原来的类型
// valueNode或者hashNode就不进行操作,直接返回
func expandNode(hash hashNode, n node) node {
	switch n := n.(type) {
	case *rawShortNode:
		// Short nodes need key and child expansion
		return &shortNode{
			// rawShortNode中key是compact格式
			Key: compactToHex(n.Key),
			Val: expandNode(nil, n.Val),
			flags: nodeFlag{
				hash: hash,
			},
		}

	case rawFullNode:
		// Full nodes need child expansion
		node := &fullNode{
			flags: nodeFlag{
				hash: hash,
			},
		}
		for i := 0; i < len(node.Children); i++ {
			if n[i] != nil {
				node.Children[i] = expandNode(nil, n[i])
			}
		}
		return node

	case valueNode, hashNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// Config defines all necessary options for database.
type Config struct {
	Cache     int    // Memory allowance (MB) to use for caching trie nodes in memory
	// fastcache保存到的文件
	Journal   string // Journal of clean cache to survive node restarts
	// 是否记录梅克尔树的key的原像
	Preimages bool   // Flag whether the preimage of trie key is recorded
}

// NewDatabase creates a new trie database to store ephemeral trie content before
// its written out to disk or garbage collected. No read cache is created, so all
// data retrievals will hit the underlying disk database.
// 创建一个梅克尔树的内存数据库
func NewDatabase(diskdb ethdb.KeyValueStore) *Database {
	return NewDatabaseWithConfig(diskdb, nil)
}

// NewDatabaseWithConfig creates a new trie database to store ephemeral trie content
// before its written out to disk or garbage collected. It also acts as a read cache
// for nodes loaded from disk.
// 根据配置信息新建一个梅克尔树数据库
func NewDatabaseWithConfig(diskdb ethdb.KeyValueStore, config *Config) *Database {
	var cleans *fastcache.Cache
	// 判断配置选项中是否使用了cache,初始化cleans字段
	if config != nil && config.Cache > 0 {
		// fastcache初始化输入的单位是字节,config.Cache保存的是MB所以乘两次1024转化为字节
		if config.Journal == "" {
			cleans = fastcache.New(config.Cache * 1024 * 1024)
		} else {
			cleans = fastcache.LoadFromFileOrNew(config.Journal, config.Cache*1024*1024)
		}
	}
	db := &Database{
		diskdb: diskdb,
		cleans: cleans,
		dirties: map[common.Hash]*cachedNode{{}: {
			children: make(map[common.Hash]uint16),
		}},
	}
	if config == nil || config.Preimages { // TODO(karalabe): Flip to default off in the future
		db.preimages = make(map[common.Hash][]byte)
	}
	return db
}

// DiskDB retrieves the persistent storage backing the trie database.
func (db *Database) DiskDB() ethdb.KeyValueStore {
	return db.diskdb
}

// insert inserts a collapsed trie node into the memory database.
// The blob size must be specified to allow proper size tracking.
// All nodes inserted by this function will be reference tracked
// and in theory should only used for **trie nodes** insertion.
// 插入操作是将节点放入dirties中,并追加到flush-list末尾
//   1. 输入shortNode或者fullNode类型的节点,构造出来cachedNode
//   2. 将cachedNode插入到db.dirties中
//   3. 维护db.oldest,db.newest,db.dirtiesSize,还有cachedNode中的flush list
func (db *Database) insert(hash common.Hash, size int, node node) {
	// If the node's already cached, skip
	if _, ok := db.dirties[hash]; ok {
		return
	}
	memcacheDirtyWriteMeter.Mark(int64(size))

	// Create the cached entry for this node
	// 构造新的cachedNode对象
	entry := &cachedNode{
		node:      simplifyNode(node),
		size:      uint16(size),
		flushPrev: db.newest,
	}
	// 以插入节点为根的树引用的hashNode已经保存在db.dirties中的parents字段都加一
	entry.forChilds(func(child common.Hash) {
		if c := db.dirties[child]; c != nil {
			c.parents++
		}
	})
	db.dirties[hash] = entry

	// Update the flush-list endpoints
	// 如果是插入的第一个,让oldest和newest都初始化为当前这个
	if db.oldest == (common.Hash{}) {
		db.oldest, db.newest = hash, hash
	} else {
		// 不是第一个,修改newest以及让前一个插入的连接到当前这个
		db.dirties[db.newest].flushNext, db.newest = hash, hash
	}
	// 每插入一个新增了一个hash->value键值对
	// 所以大小是 哈希的大小和插入元素的大小之和
	db.dirtiesSize += common.StorageSize(common.HashLength + entry.size)
}

// insertPreimage writes a new trie node pre-image to the memory database if it's
// yet unknown. The method will NOT make a copy of the slice,
// only use if the preimage will NOT be changed later on.
//
// Note, this method assumes that the database's lock is held!
// 修改db.preimages,增加一个键值对
func (db *Database) insertPreimage(hash common.Hash, preimage []byte) {
	// Short circuit if preimage collection is disabled
	if db.preimages == nil {
		return
	}
	// Track the preimage if a yet unknown one
	if _, ok := db.preimages[hash]; ok {
		return
	}
	db.preimages[hash] = preimage
	db.preimagesSize += common.StorageSize(common.HashLength + len(preimage))
}

// node retrieves a cached trie node from memory, or returns nil if none can be
// found in the memory cache.
// 输入哈希从数据库读取节点,返回的是shortNode或者fullNode
// 首先从cleans中读
// 其次从dirties中读
// 最次从硬盘数据库中读
func (db *Database) node(hash common.Hash) node {
	// Retrieve the node from the clean cache if available
	// 先尝试从cleans中读取
	if db.cleans != nil {
		if enc := db.cleans.Get(nil, hash[:]); enc != nil {
			memcacheCleanHitMeter.Mark(1)
			memcacheCleanReadMeter.Mark(int64(len(enc)))
			return mustDecodeNode(hash[:], enc)
		}
	}
	// Retrieve the node from the dirty cache if available
	// 再尝试从dirties中读取
	db.lock.RLock()
	dirty := db.dirties[hash]
	db.lock.RUnlock()

	if dirty != nil {
		memcacheDirtyHitMeter.Mark(1)
		memcacheDirtyReadMeter.Mark(int64(dirty.size))
		return dirty.obj(hash)
	}
	memcacheDirtyMissMeter.Mark(1)

	// Content unavailable in memory, attempt to retrieve from disk
	// 最后从硬盘数据库中读取
	enc, err := db.diskdb.Get(hash[:])
	if err != nil || enc == nil {
		return nil
	}
	// 从数据库中读取后加入到cleans中
	if db.cleans != nil {
		db.cleans.Set(hash[:], enc)
		memcacheCleanMissMeter.Mark(1)
		memcacheCleanWriteMeter.Mark(int64(len(enc)))
	}
	return mustDecodeNode(hash[:], enc)
}

// Node retrieves an encoded cached trie node from memory. If it cannot be found
// cached, the method queries the persistent database for the content.
// 从数据库中查询节点,返回的是rlp编码,字节数组
// 先从cleans中查询,再从dirties中查询,最后从diskdb中查询
// 从diskdb中查询成功后会缓存到cleans中
func (db *Database) Node(hash common.Hash) ([]byte, error) {
	// It doesn't make sense to retrieve the metaroot
	if hash == (common.Hash{}) {
		return nil, errors.New("not found")
	}
	// Retrieve the node from the clean cache if available
	if db.cleans != nil {
		if enc := db.cleans.Get(nil, hash[:]); enc != nil {
			memcacheCleanHitMeter.Mark(1)
			memcacheCleanReadMeter.Mark(int64(len(enc)))
			return enc, nil
		}
	}
	// Retrieve the node from the dirty cache if available
	db.lock.RLock()
	dirty := db.dirties[hash]
	db.lock.RUnlock()

	if dirty != nil {
		memcacheDirtyHitMeter.Mark(1)
		memcacheDirtyReadMeter.Mark(int64(dirty.size))
		return dirty.rlp(), nil
	}
	memcacheDirtyMissMeter.Mark(1)

	// Content unavailable in memory, attempt to retrieve from disk
	enc := rawdb.ReadTrieNode(db.diskdb, hash)
	if len(enc) != 0 {
		if db.cleans != nil {
			db.cleans.Set(hash[:], enc)
			memcacheCleanMissMeter.Mark(1)
			memcacheCleanWriteMeter.Mark(int64(len(enc)))
		}
		return enc, nil
	}
	return nil, errors.New("not found")
}

// preimage retrieves a cached trie node pre-image from memory. If it cannot be
// found cached, the method queries the persistent database for the content.
// 输入哈希获取原像
// 先从preimage中读取,读取不到从diskdb中读取
func (db *Database) preimage(hash common.Hash) []byte {
	// Short circuit if preimage collection is disabled
	if db.preimages == nil {
		return nil
	}
	// Retrieve the node from cache if available
	db.lock.RLock()
	preimage := db.preimages[hash]
	db.lock.RUnlock()

	if preimage != nil {
		return preimage
	}
	return rawdb.ReadPreimage(db.diskdb, hash)
}

// Nodes retrieves the hashes of all the nodes cached within the memory database.
// This method is extremely expensive and should only be used to validate internal
// states in test code.
// 返回dirties中保存的所有节点的哈希
func (db *Database) Nodes() []common.Hash {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var hashes = make([]common.Hash, 0, len(db.dirties))
	for hash := range db.dirties {
		if hash != (common.Hash{}) { // Special case for "root" references/nodes
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// Reference adds a new reference from a parent node to a child node.
// This function is used to add reference between internal trie node
// and external node(e.g. storage trie root), all internal trie nodes
// are referenced together by database itself.
// 用来在外部节点和内部节点间增加引用
func (db *Database) Reference(child common.Hash, parent common.Hash) {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.reference(child, parent)
}

// reference is the private locked version of Reference.
func (db *Database) reference(child common.Hash, parent common.Hash) {
	// If the node does not exist, it's a node pulled from disk, skip
	node, ok := db.dirties[child]
	if !ok {
		return
	}
	// If the reference already exists, only duplicate for roots
	if db.dirties[parent].children == nil {
		db.dirties[parent].children = make(map[common.Hash]uint16)
		db.childrenSize += cachedNodeChildrenSize
	// parent已经引用了child直接返回
	// parent为common.Hash说明child是一个根节点
	// 根节点被多次引用的时候parent都是common.Hash,所以这里让parent!=common.Hash
	// 好计算根节点被引用的次数
	} else if _, ok = db.dirties[parent].children[child]; ok && parent != (common.Hash{}) {
		return
	}
	node.parents++
	db.dirties[parent].children[child]++
	// 只有第一次才需要增加大小
	// 能执行到这里只有根节点可能引用次数大于1
	// hash->uint16,所以是一个哈希的大小加上uint16的大小
	if db.dirties[parent].children[child] == 1 {
		db.childrenSize += common.HashLength + 2 // uint16 counter
	}
}

// Dereference removes an existing reference from a root node.
// 输入树根,对这个树根解引用
func (db *Database) Dereference(root common.Hash) {
	// Sanity check to ensure that the meta-root is not removed
	if root == (common.Hash{}) {
		log.Error("Attempted to dereference the trie cache meta root")
		return
	}
	db.lock.Lock()
	defer db.lock.Unlock()

	// nodes保存解引用之前的dirties中节点个数,用于计算gcnodes
	// storage保存解引用之前的dirtiesSize,用于计算gcsize
	nodes, storage, start := len(db.dirties), db.dirtiesSize, time.Now()
	// 删除对整棵树的引用
	db.dereference(root, common.Hash{})

	// 利用之前的数据与现在的数据之间的差,计算gc相关数据
	db.gcnodes += uint64(nodes - len(db.dirties))
	db.gcsize += storage - db.dirtiesSize
	db.gctime += time.Since(start)

	memcacheGCTimeTimer.Update(time.Since(start))
	memcacheGCSizeMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheGCNodesMeter.Mark(int64(nodes - len(db.dirties)))

	log.Debug("Dereferenced trie from memory database", "nodes", nodes-len(db.dirties), "size", storage-db.dirtiesSize, "time", time.Since(start),
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)
}

// dereference is the private locked version of Dereference.
// 删除parent对child的引用
// 首先操作parent的children以及childrenSize
// 然后让child.parent减一
// 如果child.parent减一后为0说明这个child不再被引用,要从flush-list中删除
func (db *Database) dereference(child common.Hash, parent common.Hash) {
	// Dereference the parent-child
	node := db.dirties[parent]

	// child还保存在node.children中,尝试从node.children中删除这个child的映射
	if node.children != nil && node.children[child] > 0 {
		// 父节点对子节点的引用次数减一
		node.children[child]--
		// 如果这个父节点不再引用这个子节点了,那么就从父节点的children里删除
		if node.children[child] == 0 {
			delete(node.children, child)
			db.childrenSize -= (common.HashLength + 2) // uint16 counter
		}
	}
	// If the child does not exist, it's a previously committed node.
	// child不在node.children中,说明之前提交过了
	node, ok := db.dirties[child]
	if !ok {
		return
	}
	// If there are no more references to the child, delete it and cascade
	// 子节点的引用次数减一
	if node.parents > 0 {
		// This is a special cornercase where a node loaded from disk (i.e. not in the
		// memcache any more) gets reinjected as a new node (short node split into full,
		// then reverted into short), causing a cached node to have no parents. That is
		// no problem in itself, but don't make maxint parents out of it.
		node.parents--
	}
	// 如果不再有节点引用该子节点,那么就删除它
	if node.parents == 0 {
		// Remove the node from the flush-list
		switch child {
		// child是oldest那么oldest变成child的下一个
		case db.oldest:
			db.oldest = node.flushNext
			db.dirties[node.flushNext].flushPrev = common.Hash{}
		// child是newest那么newest变成child的前一个
		case db.newest:
			db.newest = node.flushPrev
			db.dirties[node.flushPrev].flushNext = common.Hash{}
		default:
			// 一般情况的链表操作
			db.dirties[node.flushPrev].flushNext = node.flushNext
			db.dirties[node.flushNext].flushPrev = node.flushPrev
		}
		// Dereference all children and delete the node
		// 要删除这个节点,这个节点作为父节点,对其子节点也都要dereference
		node.forChilds(func(hash common.Hash) {
			db.dereference(hash, child)
		})
		delete(db.dirties, child)
		db.dirtiesSize -= common.StorageSize(common.HashLength + int(node.size))
		// 这个节点初始化过children的话,最终删除的时候也去掉这部分空间
		if node.children != nil {
			db.childrenSize -= cachedNodeChildrenSize
		}
	}
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold.
//
// Note, this method is a non-synchronized mutator. It is unsafe to call this
// concurrently with other mutators.
// 将保存在内存中的数据写入到数据库中,使得内存占用小于输入的大小
// 根据flush-lits中的顺序来写入数据库,从oldest开始依次写入,newest最后写入
func (db *Database) Cap(limit common.StorageSize) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	// 记录写入数据库前有多少dirties,dirtiesSize
	nodes, storage, start := len(db.dirties), db.dirtiesSize, time.Now()
	batch := db.diskdb.NewBatch()

	// db.dirtiesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted.
	size := db.dirtiesSize + common.StorageSize((len(db.dirties)-1)*cachedNodeSize)
	size += db.childrenSize - common.StorageSize(len(db.dirties[common.Hash{}].children)*(common.HashLength+2))

	// If the preimage cache got large enough, push to disk. If it's still small
	// leave for later to deduplicate writes.
	// 如果preimage的容量达到使用限制,先向数据库写入preimages
	flushPreimages := db.preimagesSize > 4*1024*1024
	if flushPreimages {
		if db.preimages == nil {
			log.Error("Attempted to write preimages whilst disabled")
		} else {
			rawdb.WritePreimages(batch, db.preimages)
			if batch.ValueSize() > ethdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					return err
				}
				batch.Reset()
			}
		}
	}
	// Keep committing nodes from the flush-list until we're below allowance
	// 遍历flush-list,进行写入
	oldest := db.oldest
	for size > limit && oldest != (common.Hash{}) {
		// Fetch the oldest referenced node and push into the batch
		node := db.dirties[oldest]
		rawdb.WriteTrieNode(batch, oldest, node.rlp())

		// If we exceeded the ideal batch size, commit and reset
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Error("Failed to write flush list to disk", "err", err)
				return err
			}
			batch.Reset()
		}
		// Iterate to the next flush item, or abort if the size cap was achieved. Size
		// is the total size, including the useful cached data (hash -> blob), the
		// cache item metadata, as well as external children mappings.
		// 计算写入这个节点后减少了多少size
		size -= common.StorageSize(common.HashLength + int(node.size) + cachedNodeSize)
		if node.children != nil {
			size -= common.StorageSize(cachedNodeChildrenSize + len(node.children)*(common.HashLength+2))
		}
		// 链表后移
		oldest = node.flushNext
	}
	// Flush out any remainder data from the last batch
	// 写入上面循环结束后剩余的数据
	if err := batch.Write(); err != nil {
		log.Error("Failed to write flush list to disk", "err", err)
		return err
	}
	// Write successful, clear out the flushed data
	db.lock.Lock()
	defer db.lock.Unlock()

	// 重置preimages
	if flushPreimages {
		if db.preimages == nil {
			log.Error("Attempted to reset preimage cache whilst disabled")
		} else {
			db.preimages, db.preimagesSize = make(map[common.Hash][]byte), 0
		}
	}
	// 从flush-list中删除已经写入的节点
	// 从dirties中删除已经写入的节点
	// 重新计算dirtiesSize
	for db.oldest != oldest {
		node := db.dirties[db.oldest]
		delete(db.dirties, db.oldest)
		db.oldest = node.flushNext

		db.dirtiesSize -= common.StorageSize(common.HashLength + int(node.size))
		if node.children != nil {
			db.childrenSize -= common.StorageSize(cachedNodeChildrenSize + len(node.children)*(common.HashLength+2))
		}
	}
	if db.oldest != (common.Hash{}) {
		db.dirties[db.oldest].flushPrev = common.Hash{}
	}
	// 之前的len(dirties)与现在的len(dirties)的差就是写入的节点个数
	db.flushnodes += uint64(nodes - len(db.dirties))
	db.flushsize += storage - db.dirtiesSize
	db.flushtime += time.Since(start)

	memcacheFlushTimeTimer.Update(time.Since(start))
	memcacheFlushSizeMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheFlushNodesMeter.Mark(int64(nodes - len(db.dirties)))

	log.Debug("Persisted nodes from memory database", "nodes", nodes-len(db.dirties), "size", storage-db.dirtiesSize, "time", time.Since(start),
		"flushnodes", db.flushnodes, "flushsize", db.flushsize, "flushtime", db.flushtime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	return nil
}

// Commit iterates over all the children of a particular node, writes them out
// to disk, forcefully tearing down all references in both directions. As a side
// effect, all pre-images accumulated up to this point are also written.
//
// Note, this method is a non-synchronized mutator. It is unsafe to call this
// concurrently with other mutators.
func (db *Database) Commit(node common.Hash, report bool, callback func(common.Hash)) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	// 该函数要先完成硬盘数据库读写才删除内存中的数据
	// 避免已经在内存中删除了但是还没有写入硬盘的情况发生
	start := time.Now()
	batch := db.diskdb.NewBatch()

	// Move all of the accumulated preimages into a write batch
	if db.preimages != nil {
		rawdb.WritePreimages(batch, db.preimages)
		// Since we're going to replay trie node writes into the clean cache, flush out
		// any batched pre-images before continuing.
		if err := batch.Write(); err != nil {
			return err
		}
		batch.Reset()
	}
	// Move the trie itself into the batch, flushing if enough data is accumulated
	nodes, storage := len(db.dirties), db.dirtiesSize

	// 将db包装成cleaner,用于作为Replay的参数,在写入硬盘后清理内存中的dirties
	uncacher := &cleaner{db}
	if err := db.commit(node, batch, uncacher, callback); err != nil {
		log.Error("Failed to commit trie from trie database", "err", err)
		return err
	}
	// Trie mostly committed to disk, flush any batch leftovers
	// 写入硬盘数据库中,这里没有判断IdealBatchSize,因为一定要写入
	if err := batch.Write(); err != nil {
		log.Error("Failed to write trie to disk", "err", err)
		return err
	}
	// Uncache any leftovers in the last batch
	db.lock.Lock()
	defer db.lock.Unlock()

	// 清理缓存在内存中的数据
	batch.Replay(uncacher)
	batch.Reset()

	// Reset the storage counters and bumped metrics
	if db.preimages != nil {
		db.preimages, db.preimagesSize = make(map[common.Hash][]byte), 0
	}
	memcacheCommitTimeTimer.Update(time.Since(start))
	memcacheCommitSizeMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheCommitNodesMeter.Mark(int64(nodes - len(db.dirties)))

	logger := log.Info
	if !report {
		logger = log.Debug
	}
	logger("Persisted trie from memory database", "nodes", nodes-len(db.dirties)+int(db.flushnodes), "size", storage-db.dirtiesSize+db.flushsize, "time", time.Since(start)+db.flushtime,
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	// Reset the garbage collection statistics
	// 重置垃圾回收统计数据
	db.gcnodes, db.gcsize, db.gctime = 0, 0, 0
	db.flushnodes, db.flushsize, db.flushtime = 0, 0, 0

	return nil
}

// commit is the private locked version of Commit.
// 递归写入整棵树
func (db *Database) commit(hash common.Hash, batch ethdb.Batch, uncacher *cleaner, callback func(common.Hash)) error {
	// If the node does not exist, it's a previously committed node
	node, ok := db.dirties[hash]
	if !ok {
		return nil
	}
	var err error
	// 向下递归整棵树,所有节点都调用commit
	node.forChilds(func(child common.Hash) {
		if err == nil {
			err = db.commit(child, batch, uncacher, callback)
		}
	})
	if err != nil {
		return err
	}
	// If we've reached an optimal batch size, commit and start over
	rawdb.WriteTrieNode(batch, hash, node.rlp())
	if callback != nil {
		callback(hash)
	}
	if batch.ValueSize() >= ethdb.IdealBatchSize {
		if err := batch.Write(); err != nil {
			return err
		}
		db.lock.Lock()
		// 每次写入之后都重放到uncacher中,用来清理内存
		batch.Replay(uncacher)
		batch.Reset()
		db.lock.Unlock()
	}
	return nil
}

// cleaner is a database batch replayer that takes a batch of write operations
// and cleans up the trie database from anything written to disk.
// 实现了KeyValueWriter接口
// 目的是可以作为batch.Replay的参数
// 调用Replay方法时已经写入了硬盘数据库,可以开始清理内存中的数据
// batch中保存了对硬盘数据库的写入操作
// 将这些写入操作重放到cleaner中,意味着将dirties中数据移除并写入到cleans中
type cleaner struct {
	db *Database
}

// Put reacts to database writes and implements dirty data uncaching. This is the
// post-processing step of a commit operation where the already persisted trie is
// removed from the dirty cache and moved into the clean cache. The reason behind
// 将节点从flush-list中移除,然后从dirties中移除
// 如果有cleans的话将移除的节点加入cleans
// the two-phase commit is to ensure data availability while moving from memory
// to disk.
func (c *cleaner) Put(key []byte, rlp []byte) error {
	hash := common.BytesToHash(key)

	// If the node does not exist, we're done on this path
	node, ok := c.db.dirties[hash]
	if !ok {
		return nil
	}
	// Node still exists, remove it from the flush-list
	// 首先从flush-list中移除
	switch hash {
	case c.db.oldest:
		c.db.oldest = node.flushNext
		c.db.dirties[node.flushNext].flushPrev = common.Hash{}
	case c.db.newest:
		c.db.newest = node.flushPrev
		c.db.dirties[node.flushPrev].flushNext = common.Hash{}
	default:
		c.db.dirties[node.flushPrev].flushNext = node.flushNext
		c.db.dirties[node.flushNext].flushPrev = node.flushPrev
	}
	// Remove the node from the dirty cache
	// 然后从dirties中移除
	delete(c.db.dirties, hash)
	c.db.dirtiesSize -= common.StorageSize(common.HashLength + int(node.size))
	if node.children != nil {
		c.db.dirtiesSize -= common.StorageSize(cachedNodeChildrenSize + len(node.children)*(common.HashLength+2))
	}
	// Move the flushed node into the clean cache to prevent insta-reloads
	// 有可能的加入到cleans中
	if c.db.cleans != nil {
		c.db.cleans.Set(hash[:], rlp)
		memcacheCleanWriteMeter.Mark(int64(len(rlp)))
	}
	return nil
}

func (c *cleaner) Delete(key []byte) error {
	panic("not implemented")
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
func (db *Database) Size() (common.StorageSize, common.StorageSize) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	// db.dirtiesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted.
	var metadataSize = common.StorageSize((len(db.dirties) - 1) * cachedNodeSize)
	var metarootRefs = common.StorageSize(len(db.dirties[common.Hash{}].children) * (common.HashLength + 2))
	return db.dirtiesSize + db.childrenSize + metadataSize - metarootRefs, db.preimagesSize
}

// saveCache saves clean state cache to given directory path
// using specified CPU cores.
// 可以指定线程数保存fastcache到文件中
func (db *Database) saveCache(dir string, threads int) error {
	// 根本没用fastcache直接返回
	if db.cleans == nil {
		return nil
	}
	log.Info("Writing clean trie cache to disk", "path", dir, "threads", threads)

	start := time.Now()
	err := db.cleans.SaveToFileConcurrent(dir, threads)
	if err != nil {
		log.Error("Failed to persist clean trie cache", "error", err)
		return err
	}
	log.Info("Persisted the clean trie cache", "path", dir, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}

// SaveCache atomically saves fast cache data to the given dir using all
// available CPU cores.
// 保存fastcache到文件中,使用cpu的所有核心
func (db *Database) SaveCache(dir string) error {
	return db.saveCache(dir, runtime.GOMAXPROCS(0))
}

// SaveCachePeriodically atomically saves fast cache data to the given dir with
// the specified interval. All dump operation will only use a single CPU core.
// 定期将db.clean保存到文件中,使用单线程保存
func (db *Database) SaveCachePeriodically(dir string, interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.saveCache(dir, 1)
		case <-stopCh:
			return
		}
	}
}
