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

package enode

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Evolution404/simcore/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Keys in the node database.
const (
	dbVersionKey   = "version" // Version of the database to flush if changes
	dbNodePrefix   = "n:"      // Identifier to prefix node entries with
	dbLocalPrefix  = "local:"
	dbDiscoverRoot = "v4"
	dbDiscv5Root   = "v5"

	// These fields are stored per ID and IP, the full key is "n:<ID>:v4:<IP>:findfail".
	// Use nodeItemKey to create those keys.
	dbNodeFindFails = "findfail"
	dbNodePing      = "lastping"
	dbNodePong      = "lastpong"
	dbNodeSeq       = "seq"

	// Local information is keyed by ID only, the full key is "local:<ID>:seq".
	// Use localItemKey to create those keys.
	dbLocalSeq = "seq"
)

const (
	// 超过24小时没有发现的节点就从数据库删除
	dbNodeExpiration = 24 * time.Hour // Time after which an unseen node should be dropped.
	dbCleanupCycle   = time.Hour      // Time period for running the expiration task.
	// nodedb的版本
	dbVersion = 9
)

var (
	errInvalidIP = errors.New("invalid IP")
)

var zeroIP = make(net.IP, 16)

// DB is the node database, storing previously seen nodes and any collected metadata about
// them for QoS purposes.
type DB struct {
	lvl *leveldb.DB // Interface to the database itself
	// expirer函数运行在协程中,这个runner在ensureExpirer函数用于确保expirer只启动一次
	runner sync.Once // Ensures we can start at most one expirer
	// expirer函数在后台一直运行,quit管道用于通知expirer函数结束
	quit chan struct{} // Channel to signal the expiring thread to stop
}

// OpenDB opens a node database for storing and retrieving infos about known peers in the
// network. If no path is given an in-memory, temporary database is constructed.
// 创建一个储存节点的数据库对象
// path为空代表创建内存数据库,否则根据路径创建持久数据库
func OpenDB(path string) (*DB, error) {
	if path == "" {
		return newMemoryDB()
	}
	return newPersistentDB(path)
}

// newMemoryNodeDB creates a new in-memory node database without a persistent backend.
// 创建内存数据库
func newMemoryDB() (*DB, error) {
	// 在内存中创建leveldb对象
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		return nil, err
	}
	return &DB{lvl: db, quit: make(chan struct{})}, nil
}

// newPersistentNodeDB creates/opens a leveldb backed persistent node database,
// also flushing its contents in case of a version mismatch.
// 使用leveldb.OpenFile创建一个在硬盘的持久数据库
func newPersistentDB(path string) (*DB, error) {
	opts := &opt.Options{OpenFilesCacheCapacity: 5}
	// 先直接打开数据库文件
	// 如果有错误,而且报错是ErrCorrupted,那么就尝试恢复文件,恢复还是报错就返回错误
	db, err := leveldb.OpenFile(path, opts)
	if _, iscorrupted := err.(*errors.ErrCorrupted); iscorrupted {
		db, err = leveldb.RecoverFile(path, nil)
	}
	if err != nil {
		return nil, err
	}
	// The nodes contained in the cache correspond to a certain protocol version.
	// Flush all nodes if the version doesn't match.
	// currentVer代表当前版本,就是将int类型转换成可变长度的字节数组
	currentVer := make([]byte, binary.MaxVarintLen64)
	currentVer = currentVer[:binary.PutVarint(currentVer, int64(dbVersion))]

	blob, err := db.Get([]byte(dbVersionKey), nil)
	// 如果数据库里还没保存版本,就保存下来当前版本
	// 如果保存的版本不匹配,清除现在的数据库文件,重新创建数据库
	switch err {
	case leveldb.ErrNotFound:
		// Version not found (i.e. empty cache), insert it
		if err := db.Put([]byte(dbVersionKey), currentVer, nil); err != nil {
			db.Close()
			return nil, err
		}

	// 判断版本是否匹配,如果不匹配删除所有数据库文件,重新创建
	case nil:
		// Version present, flush if different
		if !bytes.Equal(blob, currentVer) {
			db.Close()
			// 删除所有文件,然后重新创建数据库
			if err = os.RemoveAll(path); err != nil {
				return nil, err
			}
			return newPersistentDB(path)
		}
	}
	return &DB{lvl: db, quit: make(chan struct{})}, nil
}

// nodeKey returns the database key for a node record.
// 根据节点的id获取在数据库中的key
// 格式就是 n:id:v4
func nodeKey(id ID) []byte {
	key := append([]byte(dbNodePrefix), id[:]...)
	key = append(key, ':')
	key = append(key, dbDiscoverRoot...)
	return key
}

// splitNodeKey returns the node ID of a key created by nodeKey.
// 根据数据库里的key,解析出来节点的ID
// 返回节点的id 和 key在id后面剩余的部分
// n:id:v4
func splitNodeKey(key []byte) (id ID, rest []byte) {
	if !bytes.HasPrefix(key, []byte(dbNodePrefix)) {
		return ID{}, nil
	}
	item := key[len(dbNodePrefix):]
	copy(id[:], item[:len(id)])
	return id, item[len(id)+1:]
}

// nodeItemKey returns the database key for a node metadata field.
// 拼接出来节点其他参数的key
// 格式是 n:id:v4:ip16:field
func nodeItemKey(id ID, ip net.IP, field string) []byte {
	ip16 := ip.To16()
	if ip16 == nil {
		panic(fmt.Errorf("invalid IP (length %d)", len(ip)))
	}
	return bytes.Join([][]byte{nodeKey(id), ip16, []byte(field)}, []byte{':'})
}

// splitNodeItemKey returns the components of a key created by nodeItemKey.
// 将NodeItemKey里的各个元素切分开
// key里面保存的ip是ip16,但是解析出来的ip会区分出来ipv4或者ipv6
func splitNodeItemKey(key []byte) (id ID, ip net.IP, field string) {
	// 切分key,调用之后key是id后面剩余的部分
	id, key = splitNodeKey(key)
	// Skip discover root.
	// 如果剩余的部分只有"v4"那就结束
	if string(key) == dbDiscoverRoot {
		return id, nil, ""
	}
	// 跳过"v4:",加一是还有一个冒号,读取下面的部分
	key = key[len(dbDiscoverRoot)+1:]
	// Split out the IP.
	ip = key[:16]
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	key = key[16+1:]
	// Field is the remainder of key.
	field = string(key)
	return id, ip, field
}

// v5的key的格式如下
// n:id:v5:ip16:field
func v5Key(id ID, ip net.IP, field string) []byte {
	return bytes.Join([][]byte{
		[]byte(dbNodePrefix),
		id[:],
		[]byte(dbDiscv5Root),
		ip.To16(),
		[]byte(field),
	}, []byte{':'})
}

// localItemKey returns the key of a local node item.
// localItemKey的格式是
// local:id:field
func localItemKey(id ID, field string) []byte {
	key := append([]byte(dbLocalPrefix), id[:]...)
	key = append(key, ':')
	key = append(key, field...)
	return key
}

// fetchInt64 retrieves an integer associated with a particular key.
// 获取数据库中key对应的int64值
func (db *DB) fetchInt64(key []byte) int64 {
	blob, err := db.lvl.Get(key, nil)
	if err != nil {
		return 0
	}
	val, read := binary.Varint(blob)
	if read <= 0 {
		return 0
	}
	return val
}

// storeInt64 stores an integer in the given key.
// 向指定的key保存int64
func (db *DB) storeInt64(key []byte, n int64) error {
	blob := make([]byte, binary.MaxVarintLen64)
	blob = blob[:binary.PutVarint(blob, n)]
	return db.lvl.Put(key, blob, nil)
}

// fetchUint64 retrieves an integer associated with a particular key.
// 获取key对应的uint64值
func (db *DB) fetchUint64(key []byte) uint64 {
	blob, err := db.lvl.Get(key, nil)
	if err != nil {
		return 0
	}
	val, _ := binary.Uvarint(blob)
	return val
}

// storeUint64 stores an integer in the given key.
// 设置key对应的值为指定uint64
func (db *DB) storeUint64(key []byte, n uint64) error {
	blob := make([]byte, binary.MaxVarintLen64)
	blob = blob[:binary.PutUvarint(blob, n)]
	return db.lvl.Put(key, blob, nil)
}

// Node retrieves a node with a given id from the database.
// 输入节点ID从数据库中读取Node对象
func (db *DB) Node(id ID) *Node {
	blob, err := db.lvl.Get(nodeKey(id), nil)
	if err != nil {
		return nil
	}
	return mustDecodeNode(id[:], blob)
}

// 输入节点id和节点rlp编码解析出来Node对象
// 创建一个Node对象,需要设置r和id
func mustDecodeNode(id, data []byte) *Node {
	node := new(Node)
	if err := rlp.DecodeBytes(data, &node.r); err != nil {
		panic(fmt.Errorf("p2p/enode: can't decode node %x in DB: %v", id, err))
	}
	// Restore node id cache.
	copy(node.id[:], id)
	return node
}

// UpdateNode inserts - potentially overwriting - a node into the peer database.
// 将输入的节点保存到数据库中
// 输入的节点的Seq要大于数据库中存在的
// 每个节点在数据库中占用两个字段
//   nodeKey(node.ID())用来保存节点的rlp编码
//   nodeItemKey(node.ID(),zeroIP,dbNodeSeq)保存节点的Seq
func (db *DB) UpdateNode(node *Node) error {
	// 更新的节点的seq一定要大于现有的
	if node.Seq() < db.NodeSeq(node.ID()) {
		return nil
	}
	blob, err := rlp.EncodeToBytes(&node.r)
	if err != nil {
		return err
	}
	// 更新数据库中保存的节点rlp编码
	if err := db.lvl.Put(nodeKey(node.ID()), blob, nil); err != nil {
		return err
	}
	// 更新数据库中节点的seq
	return db.storeUint64(nodeItemKey(node.ID(), zeroIP, dbNodeSeq), node.Seq())
}

// NodeSeq returns the stored record sequence number of the given node.
// 获取指定节点的seq
func (db *DB) NodeSeq(id ID) uint64 {
	return db.fetchUint64(nodeItemKey(id, zeroIP, dbNodeSeq))
}

// Resolve returns the stored record of the node if it has a larger sequence
// number than n.
// 输入一个Node对象,判断输入的对象和数据库中哪个seq更大,返回seq更大的结果
func (db *DB) Resolve(n *Node) *Node {
	if n.Seq() > db.NodeSeq(n.ID()) {
		return n
	}
	return db.Node(n.ID())
}

// DeleteNode deletes all information associated with a node.
// 删除数据库所有和这个节点有关的信息
func (db *DB) DeleteNode(id ID) {
	deleteRange(db.lvl, nodeKey(id))
}

// 删除所有key的前缀是prefix的键值对
func deleteRange(db *leveldb.DB, prefix []byte) {
	it := db.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()
	for it.Next() {
		db.Delete(it.Key(), nil)
	}
}

// ensureExpirer is a small helper method ensuring that the data expiration
// mechanism is running. If the expiration goroutine is already running, this
// method simply returns.
//
// The goal is to start the data evacuation only after the network successfully
// bootstrapped itself (to prevent dumping potentially useful seed nodes). Since
// it would require significant overhead to exactly trace the first successful
// convergence, it's simpler to "ensure" the correct state when an appropriate
// condition occurs (i.e. a successful bonding), and discard further events.
func (db *DB) ensureExpirer() {
	db.runner.Do(func() { go db.expirer() })
}

// expirer should be started in a go routine, and is responsible for looping ad
// infinitum and dropping stale data from the database.
// 每小时周期性的调用db.expireNodes
func (db *DB) expirer() {
	tick := time.NewTicker(dbCleanupCycle)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			db.expireNodes()
		case <-db.quit:
			return
		}
	}
}

// expireNodes iterates over the database and deletes all nodes that have not
// been seen (i.e. received a pong from) for some time.
func (db *DB) expireNodes() {
	// 生成一个遍历所有节点信息的迭代器
	it := db.lvl.NewIterator(util.BytesPrefix([]byte(dbNodePrefix)), nil)
	defer it.Release()
	if !it.Next() {
		return
	}

	var (
		threshold    = time.Now().Add(-dbNodeExpiration).Unix()
		youngestPong int64
		// atEnd用来标记迭代器是不是还有下一个元素,没有元素了就为true
		atEnd = false
	)
	for !atEnd {
		// 找到记录节点回复pong的时间
		// 判断节点上一次pong的时间,超过24小时就删除节点
		id, ip, field := splitNodeItemKey(it.Key())
		if field == dbNodePong {
			time, _ := binary.Varint(it.Value())
			if time > youngestPong {
				youngestPong = time
			}
			// 上一次pong的时间距今超过24小时
			if time < threshold {
				// Last pong from this IP older than threshold, remove fields belonging to it.
				deleteRange(db.lvl, nodeItemKey(id, ip, ""))
			}
		}
		atEnd = !it.Next()
		nextID, _ := splitNodeKey(it.Key())
		// 如果迭代到末尾或者进入了下一个节点的信息
		if atEnd || nextID != id {
			// We've moved beyond the last entry of the current ID.
			// Remove everything if there was no recent enough pong.
			if youngestPong > 0 && youngestPong < threshold {
				deleteRange(db.lvl, nodeKey(id))
			}
			youngestPong = 0
		}
	}
}

// LastPingReceived retrieves the time of the last ping packet received from
// a remote node.
// 获取指定节点的lastping时间
// 也就是上次接收到来自这个节点ping包的时间
func (db *DB) LastPingReceived(id ID, ip net.IP) time.Time {
	if ip = ip.To16(); ip == nil {
		return time.Time{}
	}
	return time.Unix(db.fetchInt64(nodeItemKey(id, ip, dbNodePing)), 0)
}

// UpdateLastPingReceived updates the last time we tried contacting a remote node.
// 更新指定节点的lastping时间
// 更新上次接收到来自这个节点ping包的时间为指定的时间
func (db *DB) UpdateLastPingReceived(id ID, ip net.IP, instance time.Time) error {
	if ip = ip.To16(); ip == nil {
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodePing), instance.Unix())
}

// LastPongReceived retrieves the time of the last successful pong from remote node.
// 获取指定节点lastpong的时间
// 调用过LastPongReceived后,就会在后台启动删除过期节点的协程
// 过期节点就是超过一小时没有收到pong包的节点
func (db *DB) LastPongReceived(id ID, ip net.IP) time.Time {
	if ip = ip.To16(); ip == nil {
		return time.Time{}
	}
	// Launch expirer
	db.ensureExpirer()
	return time.Unix(db.fetchInt64(nodeItemKey(id, ip, dbNodePong)), 0)
}

// UpdateLastPongReceived updates the last pong time of a node.
// 更新指定节点lastpong的时间
func (db *DB) UpdateLastPongReceived(id ID, ip net.IP, instance time.Time) error {
	if ip = ip.To16(); ip == nil {
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodePong), instance.Unix())
}

// FindFails retrieves the number of findnode failures since bonding.
// 获取指定节点findfail的次数
func (db *DB) FindFails(id ID, ip net.IP) int {
	if ip = ip.To16(); ip == nil {
		return 0
	}
	return int(db.fetchInt64(nodeItemKey(id, ip, dbNodeFindFails)))
}

// UpdateFindFails updates the number of findnode failures since bonding.
// 更新指定节点findfail的次数
func (db *DB) UpdateFindFails(id ID, ip net.IP, fails int) error {
	if ip = ip.To16(); ip == nil {
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodeFindFails), int64(fails))
}

// FindFailsV5 retrieves the discv5 findnode failure counter.
// 获取指定节点findfail的次数(v5版本)
func (db *DB) FindFailsV5(id ID, ip net.IP) int {
	if ip = ip.To16(); ip == nil {
		return 0
	}
	return int(db.fetchInt64(v5Key(id, ip, dbNodeFindFails)))
}

// UpdateFindFailsV5 stores the discv5 findnode failure counter.
// 更新指定节点findfail的次数(V5版本)
func (db *DB) UpdateFindFailsV5(id ID, ip net.IP, fails int) error {
	if ip = ip.To16(); ip == nil {
		return errInvalidIP
	}
	return db.storeInt64(v5Key(id, ip, dbNodeFindFails), int64(fails))
}

// localSeq retrieves the local record sequence counter, defaulting to the current
// timestamp if no previous exists. This ensures that wiping all data associated
// with a node (apart from its key) will not generate already used sequence nums.
// 获取指定节点本地保存的seq
func (db *DB) localSeq(id ID) uint64 {
	if seq := db.fetchUint64(localItemKey(id, dbLocalSeq)); seq > 0 {
		return seq
	}
	return nowMilliseconds()
}

// storeLocalSeq stores the local record sequence counter.
// 更新指定节点本地保存保存的seq
func (db *DB) storeLocalSeq(id ID, n uint64) {
	db.storeUint64(localItemKey(id, dbLocalSeq), n)
}

// QuerySeeds retrieves random nodes to be used as potential seed nodes
// for bootstrapping.
// 从数据库中随机出来最多n个节点
// 随机出来的节点距离上次响应时间都不超过maxAge
// 这个函数用于启动的时候获取初始的节点
func (db *DB) QuerySeeds(n int, maxAge time.Duration) []*Node {
	var (
		now   = time.Now()
		nodes = make([]*Node, 0, n)
		// 用来遍历整个数据库
		it = db.lvl.NewIterator(nil, nil)
		id ID
	)
	defer it.Release()

seek:
	// seeks用来记录这个循环运行的次数,为了避免运行过久这个循环最多运行n*5次
	for seeks := 0; len(nodes) < n && seeks < n*5; seeks++ {
		// Seek to a random entry. The first byte is incremented by a
		// random amount each time in order to increase the likelihood
		// of hitting all existing nodes in very small databases.
		// 循环每次随机取到数据库中的一个node
		ctr := id[0]
		rand.Read(id[:])
		id[0] = ctr + id[0]%16
		it.Seek(nodeKey(id))

		n := nextNode(it)
		// 随机的key后面没有节点了,重新随机一个
		if n == nil {
			id[0] = 0
			continue seek // iterator exhausted
		}
		// 随机出来的节点lastpong过去太久了,重新随机一个
		if now.Sub(db.LastPongReceived(n.ID(), n.IP())) > maxAge {
			continue seek
		}
		// 随机到的节点与之前取到的重复了,重新随机一个
		for i := range nodes {
			if nodes[i].ID() == n.ID() {
				continue seek // duplicate
			}
		}
		// 新增随机到的节点
		nodes = append(nodes, n)
	}
	return nodes
}

// reads the next node record from the iterator, skipping over other
// database entries.
// 解析出来数据库中的下一个Node
func nextNode(it iterator.Iterator) *Node {
	for end := false; !end; end = !it.Next() {
		id, rest := splitNodeKey(it.Key())
		// 跳过所有这个节点相关的key,只关心nodeKey
		// 查找到这个节点保存的rlp编码
		if string(rest) != dbDiscoverRoot {
			continue
		}
		return mustDecodeNode(id[:], it.Value())
	}
	return nil
}

// close flushes and closes the database files.
// 关闭节点数据库
func (db *DB) Close() {
	close(db.quit)
	db.lvl.Close()
}
