// Copyright 2015 The go-ethereum Authors
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

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.

// Table是Kademlia算法保存邻居节点的数据结构

package discover

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/netutil"
)

const (
	alpha = 3 // Kademlia concurrency factor
	// 一个桶内保存的节点个数
	bucketSize      = 16 // Kademlia bucket size
	maxReplacements = 10 // Size of per-bucket replacement list

	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // Number of buckets
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket

	// IP address limits.
	// 用来限制来自同一个子网的ip的个数
	// 分为桶级限制和表级限制,子网的前缀都设置为24bit
	// 同一个桶内同一个子网的节点最多2个
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	// 整个表内同一个子网的节点个数最多10个
	tableIPLimit, tableSubnet = 10, 24

	refreshInterval = 30 * time.Minute
	// 每次重新检测一个节点的时间间隔是10s内的随机数值
	revalidateInterval = 10 * time.Second
	copyNodesInterval  = 30 * time.Second
	// 在表内存储超过5分钟且ping通的节点会被保存到数据库中
	seedMinTableTime = 5 * time.Minute
	// 一次从数据库中读取30个节点
	seedCount = 30
	// 从数据库中读取的节点距离当前最多五天
	seedMaxAge = 5 * 24 * time.Hour
)

// Table is the 'node table', a Kademlia-like index of neighbor nodes. The table keeps
// itself up-to-date by verifying the liveness of neighbors and requesting their node
// records when announcements of a new record version are received.
type Table struct {
	mutex sync.Mutex // protects buckets, bucket content, nursery, rand
	// 根据距离放置的节点
	buckets [nBuckets]*bucket // index of known nodes by distance
	// 启动的时候自带的节点,当所有桶内都没有节点而且数据库内也没有节点时使用
	nursery []*node // bootstrap nodes
	// 随机数生成器,定期更新随机数生成器,保证表的一些随机操作的安全性
	rand *mrand.Rand // source of randomness, periodically reseeded
	// 用来限制具有共同前缀的ip个数不能过多
	ips netutil.DistinctNetSet

	log log.Logger
	db  *enode.DB // database of known nodes
	net transport
	// 触发refresh操作
	refreshReq chan chan struct{}
	// 用来标记第一次调用doRefresh是否完成
	// 第一次doRefresh完成后这个管道就会被关闭
	initDone chan struct{}
	closeReq chan struct{}
	// 用来标记所有操作都已经关闭
	closed chan struct{}

	// 一旦有节点加入到桶中就调用这个回调函数
	nodeAddedHook func(*node) // for testing
}

// transport is implemented by the UDP transports.
// transport接口由UDPv4和UDPv5实现
type transport interface {
	Self() *enode.Node
	// 请求远程节点获取最新的记录
	RequestENR(*enode.Node) (*enode.Node, error)
	lookupRandom() []*enode.Node
	lookupSelf() []*enode.Node
	// ping一个远程节点,获得最新的序列号
	ping(*enode.Node) (seq uint64, err error)
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
// bucket中保存距离都在一个范围内的节点,entries是当前在线节点,replacements是替补节点
type bucket struct {
	// 当前在线的所有节点,按照上次联系的时间进行排序
	entries []*node // live entries, sorted by time of last contact
	// entries中断连后用来替补的节点
	replacements []*node // recently seen nodes to be used if revalidation fails
	// 每个桶内也对一个子网的ip个数有限制
	ips netutil.DistinctNetSet
}

// 创建一个节点表对象，并进行初始化操作
// 初始化随机数种子、从节点数据库加载至多30个节点
func newTable(t transport, db *enode.DB, bootnodes []*enode.Node, log log.Logger) (*Table, error) {
	tab := &Table{
		net:        t,
		db:         db,
		refreshReq: make(chan chan struct{}),
		initDone:   make(chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
		rand:       mrand.New(mrand.NewSource(0)),
		// 整个表内同一个子网ip的节点不能超过10个
		ips: netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
		log: log,
	}
	if err := tab.setFallbackNodes(bootnodes); err != nil {
		return nil, err
	}
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			// 每个桶内同一个子网ip的节点不能超过2个
			ips: netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: bucketIPLimit},
		}
	}
	// 为随机数生成器初始化一个种子
	tab.seedRand()
	// 从数据库保存的节点中加载30个出来保存到桶里
	tab.loadSeedNodes()

	return tab, nil
}

func (tab *Table) self() *enode.Node {
	return tab.net.Self()
}

// 使用crypto/rand库生成种子提供给math/rand用以生成随机数
func (tab *Table) seedRand() {
	// 新的种子使用密码学级别的随机数
	var b [8]byte
	crand.Read(b[:])

	tab.mutex.Lock()
	// 重置随机数种子
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
}

// ReadRandomNodes fills the given slice with random nodes from the table. The results
// are guaranteed to be unique for a single invocation, no node will appear twice.
// 选取随机的节点到buf中,选取的个数是buf的长度
// 返回填充的节点个数
func (tab *Table) ReadRandomNodes(buf []*enode.Node) (n int) {
	if !tab.isInitDone() {
		return 0
	}
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// 获取表内的所有节点
	var nodes []*enode.Node
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes = append(nodes, unwrapNode(n))
		}
	}
	// Shuffle.
	// 然后将所有节点的列表重新乱序排一下
	for i := 0; i < len(nodes); i++ {
		j := tab.rand.Intn(len(nodes))
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	// 返回乱序后的前n个节点
	return copy(buf, nodes)
}

// getNode returns the node with the given ID or nil if it isn't in the table.
// 从表中根据id读取一个节点
func (tab *Table) getNode(id enode.ID) *enode.Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bucket(id)
	for _, e := range b.entries {
		if e.ID() == id {
			return unwrapNode(e)
		}
	}
	return nil
}

// close terminates the network listener and flushes the node database.
// 关闭网络监听,保存所有数据到节点数据库
func (tab *Table) close() {
	// 首先关闭closeReq管道
	//   触发loop函数执行操作,loop中执行操作完成后会关闭closed管道
	close(tab.closeReq)
	// 等待loop函数完成剩余的操作
	<-tab.closed
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
// 设置初始查询节点,当节点表为空且节点数据库为空的时候将查询初始节点
// 初始节点被保存到Table.nursery中
func (tab *Table) setFallbackNodes(nodes []*enode.Node) error {
	for _, n := range nodes {
		// 输入的节点中有任何一个出现问题都直接返回错误
		if err := n.ValidateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap node %q: %v", n, err)
		}
	}
	// 封装起来保存到nursery中
	tab.nursery = wrapNodes(nodes)
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
// 判断第一次刷新操作是否已经完成
func (tab *Table) isInitDone() bool {
	// 如果initDone管道被关闭说明第一次刷新操作完成
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

// 通过此方法主动触发表的刷新操作,返回done管道用于等待刷新完成
func (tab *Table) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	// 向refreshReq管道发送一个done管道,通知loop方法进行刷新操作
	case tab.refreshReq <- done:
	case <-tab.closeReq:
		close(done)
	}
	// done管道将在刷新过程完成后被关闭,所以外部监听此管道等待刷新完成
	return done
}

// loop schedules runs of doRefresh, doRevalidate and copyLiveNodes.
// loop在单独一个协程中启动,用于执行节点表的三种定时操作
// 1. 每30分钟一次的刷新操作
// 2. 每10秒内随机时间触发一次的节点重生效操作
// 3. 每30秒一次的节点保存操作
func (tab *Table) loop() {

	var (
		// 重生效10秒内的随机时间触发一次,所以没使用Ticker
		revalidate = time.NewTimer(tab.nextRevalidateTime())
		// 刷新30分钟触发一次
		refresh = time.NewTicker(refreshInterval)
		// 保存节点30秒触发一次
		copyNodes = time.NewTicker(copyNodesInterval)
		// 没有进行刷新操作时为nil;正在进行刷新不为nil,刷新结束接收到通知
		refreshDone    = make(chan struct{}) // where doRefresh reports completion
		revalidateDone chan struct{}         // where doRevalidate reports completion
		// 正在刷新过程中发送的刷新请求都保存到这里
		waiting = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
	)
	defer refresh.Stop()
	defer revalidate.Stop()
	defer copyNodes.Stop()

	// Start initial refresh.
	// 启动第一次刷新过程
	go tab.doRefresh(refreshDone)

loop:
	for {
		select {
		// 刷新有两种触发方式：定时触发、手动触发以下两个分支监听这两种情况
		case <-refresh.C:
			tab.seedRand()
			// 没有正在进行刷新,才会调用刷新方法
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		case req := <-tab.refreshReq:
			// 保存刷新请求,加入到等待列表中
			waiting = append(waiting, req)
			// 没有正在进行刷新,才会调用刷新方法
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		// 刷新完成,通知所有刷新请求已经完成了刷新
		case <-refreshDone:
			for _, ch := range waiting {
				close(ch)
			}
			waiting, refreshDone = nil, nil
		// 执行重生效操作
		case <-revalidate.C:
			revalidateDone = make(chan struct{})
			go tab.doRevalidate(revalidateDone)
		case <-revalidateDone:
			// 每次revalidate的间隔时间不同,需要重新设置revalidate的定时器
			revalidate.Reset(tab.nextRevalidateTime())
			revalidateDone = nil
		// 执行节点保存操作
		case <-copyNodes.C:
			go tab.copyLiveNodes()
		// 外部关闭了closeReq管道,循环结束处理剩余的内容直到关闭closed管道,代表Table完全关闭
		case <-tab.closeReq:
			break loop
		}
	}

	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}
	if revalidateDone != nil {
		<-revalidateDone
	}
	close(tab.closed)
}

// doRefresh performs a lookup for a random target to keep buckets full. seed nodes are
// inserted if the table is empty (initial bootstrap or discarded faulty peers).
// 输入的管道用来通知调用完成,函数结束关闭done管道,外部调用者监听传入的管道就可以知道调用完成
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	// 加载一些节点
	tab.loadSeedNodes()

	// Run self lookup to discover new neighbor nodes.
	tab.net.lookupSelf()

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// We perform a few lookups with a random target instead.
	for i := 0; i < 3; i++ {
		tab.net.lookupRandom()
	}
}

// 从数据库中加载随机的总计最多30个节点保存到各个桶内
func (tab *Table) loadSeedNodes() {
	// 从节点数据库中随机查询几个节点
	seeds := wrapNodes(tab.db.QuerySeeds(seedCount, seedMaxAge))
	seeds = append(seeds, tab.nursery...)
	// 将这些节点添加到节点表中
	for i := range seeds {
		seed := seeds[i]
		// 如果不打印这条日志，使用Lazy能避免计算这个age
		age := log.Lazy{Fn: func() interface{} { return time.Since(tab.db.LastPongReceived(seed.ID(), seed.IP())) }}
		tab.log.Trace("Found seed node in database", "id", seed.ID(), "addr", seed.addr(), "age", age)
		tab.addSeenNode(seed)
	}
}

// doRevalidate checks that the last node in a random bucket is still live and replaces or
// deletes the node if it isn't.
// 随机挑选一个桶里的最后一个节点进行ping
//   如果ping通的话就放到桶内的首位
//   ping不通就删除,使用replacements里的随机一个节点替换
func (tab *Table) doRevalidate(done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	// 随机选取一个桶的末尾节点,并得到桶的序号
	last, bi := tab.nodeToRevalidate()
	if last == nil {
		// No non-empty bucket found.
		return
	}

	// Ping the selected node and wait for a pong.
	// 本地主动Ping一下随机节点
	remoteSeq, err := tab.net.ping(unwrapNode(last))

	// Also fetch record if the node replied and returned a higher sequence number.
	// 远程节点的记录序号大于本地的记录,查询远程节点的最新记录
	if last.Seq() < remoteSeq {
		n, err := tab.net.RequestENR(unwrapNode(last))
		if err != nil {
			tab.log.Debug("ENR request failed", "id", last.ID(), "addr", last.addr(), "err", err)
		} else {
			// 更新记录
			last = &node{Node: *n, addedAt: last.addedAt, livenessChecks: last.livenessChecks}
		}
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	// 找到随机节点所在的桶
	b := tab.buckets[bi]
	// 如果刚才Ping通了远程节点,把它放到桶的首位
	if err == nil {
		// The node responded, move it to the front.
		// 存活检测记录加一
		last.livenessChecks++
		tab.log.Debug("Revalidated node", "b", bi, "id", last.ID(), "checks", last.livenessChecks)
		// 移动到首位
		tab.bumpInBucket(b, last)
		return
	}
	// No reply received, pick a replacement or delete the node if there aren't
	// any replacements.
	// 执行到这里说明刚才Ping不通
	// Ping不通的节点使用一个随机替补节点替换
	if r := tab.replace(b, last); r != nil {
		tab.log.Debug("Replaced dead node", "b", bi, "id", last.ID(), "ip", last.IP(), "checks", last.livenessChecks, "r", r.ID(), "rip", r.IP())
		// 桶里面没有替补节点,直接删除
	} else {
		tab.log.Debug("Removed dead node", "b", bi, "id", last.ID(), "ip", last.IP(), "checks", last.livenessChecks)
	}
}

// nodeToRevalidate returns the last node in a random, non-empty bucket.
// 返回一个随机的桶内的最后一个节点,以及桶的下表
// 所有桶都是空的返回nil
func (tab *Table) nodeToRevalidate() (n *node, bi int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// 生成一个桶的顺序的随机序列,按照随机顺序遍历桶
	for _, bi = range tab.rand.Perm(len(tab.buckets)) {
		b := tab.buckets[bi]
		// 找到任意一个不空的桶,返回桶中最后一个元素
		if len(b.entries) > 0 {
			last := b.entries[len(b.entries)-1]
			return last, bi
		}
	}
	return nil, 0
}

// 计算下一次执行重生效过程的时间间隔
// 取10秒内的一个随机时间
func (tab *Table) nextRevalidateTime() time.Duration {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return time.Duration(tab.rand.Int63n(int64(revalidateInterval)))
}

// copyLiveNodes adds nodes from the table to the database if they have been in the table
// longer than seedMinTableTime.
// 每30秒检查一次已经添加到节点表中超过5分钟的节点,将这些节点保存到节点数据库中
func (tab *Table) copyLiveNodes() {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	now := time.Now()
	// 遍历所有节点,将添加时间距今超过5分钟且ping通的节点加入到数据库中
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			if n.livenessChecks > 0 && now.Sub(n.addedAt) >= seedMinTableTime {
				tab.db.UpdateNode(unwrapNode(n))
			}
		}
	}
}

// findnodeByID returns the n nodes in the table that are closest to the given id.
// This is used by the FINDNODE/v4 handler.
//
// The preferLive parameter says whether the caller wants liveness-checked results. If
// preferLive is true and the table contains any verified nodes, the result will not
// contain unverified nodes. However, if there are no verified nodes at all, the result
// will contain unverified nodes.
// 返回表中与target最近的几个节点,nresults表示最多返回的个数
// preferLive为true的话优先返回livenessChecks大于零的节点,如果没有这样的节点就还是返回最近的节点
func (tab *Table) findnodeByID(target enode.ID, nresults int, preferLive bool) *nodesByDistance {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// Scan all buckets. There might be a better way to do this, but there aren't that many
	// buckets, so this solution should be fine. The worst-case complexity of this loop
	// is O(tab.len() * nresults).
	// nodes记录所有节点,liveNodes记录所有livenessChecks大于零的节点
	// 这两个列表遍历后按序保存
	nodes := &nodesByDistance{target: target}
	liveNodes := &nodesByDistance{target: target}
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes.push(n, nresults)
			if preferLive && n.livenessChecks > 0 {
				liveNodes.push(n, nresults)
			}
		}
	}

	// 优先返回livenessChecks大于零的节点
	if preferLive && len(liveNodes.entries) > 0 {
		return liveNodes
	}
	return nodes
}

// len returns the number of nodes in the table.
// 计算所有桶内保存的节点个数的总和
func (tab *Table) len() (n int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// bucketLen returns the number of nodes in the bucket for the given ID.
// 根据id计算所在桶的长度
func (tab *Table) bucketLen(id enode.ID) int {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return len(tab.bucket(id).entries)
}

// bucket returns the bucket for the given node ID hash.
// 根据节点id获取所在的桶
func (tab *Table) bucket(id enode.ID) *bucket {
	// 计算两个节点间的距离
	d := enode.LogDist(tab.self().ID(), id)
	return tab.bucketAtDistance(d)
}

// 根据距离计算所在的桶
func (tab *Table) bucketAtDistance(d int) *bucket {
	// 距离小于最小距离的都放进第一个桶
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	// 其他的按照距离放进不同的桶
	return tab.buckets[d-bucketMinDistance-1]
}

// addSeenNode adds a node which may or may not be live to the end of a bucket. If the
// bucket has space available, adding the node succeeds immediately. Otherwise, the node is
// added to the replacements list.
//
// The caller must not hold tab.mutex.
// 向表中添加一个新发现的节点
// 已经存在于桶内的节点不进行操作
// 如果桶还没满直接加入桶中,桶已经满了就加入到替补节点中
// 也能用于将replacements中的节点移动到桶内
func (tab *Table) addSeenNode(n *node) {
	if n.ID() == tab.self().ID() {
		return
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	// 计算所在的桶
	b := tab.bucket(n.ID())
	// 已经保存在桶中了直接返回
	if contains(b.entries, n.ID()) {
		// Already in bucket, don't add.
		return
	}
	// 如果桶已经满了添加的替补节点中
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		tab.addReplacement(b, n)
		return
	}
	// 现在尝试将节点添加到表中

	// 首先判断是否满足IP限制
	if !tab.addIP(b, n.IP()) {
		// Can't add: IP limit reached.
		return
	}
	// Add to end of bucket:
	// 满足ip限制的节点加入到桶的末尾,并从替补节点中删除
	b.entries = append(b.entries, n)
	b.replacements = deleteNode(b.replacements, n)
	// 记录添加节点的时间
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
}

// addVerifiedNode adds a node whose existence has been verified recently to the front of a
// bucket. If the node is already in the bucket, it is moved to the front. If the bucket
// has no space, the node is added to the replacements list.
//
// There is an additional safety measure: if the table is still initializing the node
// is not added. This prevents an attack where the table could be filled by just sending
// ping repeatedly.
//
// The caller must not hold tab.mutex.
// 也是添加一个节点到桶内
// 不同的是已经存在的节点会被移动到桶的首位
func (tab *Table) addVerifiedNode(n *node) {
	if !tab.isInitDone() {
		return
	}
	if n.ID() == tab.self().ID() {
		return
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.bucket(n.ID())
	// 新添加的节点可能已经在桶中,尝试直接移动到首位
	if tab.bumpInBucket(b, n) {
		// Already in bucket, moved to front.
		return
	}
	// 桶已经满了添加到替补节点
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		tab.addReplacement(b, n)
		return
	}
	if !tab.addIP(b, n.IP()) {
		// Can't add: IP limit reached.
		return
	}
	// Add to front of bucket.
	// 将节点添加到桶的首位,并从替补节点中删除
	b.entries, _ = pushNode(b.entries, n, bucketSize)
	b.replacements = deleteNode(b.replacements, n)
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
}

// delete removes an entry from the node table. It is used to evacuate dead nodes.
// 从节点所在的桶中删除节点
func (tab *Table) delete(node *node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	tab.deleteInBucket(tab.bucket(node.ID()), node)
}

// 用于判断这个ip能不能通过ips的限制
func (tab *Table) addIP(b *bucket, ip net.IP) bool {
	if len(ip) == 0 {
		return false // Nodes without IP cannot be added.
	}
	// 内网地址不进行限制
	if netutil.IsLAN(ip) {
		return true
	}
	// 判断是否触发了表级限制
	if !tab.ips.Add(ip) {
		tab.log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	// 判断是否触发了桶级限制
	if !b.ips.Add(ip) {
		tab.log.Debug("IP exceeds bucket limit", "ip", ip)
		// 刚才在表的ips中添加了,这里移除
		tab.ips.Remove(ip)
		return false
	}
	return true
}

// 让表和桶的ips都移除指定ip
func (tab *Table) removeIP(b *bucket, ip net.IP) {
	if netutil.IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

// 将节点插入到某个桶的替补节点的首位
func (tab *Table) addReplacement(b *bucket, n *node) {
	for _, e := range b.replacements {
		if e.ID() == n.ID() {
			return // already in list
		}
	}
	if !tab.addIP(b, n.IP()) {
		return
	}
	var removed *node
	// 向replacements中最开始位置插入新的节点
	b.replacements, removed = pushNode(b.replacements, n, maxReplacements)
	// 如果有删除的节点,在ips中也要删除
	if removed != nil {
		tab.removeIP(b, removed.IP())
	}
}

// replace removes n from the replacement list and replaces 'last' with it if it is the
// last entry in the bucket. If 'last' isn't the last entry, it has either been replaced
// with someone else or became active.
// 将桶内的最后一个节点删除,并将一个随机替补节点加入到桶的最后
// 返回桶内新增的替补节点,如果没有替补节点返回nil
func (tab *Table) replace(b *bucket, last *node) *node {
	// last必须是entries中的最后一个
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID() != last.ID() {
		// Entry has moved, don't replace it.
		return nil
	}
	// Still the last entry.
	// replacements里面没有节点,只好直接删除
	if len(b.replacements) == 0 {
		tab.deleteInBucket(b, last)
		return nil
	}
	// 从replacements中随机取一个节点r
	r := b.replacements[tab.rand.Intn(len(b.replacements))]
	// 将r从replacements中删除
	b.replacements = deleteNode(b.replacements, r)
	// 将r添加到桶的末尾
	b.entries[len(b.entries)-1] = r
	tab.removeIP(b, last.IP())
	return r
}

// bumpInBucket moves the given node to the front of the bucket entry list
// if it is contained in that list.
// 将已经在桶内的节点n移动到b.entries的开始位置
// 因为ip有可能发生了变化所以需要对ips进行处理
func (tab *Table) bumpInBucket(b *bucket, n *node) bool {
	for i := range b.entries {
		if b.entries[i].ID() == n.ID() {
			// 判断新节点的ip是否发生了变化
			// ip发生了变化需要修正ips的记录
			if !n.IP().Equal(b.entries[i].IP()) {
				// Endpoint has changed, ensure that the new IP fits into table limits.
				tab.removeIP(b, b.entries[i].IP())
				// 如果新的ip超过了ips的限制,就还保持原来的ip,并返回false
				if !tab.addIP(b, n.IP()) {
					// It doesn't, put the previous one back.
					tab.addIP(b, b.entries[i].IP())
					return false
				}
			}
			// Move it to the front.
			// 将这个节点从原来的位置移动到首位
			copy(b.entries[1:], b.entries[:i])
			b.entries[0] = n
			return true
		}
	}
	return false
}

// 从桶内删除一个节点
// 需要从b.entries中移除n
// 还需要表和桶的ips中移除n
func (tab *Table) deleteInBucket(b *bucket, n *node) {
	b.entries = deleteNode(b.entries, n)
	tab.removeIP(b, n.IP())
}

// 判断一批节点内是否有与这个id相同的节点
func contains(ns []*node, id enode.ID) bool {
	for _, n := range ns {
		if n.ID() == id {
			return true
		}
	}
	return false
}

// pushNode adds n to the front of list, keeping at most max items.
// 将新节点n插入list的最开始
// 如果达到最大长度限制,末尾的节点会被挤出来并返回
// 没达到上限返回的removed是nil
func pushNode(list []*node, n *node, max int) ([]*node, *node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}

// deleteNode removes n from list.
// 从列表中删除节点,返回删除后的列表
func deleteNode(list []*node, n *node) []*node {
	for i := range list {
		if list[i].ID() == n.ID() {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// nodesByDistance is a list of nodes, ordered by distance to target.
// 里面保存的所有节点按照距离target从近到远的顺序排列
type nodesByDistance struct {
	entries []*node
	target  enode.ID
}

// push adds the given node to the list, keeping the total size below maxElems.
// 计算n于target的位置,按照距离逐渐变大的顺序将n插入到列表中
// 超过maxElems就移除末尾的元素
func (h *nodesByDistance) push(n *node, maxElems int) {
	// 找到新节点n应该放置的位置ix
	ix := sort.Search(len(h.entries), func(i int) bool {
		// 在列表中找到第一个使得返回结果大于零,也就是刚好距离小于那个节点的位置,也就是n应该插入的位置
		return enode.DistCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})
	// 没到上限直接先追加让列表长度加一,到了上限不追加在下面复制过程中相当于丢掉了最后一个元素
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	if ix == len(h.entries) {
		// farther away than all nodes we already have.
		// if there was room for it, the node is now the last element.
	} else {
		// slide existing entries down to make room
		// this will overwrite the entry we just appended.
		// 全部向后挪,然后把n放到ix上
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
