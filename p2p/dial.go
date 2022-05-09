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

package p2p

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/netutil"
)

const (
	// This is the amount of time spent waiting in between redialing a certain node. The
	// limit is a bit higher than inboundThrottleTime to prevent failing dials in small
	// private networks.
	// 重新连接一个节点的时间间隔必须超过35秒
	dialHistoryExpiration = inboundThrottleTime + 5*time.Second

	// Config for the "Looking for peers" message.
	// 打印拨号日志最快的频率是10秒一次
	dialStatsLogInterval = 10 * time.Second // printed at most this often
	// 有大于等于三个节点连接成功,就不再打印拨号日志
	dialStatsPeerLimit = 3 // but not if more than this many dialed peers

	// Endpoint resolution is throttled with bounded backoff.
	// 第一次解析和第二次解析的时间间隔初始为10s
	initialResolveDelay = 60 * time.Second
	// 针对一个节点两次调用Resolve之间的时间间隔最大是一小时
	maxResolveDelay = time.Hour
)

// NodeDialer is used to connect to nodes in the network, typically by using
// an underlying net.Dialer but also using net.Pipe in tests.
// 用来创建与另一个节点的连接
// 这个接口被tcpDialer和SimAdapter实现,tcpDialer是真正的网络连接,SimAdapter是使用内存管道
// 这个Dial方法传入的参数是Context和enode.Node
// 是对下面这个函数的封装,network一般直接指定为tcp,address由enode.Node解析出来
// func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
type NodeDialer interface {
	Dial(context.Context, *enode.Node) (net.Conn, error)
}

// 输入一个节点旧记录获取最新记录
type nodeResolver interface {
	Resolve(*enode.Node) *enode.Node
}

// tcpDialer implements NodeDialer using real TCP connections.
// 实现了NodeDialer接口
type tcpDialer struct {
	d *net.Dialer
}

func (t tcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	return t.d.DialContext(ctx, "tcp", nodeAddr(dest).String())
}

// 将enode.Node对象转化为net.Addr
func nodeAddr(n *enode.Node) net.Addr {
	return &net.TCPAddr{IP: n.IP(), Port: n.TCP()}
}

// checkDial errors:
var (
	errSelf             = errors.New("is self")
	errAlreadyDialing   = errors.New("already dialing")
	errAlreadyConnected = errors.New("already connected")
	errRecentlyDialed   = errors.New("recently dialed")
	errNetRestrict      = errors.New("not contained in netrestrict list")
	errNoPort           = errors.New("node does not provide TCP port")
)

// dialer creates outbound connections and submits them into Server.
// Two types of peer connections can be created:
//
//  - static dials are pre-configured connections. The dialer attempts
//    keep these nodes connected at all times.
//
//  - dynamic dials are created from node discovery results. The dialer
//    continuously reads candidate nodes from its input iterator and attempts
//    to create peer connections to nodes arriving through the iterator.
//
// 有两种情况建立新的连接
// 对于预定义的static nodes,将会不断尝试进行连接
// 从节点发现过程中得到的新节点,将会从迭代器中读取,然后建立连接
type dialScheduler struct {
	dialConfig
	// 在dial函数结束位置调用,生成的连接对象需要经过setupFunc处理
	setupFunc dialSetupFunc
	// stop函数中用来等待readNodes和loop函数结束
	wg     sync.WaitGroup
	cancel context.CancelFunc
	ctx    context.Context
	// 协程readNodes中将会把节点发送到这里
	nodesIn chan *enode.Node
	// dialTask运行完run函数后就发送到doneCh中
	doneCh chan *dialTask
	// 添加一个静态节点 addStatic中使用
	addStaticCh chan *enode.Node
	// 删除一个静态节点 removeStatic中使用
	remStaticCh chan *enode.Node
	// 添加一个节点 peerAdded中使用
	addPeerCh chan *conn
	// 删除一个节点 peerRemoved中使用
	remPeerCh chan *conn

	// Everything below here belongs to loop and
	// should only be accessed by code on the loop goroutine.
	dialing map[enode.ID]*dialTask // active tasks
	// 记录当前所有连接成功的节点
	peers map[enode.ID]struct{} // all connected peers
	// 当前本地主动连接且在线的节点个数
	dialPeers int // current number of dialed peers

	// The static map tracks all static dial tasks. The subset of usable static dial tasks
	// (i.e. those passing checkDial) is kept in staticPool. The scheduler prefers
	// launching random static tasks from the pool over launching dynamic dials from the
	// iterator.
	// 保存了所有的静态节点,静态节点通过Server.AddPeer添加
	static map[enode.ID]*dialTask
	// 保存了所有没有被连接的静态节点
	// 通过AddPeer添加的节点默认加入到staticPool中,如果该节点成功升级为Peer或者调用了RemovePeer就从staticPool中移除
	staticPool []*dialTask

	// The dial history keeps recently dialed nodes. Members of history are not dialed.
	// 在startDial中往history新增记录
	history expHeap
	// 下一个过期元素的计时器,下一个元素过期的时间触发
	historyTimer mclock.Timer
	// 记录historyTimer的触发时间,也就是下一个元素的过期时间
	historyTimerTime mclock.AbsTime

	// for logStats
	// 记录上次在logStats函数中打印了日志的时间
	lastStatsLog mclock.AbsTime
	// 记录上次打印之后doneCh中接受了多少次结果
	doneSinceLastLog int
}

type dialSetupFunc func(net.Conn, connFlag, *enode.Node) error

type dialConfig struct {
	self enode.ID // our own ID
	// 最多主动连接且在线的节点个数
	maxDialPeers int // maximum number of dialed peers
	// 同时拨号的节点最大个数,默认50个
	maxActiveDials int              // maximum number of active dials
	netRestrict    *netutil.Netlist // IP netrestrict list, disabled if nil
	// 包含Resolve方法，用来查询一个节点记录的最新内容
	resolver nodeResolver
	dialer   NodeDialer
	log      log.Logger
	clock    mclock.Clock
	rand     *mrand.Rand
}

// 为输入的配置增加默认选项
func (cfg dialConfig) withDefaults() dialConfig {
	if cfg.maxActiveDials == 0 {
		cfg.maxActiveDials = defaultMaxPendingPeers
	}
	if cfg.log == nil {
		cfg.log = log.Root()
	}
	if cfg.clock == nil {
		cfg.clock = mclock.System{}
	}
	if cfg.rand == nil {
		// 先使用crand生成随机种子,在用这个随机种子生成随机数
		// 因为crand效率低,但是不需要种子就能生成不重复随机数,所以用它生成随机种子
		seedb := make([]byte, 8)
		crand.Read(seedb)
		seed := int64(binary.BigEndian.Uint64(seedb))
		cfg.rand = mrand.New(mrand.NewSource(seed))
	}
	return cfg
}

func newDialScheduler(config dialConfig, it enode.Iterator, setupFunc dialSetupFunc) *dialScheduler {
	d := &dialScheduler{
		dialConfig:  config.withDefaults(),
		setupFunc:   setupFunc,
		dialing:     make(map[enode.ID]*dialTask),
		static:      make(map[enode.ID]*dialTask),
		peers:       make(map[enode.ID]struct{}),
		doneCh:      make(chan *dialTask),
		nodesIn:     make(chan *enode.Node),
		addStaticCh: make(chan *enode.Node),
		remStaticCh: make(chan *enode.Node),
		addPeerCh:   make(chan *conn),
		remPeerCh:   make(chan *conn),
	}
	d.lastStatsLog = d.clock.Now()
	// 初始化d.ctx和d.cancel
	d.ctx, d.cancel = context.WithCancel(context.Background())
	// 阻塞住readNodes和loop函数
	d.wg.Add(2)
	// 从迭代器中不断读取节点,发送到ndoesIn管道
	go d.readNodes(it)
	go d.loop(it)
	return d
}

// stop shuts down the dialer, canceling all current dial tasks.
func (d *dialScheduler) stop() {
	d.cancel()
	d.wg.Wait()
}

// addStatic adds a static dial candidate.
// 添加静态节点,实际上就是向addStaticCh发送通知
func (d *dialScheduler) addStatic(n *enode.Node) {
	select {
	case d.addStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// removeStatic removes a static dial candidate.
func (d *dialScheduler) removeStatic(n *enode.Node) {
	select {
	case d.remStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// peerAdded updates the peer set.
// 当一个节点完成了加密握手和协议握手,那就在这里通知dialScheduler
func (d *dialScheduler) peerAdded(c *conn) {
	select {
	case d.addPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// peerRemoved updates the peer set.
func (d *dialScheduler) peerRemoved(c *conn) {
	select {
	case d.remPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// loop is the main loop of the dialer.
func (d *dialScheduler) loop(it enode.Iterator) {
	var (
		nodesCh chan *enode.Node
		// 当history中任意一个节点到期了,这里会收到通知
		historyExp = make(chan struct{}, 1)
	)

loop:
	for {
		// Launch new dials if slots are available.
		slots := d.freeDialSlots()
		// 首先尝试启动静态节点
		slots -= d.startStaticDials(slots)
		// 如果静态节点没有消耗完slots,那么再从节点发现的迭代器中获取节点
		if slots > 0 {
			nodesCh = d.nodesIn
		} else {
			nodesCh = nil
		}
		d.rearmHistoryTimer(historyExp)
		// 打印日志
		d.logStats()

		select {
		case node := <-nodesCh:
			if err := d.checkDial(node); err != nil {
				d.log.Trace("Discarding dial candidate", "id", node.ID(), "ip", node.IP(), "reason", err)
			} else {
				d.startDial(newDialTask(node, dynDialedConn))
			}

		// 拨号完成的节点,从dialing中删除
		case task := <-d.doneCh:
			id := task.dest.ID()
			delete(d.dialing, id)
			// 针对静态节点,如果没有拨号成功重新加入到staticPool中
			d.updateStaticPool(id)
			d.doneSinceLastLog++

		// 完成了加密握手协议握手还有所有检测真正成为Peer了
		// 如果是主动拨号的节点让dialPeers加一
		// 将新节点id和连接标识位加入到peers
		// 由于连接成功如果是静态节点从staticPool中删除
		case c := <-d.addPeerCh:
			// 让当前拨号的节点个数增加一
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers++
			}
			id := c.node.ID()
			d.peers[id] = struct{}{}
			// Remove from static pool because the node is now connected.
			// 这个节点如果在staticPool中,现在已经连接成功了需要从里面移除
			task := d.static[id]
			if task != nil && task.staticPoolIndex >= 0 {
				d.removeFromStaticPool(task.staticPoolIndex)
			}
			// TODO: cancel dials to connected peers

		// 删除一个对等节点,需要如下三步
		// 如果是主动拨号的节点让dialPeers减一
		// 将节点id和连接标识位从peers移除
		// 由于删除节点如果是静态节点就添加到staticPool
		case c := <-d.remPeerCh:
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers--
			}
			delete(d.peers, c.node.ID())
			d.updateStaticPool(c.node.ID())

		// 通过Server.AddPeer添加的节点被发送到这里
		// 首先加入到d.static中,然后如果还没有和这个节点建立连接就加入到staticPool中
		case node := <-d.addStaticCh:
			id := node.ID()
			_, exists := d.static[id]
			d.log.Trace("Adding static node", "id", id, "ip", node.IP(), "added", !exists)
			if exists {
				continue loop
			}
			task := newDialTask(node, staticDialedConn)
			d.static[id] = task
			// 可以被拨号的加入到staticPool中
			if d.checkDial(node) == nil {
				d.addToStaticPool(task)
			}

		case node := <-d.remStaticCh:
			id := node.ID()
			task := d.static[id]
			d.log.Trace("Removing static node", "id", id, "ok", task != nil)
			if task != nil {
				delete(d.static, id)
				if task.staticPoolIndex >= 0 {
					d.removeFromStaticPool(task.staticPoolIndex)
				}
			}

		case <-historyExp:
			d.expireHistory()

		case <-d.ctx.Done():
			it.Close()
			break loop
		}
	}

	d.stopHistoryTimer(historyExp)
	for range d.dialing {
		<-d.doneCh
	}
	d.wg.Done()
}

// readNodes runs in its own goroutine and delivers nodes from
// the input iterator to the nodesIn channel.
// readNodes在newDialScheduler中调用,执行在一个单独的协程中,不断循环从迭代器中读取节点
func (d *dialScheduler) readNodes(it enode.Iterator) {
	defer d.wg.Done()

	for it.Next() {
		select {
		case d.nodesIn <- it.Node():
		case <-d.ctx.Done():
		}
	}
}

// logStats prints dialer statistics to the log. The message is suppressed when enough
// peers are connected because users should only see it while their client is starting up
// or comes back online.
// 打印当前dialer的一些统计信息,找不到节点一直循环打印的Looking for peers就是在这里
func (d *dialScheduler) logStats() {
	now := d.clock.Now()
	// 判断是否过于频繁
	if d.lastStatsLog.Add(dialStatsLogInterval) > now {
		return
	}
	if d.dialPeers < dialStatsPeerLimit && d.dialPeers < d.maxDialPeers {
		d.log.Info("Looking for peers", "peercount", len(d.peers), "tried", d.doneSinceLastLog, "static", len(d.static))
	}
	d.doneSinceLastLog = 0
	d.lastStatsLog = now
}

// rearmHistoryTimer configures d.historyTimer to fire when the
// next item in d.history expires.
// 更新historyTimerTime为history中下一个过期元素的过期时间
// 当下一个元素到期时间达到后,向参数管道ch中发送通知
func (d *dialScheduler) rearmHistoryTimer(ch chan struct{}) {
	if len(d.history) == 0 || d.historyTimerTime == d.history.nextExpiry() {
		return
	}
	// 需要处理下一个即将过期的元素了,将之前的计时器停止
	d.stopHistoryTimer(ch)
	d.historyTimerTime = d.history.nextExpiry()
	timeout := time.Duration(d.historyTimerTime - d.clock.Now())
	// 设置定时器,当到达下一个元素的到期时间后,向管道ch中发送通知
	d.historyTimer = d.clock.AfterFunc(timeout, func() { ch <- struct{}{} })
}

// stopHistoryTimer stops the timer and drains the channel it sends on.
// 停止historyTimer计时器
func (d *dialScheduler) stopHistoryTimer(ch chan struct{}) {
	// 这里Stop返回false,说明定时器到期了或者之前被停止过了
	// 但是其他会停止这个定时器地方只有expireHistory,调用Stop后立刻清空historyTimer为nil,这里要求不是nil
	// 所以一定不是定时器被停止了,只能是过期了还没有被loop处理
	// 所以清除掉它的缓存
	if d.historyTimer != nil && !d.historyTimer.Stop() {
		<-ch
	}
}

// expireHistory removes expired items from d.history.
// 停止计时器historyTimer,对history执行过期操作,删除过期的元素
func (d *dialScheduler) expireHistory() {
	d.historyTimer.Stop()
	d.historyTimer = nil
	d.historyTimerTime = 0
	d.history.expire(d.clock.Now(), func(hkey string) {
		var id enode.ID
		copy(id[:], hkey)
		d.updateStaticPool(id)
	})
}

// freeDialSlots returns the number of free dial slots. The result can be negative
// when peers are connected while their task is still running.
// 获取还需要对多少个节点进行拨号
func (d *dialScheduler) freeDialSlots() int {
	// maxDialPeers-dialPeers代表当前还缺少多少节点到达同时连接的节点上限
	// 这里的slots代表接下来会去拨号多少个节点
	// 需要乘2是因为拨号的节点基本不可能都成功建立连接,所以设置冗余量
	slots := (d.maxDialPeers - d.dialPeers) * 2
	if slots > d.maxActiveDials {
		slots = d.maxActiveDials
	}
	// 再减去正在进行的拨号过程,就代表还需要进行多少拨号过程
	free := slots - len(d.dialing)
	return free
}

// checkDial returns an error if node n should not be dialed.
// 检查这个节点能不能被拨号
// 已经在拨号的,已经连接的,在限制ip段的,刚刚拨号过的这里都返回错误
func (d *dialScheduler) checkDial(n *enode.Node) error {
	if n.ID() == d.self {
		return errSelf
	}
	if n.IP() != nil && n.TCP() == 0 {
		// This check can trigger if a non-TCP node is found
		// by discovery. If there is no IP, the node is a static
		// node and the actual endpoint will be resolved later in dialTask.
		return errNoPort
	}
	if _, ok := d.dialing[n.ID()]; ok {
		return errAlreadyDialing
	}
	if _, ok := d.peers[n.ID()]; ok {
		return errAlreadyConnected
	}
	if d.netRestrict != nil && !d.netRestrict.Contains(n.IP()) {
		return errNetRestrict
	}
	if d.history.contains(string(n.ID().Bytes())) {
		return errRecentlyDialed
	}
	return nil
}

// startStaticDials starts n static dial tasks.
// 从staticPool中随机出来n个dialTask,对他们调用startDial
// 这些dialTask会从staticPool中移除
func (d *dialScheduler) startStaticDials(n int) (started int) {
	for started = 0; started < n && len(d.staticPool) > 0; started++ {
		idx := d.rand.Intn(len(d.staticPool))
		task := d.staticPool[idx]
		d.startDial(task)
		d.removeFromStaticPool(idx)
	}
	return started
}

// updateStaticPool attempts to move the given static dial back into staticPool.
// 这个节点当前能被拨号的话就添加到staticPool中
// 没有被checkDial的一些要求限制,而且当前不在staticPool中
func (d *dialScheduler) updateStaticPool(id enode.ID) {
	task, ok := d.static[id]
	if ok && task.staticPoolIndex < 0 && d.checkDial(task.dest) == nil {
		d.addToStaticPool(task)
	}
}

// 将指定的dialTask加入到staticPool中
func (d *dialScheduler) addToStaticPool(task *dialTask) {
	// 一个dialTask只能往staticPool中添加一次
	if task.staticPoolIndex >= 0 {
		panic("attempt to add task to staticPool twice")
	}
	d.staticPool = append(d.staticPool, task)
	// 保存这个任务的下标
	task.staticPoolIndex = len(d.staticPool) - 1
}

// removeFromStaticPool removes the task at idx from staticPool. It does that by moving the
// current last element of the pool to idx and then shortening the pool by one.
// 从staticPool中删除指定下标的任务
// 被删除的任务的staticPoolIndex恢复为-1
// 删除过程就是将末尾元素移动到删除位置,然后修改原来末尾元素的下标即可
func (d *dialScheduler) removeFromStaticPool(idx int) {
	task := d.staticPool[idx]
	end := len(d.staticPool) - 1
	d.staticPool[idx] = d.staticPool[end]
	d.staticPool[idx].staticPoolIndex = idx
	d.staticPool[end] = nil
	d.staticPool = d.staticPool[:end]
	task.staticPoolIndex = -1
}

// startDial runs the given dial task in a separate goroutine.
// 启动一个拨号过程
// 更新history,将这个任务加入dialing
// 然后在单独的协程内启动tart.run, 当run结束后将task发送到doneCh
func (d *dialScheduler) startDial(task *dialTask) {
	d.log.Trace("Starting p2p dial", "id", task.dest.ID(), "ip", task.dest.IP(), "flag", task.flags)
	hkey := string(task.dest.ID().Bytes())
	// 将节点加入history中,并设置超时时间
	d.history.add(hkey, d.clock.Now().Add(dialHistoryExpiration))
	d.dialing[task.dest.ID()] = task
	go func() {
		task.run(d)
		// 执行完的dialTask对象发送到doneCh中
		d.doneCh <- task
	}()
}

// A dialTask generated for each node that is dialed.
// 每次要对其他节点拨号前都生成一个dialTask对象
// 记录要拨号的目标,连接的标识以及在staticPool中的下标
type dialTask struct {
	// 初始化的时候使用-1,还不知道在staticPool中的位置
	staticPoolIndex int
	flags           connFlag
	// These fields are private to the task and should not be
	// accessed by dialScheduler while the task is running.
	dest *enode.Node
	// 记录上次解析这个节点的时间
	lastResolved mclock.AbsTime
	// 两次解析之间的最小间隔
	resolveDelay time.Duration
}

// 创建dialTask对象
func newDialTask(dest *enode.Node, flags connFlag) *dialTask {
	return &dialTask{dest: dest, flags: flags, staticPoolIndex: -1}
}

type dialError struct {
	error
}

// 建立与对应节点的连接
func (t *dialTask) run(d *dialScheduler) {
	// 需要解析对应节点的ip,但是解析失败,这个直接返回
	if t.needResolve() && !t.resolve(d) {
		return
	}

	err := t.dial(d, t.dest)
	if err != nil {
		// For static nodes, resolve one more time if dialing fails.
		if _, ok := err.(*dialError); ok && t.flags&staticDialedConn != 0 {
			if t.resolve(d) {
				t.dial(d, t.dest)
			}
		}
	}
}

// 针对静态节点的连接,还不知道节点的ip,这时候需要通过节点发现查询一下它的ip
// 这种情况出现在用户指定了静态节点,但是没有指定它的ip
func (t *dialTask) needResolve() bool {
	return t.flags&staticDialedConn != 0 && t.dest.IP() == nil
}

// resolve attempts to find the current endpoint for the destination
// using discovery.
//
// Resolve operations are throttled with backoff to avoid flooding the
// discovery network with useless queries for nodes that don't exist.
// The backoff delay resets when the node is found.
// 通过节点发现查询节点的记录,解析出来节点的ip
func (t *dialTask) resolve(d *dialScheduler) bool {
	if d.resolver == nil {
		return false
	}
	// 第一次调用resolve,设置初始时间间隔
	if t.resolveDelay == 0 {
		t.resolveDelay = initialResolveDelay
	}
	if t.lastResolved > 0 && time.Duration(d.clock.Now()-t.lastResolved) < t.resolveDelay {
		return false
	}
	resolved := d.resolver.Resolve(t.dest)
	t.lastResolved = d.clock.Now()
	// 解析失败,解析时间间隔翻倍,上限是maxResolveDelay
	if resolved == nil {
		t.resolveDelay *= 2
		if t.resolveDelay > maxResolveDelay {
			t.resolveDelay = maxResolveDelay
		}
		d.log.Debug("Resolving node failed", "id", t.dest.ID(), "newdelay", t.resolveDelay)
		return false
	}
	// The node was found.
	// 解析成功了,更新时间间隔为10s
	t.resolveDelay = initialResolveDelay
	// 更新dest
	t.dest = resolved
	d.log.Debug("Resolved node", "id", t.dest.ID(), "addr", &net.TCPAddr{IP: t.dest.IP(), Port: t.dest.TCP()})
	return true
}

// dial performs the actual connection attempt.
// 真正的执行拨号的过程,创建与远程节点的连接
func (t *dialTask) dial(d *dialScheduler, dest *enode.Node) error {
	fd, err := d.dialer.Dial(d.ctx, t.dest)
	// 拨号生成的错误被封装成dialError
	if err != nil {
		d.log.Trace("Dial error", "id", t.dest.ID(), "addr", nodeAddr(t.dest), "conn", t.flags, "err", cleanupDialErr(err))
		return &dialError{err}
	}
	// 将拨号成功获得的连接对象封装metrics记录
	mfd := newMeteredConn(fd, false, &net.TCPAddr{IP: dest.IP(), Port: dest.TCP()})
	// 拨号完成后执行setupFunc
	return d.setupFunc(mfd, t.flags, dest)
}

func (t *dialTask) String() string {
	id := t.dest.ID()
	return fmt.Sprintf("%v %x %v:%d", t.flags, id[:8], t.dest.IP(), t.dest.TCP())
}

func cleanupDialErr(err error) error {
	if netErr, ok := err.(*net.OpError); ok && netErr.Op == "dial" {
		return netErr.Err
	}
	return err
}
