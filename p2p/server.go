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

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/discover"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/p2p/nat"
	"github.com/Evolution404/simcore/p2p/netutil"
)

const (
	// 默认拨号的超时时间是15秒
	defaultDialTimeout = 15 * time.Second

	// This is the fairness knob for the discovery mixer. When looking for peers, we'll
	// wait this long for a single source of candidates before moving on and trying other
	// sources.
	// 节点发现过程中的超时时间
	discmixTimeout = 5 * time.Second

	// Connectivity defaults.
	// inbound和outbound类型的连接，分别进行限制，各自最多同时有50个连接
	// 这是默认的限制值，可以通过Config.MaxPendingPeers进行修改
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3

	// This time limits inbound connection attempts per source IP.
	// 30秒内接收到同一个ip建立的连接,本地将拒绝连接
	// 局域网ip不受此限制
	inboundThrottleTime = 30 * time.Second

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	// 本地从网络中读取一条消息最长不能超过30秒
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	// 本地向远程节点发送一条消息最大不能超过20秒
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
// 必须指定的字段
// PrivateKey
// MaxPeers 必须指定大于零的整数
// 不指定ListenAddr将不会监听tcp连接
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	// 必选值，本地节点的私钥
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	// 必选值，最多可以同时连接的节点个数
	// MaxPeers必须指定,而且必须指定一个大于零的数
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	// 可选值，默认为50
	// 指正在进行握手阶段的连接个数，inbound和outbound分别进行计数
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	// 可选值，默认值3
	// 代表本地主动拨号的节点上限个数所占MaxPeers的比例
	// 默认是最多1/3的节点由本地主动拨号，剩下2/3由远程节点连接本地
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	// 可选值，默认为false
	// 默认启用节点发现
	NoDiscovery bool

	// DiscoveryV5 specifies whether the new topic-discovery based V5 discovery
	// protocol should be started or not.
	// 可选值，默认为false
	// 默认不启用v5版本的节点发现
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	// 可选值，本地节点的名称
	// 通常使用common.MakeName方法来创建本地的名称
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	// 可选值，代表节点发现过程的初始节点
	BootstrapNodes []*enode.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	BootstrapNodesV5 []*enode.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	// 本地会始终尝试与静态节点建立连接，除非达到连接上限
	StaticNodes []*enode.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	// 在TrustedNodes中的节点不受到连接节点个数的限制
	TrustedNodes []*enode.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	// 如果此字段不为nil，则本地指定的网段的ip的建立连接
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	// 保存了之前节点发现结果的数据库的路径
	// 可选值，代表节点数据库的路径
	// 默认值为空，代表使用内存数据库
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	// 可选项，代表本地可以运行的子协议
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	// 可选值，默认是空字符串，代表不启动监听
	// 如果设置端口为0，代表随机监听一个端口，服务器启动后会更新为真正监听的端口
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	// 不是nil,也不是nat.ExtIP的情况下
	// 例如设置为nat.Any(),Server.Start会阻塞一会,探测节点的ip
	// nat.ExtIP是固定了本地的ip为指定的值,不需要再运行upnp或者pmp协议了
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	// 创建Server的时候可以指定自定义的拨号器
	// 可选值，默认值nil，代表建立实际的tcp连接来拨号
	// 如果是nil,将使用net.Dialer.DialContext进行拨号,也就是自定义的tcpDialer对象
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	// 如果为true本地不会主动向外进行拨号
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	// 用来控制订阅的管道是否收到节点发送和接收消息的通知
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger `toml:",omitempty"`

	clock mclock.Clock
}

// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	// 以下三个字段都是为了在测试中替换成其他测试环境的函数定义的,正常情况都有专门的值
	// newTransport正常情况就是newRLPX
	newTransport func(net.Conn, *ecdsa.PublicKey) transport
	// 正常情况是nil,测试时候可以指定函数在启动Peer前调用
	newPeerHook func(*Peer)
	// listenFunc正常情况就是net.Listen
	listenFunc func(network, addr string) (net.Listener, error)

	// 保护运行状态时的一些数据
	lock sync.Mutex // protects running
	// 用来代表该对象是否是运行状态
	// Start方法中修改为true, Stop方法中修改为false
	running bool

	// 通过listenFunc生成的监听对象
	listener net.Listener
	// 本地协议握手阶段向远程节点发送的数据
	// 使用server.Start方法启动后，内部调用了setupLocalNode函数缓存本地的协议握手数据
	ourHandshake *protoHandshake
	loopWG       sync.WaitGroup // loop, listenLoop
	peerFeed     event.Feed
	log          log.Logger

	nodedb    *enode.DB
	localnode *enode.LocalNode
	ntab      *discover.UDPv4
	DiscV5    *discover.UDPv5
	// 聚合所有的节点来源,用来迭代节点
	// 比如各个子协议中自己定义的Protocol.DialCandidates
	// 以及本地执行节点发现获得的节点
	discmix *enode.FairMix
	// 保存本地向外的拨号调度器
	// 可以用来addStatic,removeStatic,peerAdded,peerRemoved
	dialsched *dialScheduler

	// Channels into the run loop.
	// 在run函数中需要使用的管道
	quit          chan struct{}
	addtrusted    chan *enode.Node
	removetrusted chan *enode.Node
	// 这个管道用来发送对本地连接的其他节点操作的函数
	// Peers,PeerCount以及RemovePeer三个函数使用了这个管道
	peerOp chan peerOpFunc
	// peerOp执行完了,通过这个管道通知
	peerOpDone chan struct{}
	delpeer    chan peerDrop
	// 执行完成加密握手后的连接被发送到这个管道
	checkpointPostHandshake chan *conn
	// 执行完成加密握手和协议握手的连接被发送到这个管道
	checkpointAddPeer chan *conn

	// State of run loop and listenLoop.
	// 所有接收到的连接的对端ip都会保存在这里30秒
	// 用来限制非局域网的ip的连接次数,30s内接收到同一个ip的连接不进行处理
	inboundHistory expHeap
}

// 可以拿到所有对等节点id和Peer对象map的函数
// 通过doPeerOp发送到run函数中调用
type peerOpFunc func(map[enode.ID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int32

const (
	// 以下是各种连接的类型

	// 代表与动态节点建立的连接,动态节点指通过节点发现获得的节点
	dynDialedConn connFlag = 1 << iota
	// 代表与静态节点建立的连接,静态节点指在Server.Config中明确指定的节点
	staticDialedConn
	// 这个连接是别的节点连接本地节点
	inboundConn
	// 这个连接的对端是在TrustedNodes中
	// 受信任的节点可以通过AddTrustedPeer动态增加
	// 当与一个节点完成加密握手且对端在trusted中为这个连接增加trustedConn标识
	trustedConn
)

// conn wraps a network connection with information gathered
// during the two handshakes.
// 完成了加密握手和协议握手后的连接对象,增加了在握手过程中收集的信息
// conn对象在SetupConn函数中创建
type conn struct {
	fd net.Conn
	transport
	// 保存这个连接的远程节点
	node *enode.Node
	// int32的末尾四位作为标记位,用来标记是否设置了指定的flag
	flags connFlag
	// 在run函数中会将错误发送到这里,用于通知SetupConn函数
	cont chan error // The run loop uses cont to signal errors to SetupConn.
	// 保存了对方节点所支持的协议名称和版本
	// 由协议握手过程中对方发送的protoHandshake包中得知
	caps []Cap  // valid after the protocol handshake
	name string // valid after the protocol handshake
}

// 实际使用中只有一个transport那就是rlpxTransport
// 两个节点建立网络连接之后,需要执行握手. 握手包括两个步骤:加密握手和协议握手
// 加密握手的目的是交换接下来通信的对称加密的密钥
// 协议握手是为了交换一些协议相关的信息,例如协议的版本号,高于某个版本号才执行压缩
// 发起方和接收方都分别连续调用doEncHandshake和doProtoHandshake两个函数
// 两个握手过程,双方各自都发送了两个数据包
// 发起方首先发送authMsg,接收等待接收验证authMsg后发送authACK,此时接收方加密握手完成
// 发起方收到接收方发送的authACK后验证通过,加密握手过程也完成
// 双方加密握手完成后都立刻发送protoHandshake包,然后等待对方的protoHandshake包
// 双方都收到协议信息后所有握手过程完成
type transport interface {
	// The two handshakes.
	// 建立连接后首先进行加密握手,然后进行协议握手
	// 分别就是doEncHandshake,doProtoHandshake
	doEncHandshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error)
	// 将输入的protoHandshake对象发送给远程节点,然后返回接收到的远程节点的protoHandshake对象
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because MsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.node.ID() != enode.ID{}) {
		s += " " + c.node.ID().String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

// 将连接标识转换成字符串
// trusted-dyndial-staticdial-inbound 这种格式,包含哪些位显示哪几个
func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

// 判断是否设置了指定的标记
// 直接将保存的flag与输入的flag按位与,结果不为零说明设置了输入的flag
func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}

// 输入f代表要操作的flag,val为true代表将flag置为1,val为false代表将flag置为0
func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}

// LocalNode returns the local node record.
func (srv *Server) LocalNode() *enode.LocalNode {
	return srv.localnode
}

// Peers returns all connected peers.
// 获取所有的对等节点
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	})
	return ps
}

// PeerCount returns the number of connected peers.
// 获取当前连接的节点个数
func (srv *Server) PeerCount() int {
	var count int
	srv.doPeerOp(func(ps map[enode.ID]*Peer) {
		count = len(ps)
	})
	return count
}

// AddPeer adds the given node to the static node set. When there is room in the peer set,
// the server will connect to the node. If the connection fails for any reason, the server
// will attempt to reconnect the peer.
// 添加静态节点
func (srv *Server) AddPeer(node *enode.Node) {
	srv.dialsched.addStatic(node)
}

// RemovePeer removes a node from the static node set. It also disconnects from the given
// node if it is currently connected as a peer.
//
// This method blocks until all protocols have exited and the peer is removed. Do not use
// RemovePeer in protocol implementations, call Disconnect on the Peer instead.
// 从静态节点中删除指定的节点,然后断开与该节点的连接
func (srv *Server) RemovePeer(node *enode.Node) {
	var (
		ch  chan *PeerEvent
		sub event.Subscription
	)
	// Disconnect the peer on the main loop.
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		// 从静态节点列表中删除
		srv.dialsched.removeStatic(node)
		// 然后断开与该节点的连接
		if peer := peers[node.ID()]; peer != nil {
			ch = make(chan *PeerEvent, 1)
			sub = srv.peerFeed.Subscribe(ch)
			peer.Disconnect(DiscRequested)
		}
	})
	// Wait for the peer connection to end.
	// 等待接收到断开连接的事件
	if ch != nil {
		defer sub.Unsubscribe()
		// 因为订阅了所有的事件,这里搜索到删除这个节点的那个事件
		for ev := range ch {
			if ev.Peer == node.ID() && ev.Type == PeerEventTypeDrop {
				return
			}
		}
	}
}

// AddTrustedPeer adds the given node to a reserved trusted list which allows the
// node to always connect, even if the slot are full.
func (srv *Server) AddTrustedPeer(node *enode.Node) {
	select {
	case srv.addtrusted <- node:
	case <-srv.quit:
	}
}

// RemoveTrustedPeer removes the given node from the trusted peer set.
func (srv *Server) RemoveTrustedPeer(node *enode.Node) {
	select {
	case srv.removetrusted <- node:
	case <-srv.quit:
	}
}

// SubscribeEvents subscribes the given channel to peer events
// 订阅节点事件,每当有新节点添加或者删除的时候输入的管道会接收到通知
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
// 获取Server对应的enode.Node对象
// 在Server调用Start前获取到v4版本
// 在Server调用Start后获取到enr记录
func (srv *Server) Self() *enode.Node {
	srv.lock.Lock()
	ln := srv.localnode
	srv.lock.Unlock()

	if ln == nil {
		return enode.NewV4(&srv.PrivateKey.PublicKey, net.ParseIP("0.0.0.0"), 0, 0)
	}
	return ln.Node()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.lock.Unlock()
	srv.loopWG.Wait()
}

// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDP implements discover.UDPConn
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, errors.New("connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discover.UDPConn
func (s *sharedUDPConn) Close() error {
	return nil
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	// 日志默认使用log.Root
	if srv.log == nil {
		srv.log = log.Root()
	}
	// 默认使用系统时钟
	if srv.clock == nil {
		srv.clock = mclock.System{}
	}
	// 既不监听本地端口,也不向外拨号
	// 这个节点根本没有用
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	// static fields
	// 调用者必须指定p2p节点的私钥
	if srv.PrivateKey == nil {
		return errors.New("Server.PrivateKey must be set to a non-nil key")
	}
	// 这里newTransport不是nil的情况,是在测试时出现
	// 正常使用p2p模块,newTransport字段在调用Start时一定是nil
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	// listenFunc不为nil的情况也是出现在测试时
	if srv.listenFunc == nil {
		srv.listenFunc = net.Listen
	}
	// 初始化在run函数中使用的这八个管道
	srv.quit = make(chan struct{})
	srv.delpeer = make(chan peerDrop)
	srv.checkpointPostHandshake = make(chan *conn)
	srv.checkpointAddPeer = make(chan *conn)
	srv.addtrusted = make(chan *enode.Node)
	srv.removetrusted = make(chan *enode.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})

	// 设置srv.ourHandshake,srv.localnode和srv.nodedb
	if err := srv.setupLocalNode(); err != nil {
		return err
	}
	// 网络中的节点同时负责向别的节点发起连接,也负责接收别的节点的连接
	// 下面的setupListening用来调度别的节点向本地发起的连接
	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			return err
		}
	}
	if err := srv.setupDiscovery(); err != nil {
		return err
	}
	// 这里的setupDialScheduler用来调度向其他节点发起连接
	srv.setupDialScheduler()

	// run函数执行完成,会执行loopWG.Done()
	srv.loopWG.Add(1)
	go srv.run()
	return nil
}

// 配置服务器的一些本地数据，包括三个操作
// 1. 缓存协议握手过程发送的数据包
// 2. 创建enode.LocalNode对象
// 3. 根据NAT类型设置LocalNode的IP信息
// 最终设置了srv.ourHandshake,srv.localnode和srv.nodedb三个字段
func (srv *Server) setupLocalNode() error {
	// Create the devp2p handshake.
	// 缓存协议握手过程使用的协议握手数据包(protoHandshake对象)
	// 首先创建对象，并保存基本信息
	pubkey := crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: pubkey[1:]}
	// 然后按照顺序向协议握手包中保存本地的支持的协议名称和版本
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	sort.Sort(capsByNameAndVersion(srv.ourHandshake.Caps))

	// Create the local node.
	// 创建enode.LocalNode对象
	// 首先指定路径创建节点数据库
	db, err := enode.OpenDB(srv.Config.NodeDatabase)
	if err != nil {
		return err
	}
	srv.nodedb = db
	// 然后利用节点数据库和本地私钥创建enode.LocalNode对象
	srv.localnode = enode.NewLocalNode(db, srv.PrivateKey)
	// 设置备用ip为127.0.0.1
	srv.localnode.SetFallbackIP(net.IP{127, 0, 0, 1})
	// TODO: check conflicts
	// 向LocalNode对象中协议子协议定义的额外字段
	for _, p := range srv.Protocols {
		for _, e := range p.Attributes {
			srv.localnode.Set(e)
		}
	}

	// 判断NAT类型
	// ExtIP直接指定节点的ip为该ip
	// 不是nil的其他情况,调用srv.NAT.ExternalIP,探测节点的外部ip
	switch srv.NAT.(type) {
	case nil:
		// No NAT interface, do nothing.
	case nat.ExtIP:
		// ExtIP doesn't block, set the IP right away.
		ip, _ := srv.NAT.ExternalIP()
		srv.localnode.SetStaticIP(ip)
	default:
		// Ask the router about the IP. This takes a while and blocks startup,
		// do it in the background.
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			if ip, err := srv.NAT.ExternalIP(); err == nil {
				srv.localnode.SetStaticIP(ip)
			}
		}()
	}
	return nil
}

// 启动节点发现
func (srv *Server) setupDiscovery() error {
	srv.discmix = enode.NewFairMix(discmixTimeout)

	// Add protocol-specific discovery sources.
	// 扫描各个协议自已定义的节点来源,添加到全局的节点来源中
	added := make(map[string]bool)
	for _, proto := range srv.Protocols {
		// 用户自定义的协议可能有重复的,每个协议只添加一次
		if proto.DialCandidates != nil && !added[proto.Name] {
			srv.discmix.AddSource(proto.DialCandidates)
			added[proto.Name] = true
		}
	}

	// Don't listen on UDP endpoint if DHT is disabled.
	// 如果没有启用节点发现,到这里就结束,只使用上面各个协议定义的节点来源
	if srv.NoDiscovery && !srv.DiscoveryV5 {
		return nil
	}

	// 接下来创建udp的连接对象,用于运行节点发现协议
	addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
	if err != nil {
		return err
	}
	// 监听UDP端口
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	srv.log.Debug("UDP listener up", "addr", realaddr)
	if srv.NAT != nil {
		if !realaddr.IP.IsLoopback() {
			srv.loopWG.Add(1)
			go func() {
				// 在nat中添加一个udp的节点映射
				nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
				srv.loopWG.Done()
			}()
		}
	}
	// 设置备用udp端口为监听的端口
	srv.localnode.SetFallbackUDP(realaddr.Port)

	// Discovery V4
	var unhandled chan discover.ReadPacket
	var sconn *sharedUDPConn
	if !srv.NoDiscovery {
		if srv.DiscoveryV5 {
			unhandled = make(chan discover.ReadPacket, 100)
			sconn = &sharedUDPConn{conn, unhandled}
		}
		cfg := discover.Config{
			PrivateKey:  srv.PrivateKey,
			NetRestrict: srv.NetRestrict,
			Bootnodes:   srv.BootstrapNodes,
			Unhandled:   unhandled,
			Log:         srv.log,
		}
		// 启动本地的节点发现协议
		ntab, err := discover.ListenV4(conn, srv.localnode, cfg)
		if err != nil {
			return err
		}
		srv.ntab = ntab
		// 本地节点发现也生成一个随机迭代器,加入到节点来源中
		srv.discmix.AddSource(ntab.RandomNodes())
	}

	// Discovery V5
	if srv.DiscoveryV5 {
		cfg := discover.Config{
			PrivateKey:  srv.PrivateKey,
			NetRestrict: srv.NetRestrict,
			Bootnodes:   srv.BootstrapNodesV5,
			Log:         srv.log,
		}
		var err error
		if sconn != nil {
			srv.DiscV5, err = discover.ListenV5(sconn, srv.localnode, cfg)
		} else {
			srv.DiscV5, err = discover.ListenV5(conn, srv.localnode, cfg)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// 设置并启动拨号调度器
func (srv *Server) setupDialScheduler() {
	config := dialConfig{
		self:           srv.localnode.ID(),
		maxDialPeers:   srv.maxDialedConns(),
		maxActiveDials: srv.MaxPendingPeers,
		log:            srv.Logger,
		netRestrict:    srv.NetRestrict,
		dialer:         srv.Dialer,
		clock:          srv.clock,
	}
	if srv.ntab != nil {
		config.resolver = srv.ntab
	}
	if config.dialer == nil {
		config.dialer = tcpDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	// 创建并启动了dialScheduler,在后台协程中不断循环拨号
	srv.dialsched = newDialScheduler(config, srv.discmix, srv.SetupConn)
	// 将服务器配置的静态节点添加到拨号调度器中
	for _, n := range srv.StaticNodes {
		srv.dialsched.addStatic(n)
	}
}

// 计算外部发起的连接上限
func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

// 计算本地拨号的节点个数上限
// 通过MaxPeers / DialRatio
func (srv *Server) maxDialedConns() (limit int) {
	// 禁用拨号或者MaxPeers为0，返回0
	if srv.NoDial || srv.MaxPeers == 0 {
		return 0
	}
	if srv.DialRatio == 0 {
		limit = srv.MaxPeers / defaultDialRatio
	} else {
		limit = srv.MaxPeers / srv.DialRatio
	}
	if limit == 0 {
		limit = 1
	}
	return limit
}

// 设置srv.listener,srv.ListenAddr,并更新localnode的TCP字段
func (srv *Server) setupListening() error {
	// Launch the listener.
	// ListenAddr不会为空字符串,Start函数在调用之前进行了判断
	listener, err := srv.listenFunc("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	srv.listener = listener
	// 重新获得真正监听的地址
	srv.ListenAddr = listener.Addr().String()

	// Update the local node record and map the TCP listening port if NAT is configured.
	// 更新localnode中端口的记录
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		srv.localnode.Set(enr.TCP(tcp.Port))
		if !tcp.IP.IsLoopback() && srv.NAT != nil {
			srv.loopWG.Add(1)
			go func() {
				nat.Map(srv.NAT, srv.quit, "tcp", tcp.Port, tcp.Port, "ethereum p2p")
				srv.loopWG.Done()
			}()
		}
	}

	// listenLoop中会调用loopWG.Done()
	srv.loopWG.Add(1)
	// listenFunc创建了listener
	// 在listenLoop里使用listener监听外部的请求
	go srv.listenLoop()
	return nil
}

// doPeerOp runs fn on the main loop.
// 将函数发送到run函数中执行,一直阻塞到函数执行完成
func (srv *Server) doPeerOp(fn peerOpFunc) {
	select {
	case srv.peerOp <- fn:
		// 等待fn在run中执行完成
		<-srv.peerOpDone
	case <-srv.quit:
	}
}

// run is the main loop of the server.
func (srv *Server) run() {
	srv.log.Info("Started P2P networking", "self", srv.localnode.Node().URLv4())
	defer srv.loopWG.Done()
	defer srv.nodedb.Close()
	defer srv.discmix.Close()
	defer srv.dialsched.stop()

	var (
		// 用来保存所有的节点
		peers = make(map[enode.ID]*Peer)
		// 统计本地接收的来自远程节点的连接个数
		inboundCount = 0
		// 记录所有信任的节点
		trusted = make(map[enode.ID]bool, len(srv.TrustedNodes))
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	// 根据Server的配置初始化最开始的受信任节点
	for _, n := range srv.TrustedNodes {
		trusted[n.ID()] = true
	}

	// 以下的管道主要分为如下几个部分:
	// 1. 退出 经典必备
	// 2. 添加删除trustedConn
	// 3. peerOp 执行一些需要获知所有正在连接节点信息的函数
	//      因为peers变量在run函数内部,外部通过管道回调函数方式的拿到
	// 4. 接收完成加密握手后的conn对象
	// 5. 接收完成协议握手后的conn对象
	// 6. 删除Peer
running:
	for {
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running

		// 在trusted变量中记录被信任的节点
		// 如果这个节点已经连接上了,更新Peer.rw的flag
		case n := <-srv.addtrusted:
			// This channel is used by AddTrustedPeer to add a node
			// to the trusted node set.
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID()] = true
			// 如果当前与这个节点已经建立了连接,更新连接的标识位 设置为trustedConn
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, true)
			}

		// 在trusted变量中设置这个节点为false
		// 如果这个节点已经连接上了,清除连接的flag中trustedConn标记
		case n := <-srv.removetrusted:
			// This channel is used by RemoveTrustedPeer to remove a node
			// from the trusted node set.
			srv.log.Trace("Removing trusted node", "node", n)
			delete(trusted, n.ID())
			// 如果当前与这个节点已经建立了连接,更新连接的标识位 取消trustedConn
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, false)
			}

		// Peers,PeerCount,RemovePeer会通过这个管道发送函数
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}

		// 完成了加密握手过程的连接
		case c := <-srv.checkpointPostHandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			// 如果是TrustedNodes，设置标记位
			if trusted[c.node.ID()] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			// 完成加密握手后进行一些基本的检测
			c.cont <- srv.postHandshakeChecks(peers, inboundCount, c)

		// setupConn中完成了加密握手和协议握手,可以添加新的节点了
		case c := <-srv.checkpointAddPeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			// 执行完成协议握手后的检查
			err := srv.addPeerChecks(peers, inboundCount, c)
			// 所有的检测都完成了
			// 开始真正添加一个节点
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := srv.launchPeer(c)
				peers[c.node.ID()] = p
				srv.log.Debug("Adding p2p peer", "peercount", len(peers), "id", p.ID(), "conn", c.flags, "addr", p.RemoteAddr(), "name", p.Name())
				srv.dialsched.peerAdded(c)
				if p.Inbound() {
					inboundCount++
				}
			}
			c.cont <- err

		// 删除一个Peer需要:从peers变量中删除,通知拨号调度器,更新inboundCount
		case pd := <-srv.delpeer:
			// A peer disconnected.
			d := common.PrettyDuration(mclock.Now() - pd.created)
			delete(peers, pd.ID())
			srv.log.Debug("Removing p2p peer", "peercount", len(peers), "id", pd.ID(), "duration", d, "req", pd.requested, "err", pd.err)
			srv.dialsched.peerRemoved(pd.rw)
			// 更新inboundCount
			if pd.Inbound() {
				inboundCount--
			}
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	// 关闭所有还在连接中的节点
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	// 等待上面所有的Disconnect成功执行
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)")
		delete(peers, p.ID())
	}
}

// 两个节点建立了网络连接,还完成了加密握手或者协议握手过程,检查一下这个连接是否可行
// 比如是否连接个数超过限制,之前是不是建立过连接,是不是与自己建立连接
// 这个检查在加密握手完成会执行,协议握手完成后也会执行,确保真正成为Peer的连接都满足这些限制
func (srv *Server) postHandshakeChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	switch {
	// 不是trustedConn,而且连接个数达到了限制,返回错误
	case !c.is(trustedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	// 外部主动发起的连接个数超过了限制
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	// 与这个节点的连接已经建立了
	case peers[c.node.ID()] != nil:
		return DiscAlreadyConnected
	// 建立的连接是自己
	case c.node.ID() == srv.localnode.ID():
		return DiscSelf
	default:
		return nil
	}
}

// 检查远程节点是否有与本地兼容的子协议,还有连接个数的一些限制
func (srv *Server) addPeerChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the post-handshake checks because the
	// peer set might have changed since those checks were performed.
	return srv.postHandshakeChecks(peers, inboundCount, c)
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
// 在单独的协程里运行listenLoop
// 监听外部发起的连接，过滤掉30秒内重复连接的IP，或者不在限制网段内的IP
// 然后对获取到的底层网络连接调用Server.SetupConn方法
func (srv *Server) listenLoop() {
	srv.log.Debug("TCP listener up", "addr", srv.listener.Addr())

	// The slots channel limits accepts of new connections.
	// 等待建立连接的节点的最大个数
	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	// slots用来限制接收到的连接个数
	// 接收到的连接会调用SetupConn进入协程处理,SetupConn一直到两个节点完成握手过程才会结束
	// 所以slots的缓存个数,就代表了正在执行握手的过程的连接个数,代表了等待连接的节点的个数
	// 每次进入协程将消耗slots中的一个缓存,协程结束的时候会返回一个
	// 这样在下面的for循环开始,一旦SetupConn协程个数超过限制就会阻塞住
	slots := make(chan struct{}, tokens)
	// 初始就将管道填满
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	// Wait for slots to be returned on exit. This ensures all connection goroutines
	// are down before listenLoop returns.
	// 对应于setupListening中调用的loopWG.Add(1)
	defer srv.loopWG.Done()
	defer func() {
		// 在listenLoop结束前清空slots
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	}()

	for {
		// Wait for a free slot before accepting.
		// 如果缓存被消耗完,这里会阻塞住,直到SetupConn执行完返还
		<-slots

		var (
			fd      net.Conn
			err     error
			lastLog time.Time
		)
		for {
			// 监听到一个连接fd
			fd, err = srv.listener.Accept()
			// 处理错误
			if netutil.IsTemporaryError(err) {
				// 临时错误的日志最多一秒一次
				if time.Since(lastLog) > 1*time.Second {
					srv.log.Debug("Temporary read error", "err", err)
					lastLog = time.Now()
				}
				// 发生了临时错误,等待一小会,再尝试看看还有没有临时错误
				time.Sleep(time.Millisecond * 200)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				slots <- struct{}{}
				return
			}
			// 没有发生错误,结束监听循环
			// 开始处理接收到的连接fd
			break
		}

		remoteIP := netutil.AddrIP(fd.RemoteAddr())
		// 检查对端ip是否有问题
		if err := srv.checkInboundConn(remoteIP); err != nil {
			srv.log.Debug("Rejected inbound connection", "addr", fd.RemoteAddr(), "err", err)
			// 对端ip有问题,关闭这个连接
			fd.Close()
			slots <- struct{}{}
			continue
		}
		// 远程节点不是nil的话,加入到度量中,并打印日志
		if remoteIP != nil {
			var addr *net.TCPAddr
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok {
				addr = tcp
			}
			fd = newMeteredConn(fd, true, addr)
			srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		}
		go func() {
			// 本地是连接的接收方,所以SetupConn的dialDest传入nil
			srv.SetupConn(fd, inboundConn, nil)
			// 连接建立完成后归还令牌到slots中
			slots <- struct{}{}
		}()
	}
}

// 判断建立连接的远程ip是不是有问题,有问题返回的错误不为nil
// 可能出现的问题:
//   如果设置了限制网段，但是对方不在限制范围内
//   对端ip在30s内重复发起连接
func (srv *Server) checkInboundConn(remoteIP net.IP) error {
	if remoteIP == nil {
		return nil
	}
	// Reject connections that do not match NetRestrict.
	// 连接本地的节点必须在限制的网段内
	if srv.NetRestrict != nil && !srv.NetRestrict.Contains(remoteIP) {
		return fmt.Errorf("not in netrestrict list")
	}
	// Reject Internet peers that try too often.
	now := srv.clock.Now()
	// 先将保存超过30秒的节点清除
	srv.inboundHistory.expire(now, nil)
	// 判断此节点30秒内是否发起过连接，局域网内连接不限制
	if !netutil.IsLAN(remoteIP) && srv.inboundHistory.contains(remoteIP.String()) {
		return fmt.Errorf("too many attempts")
	}
	// 将当前发起连接的节点加入到历史记录中，30秒后超时
	srv.inboundHistory.add(remoteIP.String(), now.Add(inboundThrottleTime))
	return nil
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
// Server必须已经调用了Start方法,在运行过程中
// SetupConn在传入的net.Conn连接上执行握手过程,生成的所有net.Conn对象都会进入这里处理
// 如果握手成功将新增一个对等节点,否则返回错误
// 调用的时机有两个分别是
//   在listenLoop中本地监听到了来自远程发起的连接
//   本地对外部节点拨号成功获得了net.Conn对象,在dialTask.dial中调用
// 这是一个公开方法,外部如果建立了网络连接,也可以通过这个方法在该连接上执行握手过程,如果成功将添加一个Peer
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *enode.Node) error {
	// 创建conn对象
	c := &conn{fd: fd, flags: flags, cont: make(chan error)}
	// dialDest为nil说明是远程节点连接本地
	if dialDest == nil {
		c.transport = srv.newTransport(fd, nil)
		// dialDest不是nil说明本地主动连接远程节点
	} else {
		c.transport = srv.newTransport(fd, dialDest.Pubkey())
	}

	// 在网络连接上执行握手过程，包括加密握手和协议握手
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
	}
	return err
}

// 执行加密握手和协议握手
func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *enode.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	// 确保Server对象已经调用Start方法,在运行中了
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}

	// If dialing, figure out the remote public key.
	// 如果本地在向外拨号,确保能获取到远程节点的公钥,如果获取不到打印并返回错误
	var dialPubkey *ecdsa.PublicKey
	if dialDest != nil {
		dialPubkey = new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			err = errors.New("dial destination doesn't have a secp256k1 public key")
			srv.log.Trace("Setting up connection failed", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
			return err
		}
	}

	// Run the RLPx handshake.
	// 执行加密握手过程,将远程节点的enode.Node保存到conn对象中
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	// 拨号方直接保存
	if dialDest != nil {
		c.node = dialDest
		// 接收方根据远程节点的公钥生成enode.Node对象
	} else {
		c.node = nodeFromConn(remotePubkey, c.fd)
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// 加密握手过程完成，检查对等节点的个数是否超过限制
	err = srv.checkpoint(c, srv.checkpointPostHandshake)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	// Run the capability negotiation handshake.
	// 开始执行协议握手过程
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed p2p handshake", "err", err)
		return err
	}
	// 验证远程节点公钥计算出来的节点ID是匹配的
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	// 两个握手过程都执行完成,通知run函数添加新的对等节点
	err = srv.checkpoint(c, srv.checkpointAddPeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	return nil
}

// 通过网络连接和对方的公钥生成enode.Node对象
func nodeFromConn(pubkey *ecdsa.PublicKey, conn net.Conn) *enode.Node {
	var ip net.IP
	var port int
	// 从网络连接中获取ip和端口
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcp.IP
		port = tcp.Port
	}
	// 生成v4版本的记录
	return enode.NewV4(pubkey, ip, port, port)
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
// 将conn对象发送到输入的管道中,run函数接收conn对象,然后返回run函数处理的错误结果
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	// 将conn对象发送出去后,会在run函数内接收
	// run函数处理完成,会将错误对象发送到c.cont管道中
	// 接收错误结果并返回
	return <-c.cont
}

// 创建并启动一个Peer
func (srv *Server) launchPeer(c *conn) *Peer {
	p := newPeer(srv.log, c, srv.Protocols)
	// 如果Server对象设置了EnableMsgEvents
	// 那么每个创建的Peer对象都会在Peer.events中保存Server.peerFeed
	if srv.EnableMsgEvents {
		// If message events are enabled, pass the peerFeed
		// to the peer.
		p.events = &srv.peerFeed
	}
	go srv.runPeer(p)
	return p
}

// runPeer runs in its own goroutine for each peer.
// 针对每个Peer,都在运行一个协程中运行runPeer函数
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeAdd,
		Peer:          p.ID(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})

	// Run the per-peer main loop.
	remoteRequested, err := p.run()

	// Announce disconnect on the main loop to update the peer set.
	// The main loop waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	// 节点的协议运行函数结束了,需要断开与这个节点的连接
	srv.delpeer <- peerDrop{p, err, remoteRequested}

	// Broadcast peer drop to external subscribers. This needs to be
	// after the send to delpeer so subscribers have a consistent view of
	// the peer set (i.e. Server.Peers() doesn't include the peer when the
	// event is received.
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeDrop,
		Peer:          p.ID(),
		Error:         err.Error(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})
}

// NodeInfo represents a short summary of the information known about the host.
// NodeInfo用来表示本地节点的各种信息
// 对应的是PeerInfo用来表示本地连接的其他节点的信息
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers
	ENR   string `json:"enr"`   // Ethereum Node Record
	IP    string `json:"ip"`    // IP address of the node
	// 本地占用的两个端口
	Ports struct {
		// UDP用于节点发现的端口
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		// TCP运行RLPx协议进行数据传输的端口
		Listener int `json:"listener"` // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
// 获取本地节点的相关信息
func (srv *Server) NodeInfo() *NodeInfo {
	// Gather and assemble the generic node infos
	node := srv.Self()
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.URLv4(),
		ID:         node.ID().String(),
		IP:         node.IP().String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = node.UDP()
	info.Ports.Listener = node.TCP()
	info.ENR = node.String()

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
// 获取本地连接的所有节点的信息
// 返回的所有信息根据节点的ID从小到大排序
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	// 首先收集所有的PeerInfo对象
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	// 根据各个对等节点的ID从小到大排序
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
