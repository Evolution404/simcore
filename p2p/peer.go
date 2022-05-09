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

package p2p

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/metrics"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
)

// 首先通过newPeer创建一个Peer对象
// peer := newPeer(log,conn,protocols)
// conn是已经完成所有握手的conn对象,protocols是本地支持的所有协议的Protocol对象
// newPeer中将每个Protocol对象封装成protoRW,实现了MsgReadWriter接口
// 重写收发消息的方法,根据各个协议的offset修正消息码,而且ReadMsg从各自的in管道中读取
// 然后执行run函数启动多个协程,readLoop,pingLoop以及每个协议一个协程
// peer.run()
// run中readLoop不断从网络中读取消息然后分配到各个协议的in管道中,相当于一个中间层

var (
	ErrShuttingDown = errors.New("shutting down")
)

const (
	baseProtocolVersion = 5
	// 在真实传输过程中,16之前的消息码被预先分配给预定义的类型
	// 例如handshakeMsg,discMsg,pingMsg,pongMsg
	baseProtocolLength = uint64(16)
	// 协议握手过程中发送的数据包大小上限
	baseProtocolMaxMsgSize = 2 * 1024

	snappyProtocolVersion = 5

	// 每15秒本地ping一下对面的节点
	pingInterval = 15 * time.Second
)

const (
	// devp2p message codes
	// 执行协议握手的时候发送的消息
	handshakeMsg = 0x00
	// 这个消息代表断开连接
	discMsg = 0x01
	pingMsg = 0x02
	pongMsg = 0x03
)

// protoHandshake is the RLP structure of the protocol handshake.
// 在协议握手过程中双方交换的数据包,描述了节点支持的协议
type protoHandshake struct {
	// 协议握手这个协议自身的版本,定义在baseProtocolVersion,就是5
	Version uint64
	// 节点的名称
	Name string
	// 保存本地或者远程节点支持的所有协议的名称和版本
	Caps       []Cap
	ListenPort uint64
	// 保存了64字节的公钥,去掉了公钥开头的第一个固定字节04
	ID []byte // secp256k1 public key

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// PeerEventType is the type of peer events emitted by a p2p.Server
type PeerEventType string

const (
	// PeerEventTypeAdd is the type of event emitted when a peer is added
	// to a p2p.Server
	PeerEventTypeAdd PeerEventType = "add"

	// PeerEventTypeDrop is the type of event emitted when a peer is
	// dropped from a p2p.Server
	PeerEventTypeDrop PeerEventType = "drop"

	// PeerEventTypeMsgSend is the type of event emitted when a
	// message is successfully sent to a peer
	PeerEventTypeMsgSend PeerEventType = "msgsend"

	// PeerEventTypeMsgRecv is the type of event emitted when a
	// message is received from a peer
	PeerEventTypeMsgRecv PeerEventType = "msgrecv"
)

// PeerEvent is an event emitted when peers are either added or dropped from
// a p2p.Server or when a message is sent or received on a peer connection
// PeerEvent总共有四种,分别是增加或者移除节点,以及接收或发送消息
// PeerEventTypeAdd,PeerEventTypeDrop,PeerEventTypeMsgSend,PeerEventTypeMsgRecv
type PeerEvent struct {
	Type PeerEventType `json:"type"`
	// 事件发生的节点，也就是接收到或发送消息的本地节点的id
	Peer          enode.ID `json:"peer"`
	Error         string   `json:"error,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	MsgCode       *uint64  `json:"msg_code,omitempty"`
	MsgSize       *uint32  `json:"msg_size,omitempty"`
	LocalAddress  string   `json:"local,omitempty"`
	RemoteAddress string   `json:"remote,omitempty"`
}

// Peer represents a connected remote node.
// Peer代表一个本地已经连接的远程节点
type Peer struct {
	rw *conn
	// 协议名称->protoRW对象的映射
	// 保存了本地与这个Peer之间同时支持的子协议
	running map[string]*protoRW
	log     log.Logger
	created mclock.AbsTime

	wg sync.WaitGroup
	// 接收用户自定义的Run函数返回的错误,还有发送Ping包遇到错误
	protoErr chan error
	closed   chan struct{}
	disc     chan DiscReason

	// events receives message send / receive events if set
	// events不为nil的时候,每次接收和发送消息都会通过这个Feed对象发送通知
	events   *event.Feed
	testPipe *MsgPipeRW // for testing
}

// NewPeer returns a peer for testing purposes.
// 只用在测试中
func NewPeer(id enode.ID, name string, caps []Cap) *Peer {
	// Generate a fake set of local protocols to match as running caps. Almost
	// no fields needs to be meaningful here as we're only using it to cross-
	// check with the "remote" caps array.
	protos := make([]Protocol, len(caps))
	for i, cap := range caps {
		protos[i].Name = cap.Name
		protos[i].Version = cap.Version
	}
	pipe, _ := net.Pipe()
	node := enode.SignNull(new(enr.Record), id)
	conn := &conn{fd: pipe, transport: nil, node: node, caps: caps, name: name}
	peer := newPeer(log.Root(), conn, protos)
	close(peer.closed) // ensures Disconnect doesn't block
	return peer
}

// NewPeerPipe creates a peer for testing purposes.
// The message pipe given as the last parameter is closed when
// Disconnect is called on the peer.
func NewPeerPipe(id enode.ID, name string, caps []Cap, pipe *MsgPipeRW) *Peer {
	p := NewPeer(id, name, caps)
	p.testPipe = pipe
	return p
}

// ID returns the node's public key.
func (p *Peer) ID() enode.ID {
	return p.rw.node.ID()
}

// Node returns the peer's node descriptor.
func (p *Peer) Node() *enode.Node {
	return p.rw.node
}

// Name returns an abbreviated form of the name
// Name如果是对Fullname的省略,小于20字节时Name和Fullname一致
// Fullname超过20个字节后面使用省略号缩写
func (p *Peer) Name() string {
	s := p.rw.name
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// Fullname returns the node name that the remote node advertised.
// Fullname 就是在Server里定义的Name
func (p *Peer) Fullname() string {
	return p.rw.name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *Peer) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RunningCap returns true if the peer is actively connected using any of the
// enumerated versions of a specific protocol, meaning that at least one of the
// versions is supported by both this node and the peer p.
// 判断这个对等节点是否支持运行输入的协议
func (p *Peer) RunningCap(protocol string, versions []uint) bool {
	if proto, ok := p.running[protocol]; ok {
		for _, ver := range versions {
			if proto.Version == ver {
				return true
			}
		}
	}
	return false
}

// RemoteAddr returns the remote address of the network connection.
func (p *Peer) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}

// LocalAddr returns the local address of the network connection.
func (p *Peer) LocalAddr() net.Addr {
	return p.rw.fd.LocalAddr()
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *Peer) Disconnect(reason DiscReason) {
	if p.testPipe != nil {
		p.testPipe.Close()
	}

	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	id := p.ID()
	return fmt.Sprintf("Peer %x %v", id[:8], p.RemoteAddr())
}

// Inbound returns true if the peer is an inbound connection
// Inbound为true代表这个peer主动连接的本地
// 为false代表本地主动连接的这个peer
func (p *Peer) Inbound() bool {
	return p.rw.is(inboundConn)
}

// 真实环境中创建Peer对象的方法,在launchPeer中调用
// 创建一个Peer需要已经执行完所有握手的conn对象和本地支持的协议
// newPeer内部根据本地支持的协议获取远程节点和本地都支持的协议进行执行
func newPeer(log log.Logger, conn *conn, protocols []Protocol) *Peer {
	// 对比本地和远程节点支持的协议名称和版本,得到两者共同支持的协议对象
	protomap := matchProtocols(protocols, conn.caps, conn)
	p := &Peer{
		rw:      conn,
		running: protomap,
		created: mclock.Now(),
		disc:    make(chan DiscReason),
		// 所有正在运行的子协议还有pingLoop会向这个管道输入错误
		protoErr: make(chan error, len(protomap)+1), // protocols + pingLoop
		closed:   make(chan struct{}),
		log:      log.New("id", conn.node.ID(), "conn", conn.flags),
	}
	return p
}

func (p *Peer) Log() log.Logger {
	return p.log
}

func (p *Peer) run() (remoteRequested bool, err error) {
	// 运行过程中会遇到三种错误
	// writeErr,readErr,protoErr
	// writeErr每发送一条消息会收到一个错误,可能是nil
	// readErr一定是读取的时候发生了问题,不会是nil
	var (
		// 用于控制一个节点所有协议线性的发送消息,不能并发的发送消息
		// 每发送一条消息再向管道写入一个元素,控制最多同时只有一个在发送
		writeStart = make(chan struct{}, 1)
		writeErr   = make(chan error, 1)
		// readLoop中发生的错误发送到这里
		readErr = make(chan error, 1)
		reason  DiscReason // sent to the peer
	)
	// run中执行了readLoop和pingLoop两个循环
	p.wg.Add(2)
	go p.readLoop(readErr)
	// pingLoop中发生的错误发送到protoErr中
	go p.pingLoop()

	// Start all protocol handlers.
	writeStart <- struct{}{}
	// 启动用户定义的协议
	p.startProtocols(writeStart, writeErr)

	// Wait for an error or disconnect.
	// 在这里阻塞住,等待以下的任何一个管道发生了错误,将错误保存到err中
loop:
	for {
		select {
		// 每发送一条消息都会收到一个writeErr,没有错误收到nil
		case err = <-writeErr:
			// A write finished. Allow the next write to start if
			// there was no error.
			if err != nil {
				reason = DiscNetworkError
				break loop
			}
			// 每发送完成一条就立刻再向管道里写入一个元素
			writeStart <- struct{}{}
		// readErr一定收到非nil的错误
		case err = <-readErr:
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				reason = r
			} else {
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr:
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc:
			reason = discReasonForError(err)
			break loop
		}
	}

	close(p.closed)
	p.rw.close(reason)
	p.wg.Wait()
	return remoteRequested, err
}

// 在run函数中调用
// 每15秒周期性的向对方发送ping包,确保对方在线而且保持连接不断开
// 因为frameReadTimeout控制了超过30s不收发消息会导致连接断开,所以这里15s发送一次控制不断开连接
func (p *Peer) pingLoop() {
	ping := time.NewTimer(pingInterval)
	defer p.wg.Done()
	defer ping.Stop()
	for {
		select {
		case <-ping.C:
			if err := SendItems(p.rw, pingMsg); err != nil {
				p.protoErr <- err
				return
			}
			ping.Reset(pingInterval)
		case <-p.closed:
			return
		}
	}
}

// 持续从rw中读取消息,读取到的消息调用Peer.handle
// 一旦发生错误,将错误发送到参数errc管道中,并结束该函数
// 在run函数中调用
func (p *Peer) readLoop(errc chan<- error) {
	defer p.wg.Done()
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			errc <- err
			return
		}
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			errc <- err
			return
		}
	}
}

// 处理接收到的消息
// 消息可能是预定义的消息和用户定义消息
// 预定义消息现在有ping和disc,收到ping返回pong,收到disc获取断开原因
// 用户定义消息发送到对应协议的in管道中
func (p *Peer) handle(msg Msg) error {
	// 首先判断消息码是不是在baseProtocolLength之前,如果是说明是预定义消息
	// 不然的话是用户实现的子协议,使用子协议进行处理
	switch {
	// 收到ping,回复pong
	case msg.Code == pingMsg:
		msg.Discard()
		go SendItems(p.rw, pongMsg)
	// 收到断开连接的消息,返回错误保存了断开连接的原因
	case msg.Code == discMsg:
		var reason [1]DiscReason
		// This is the last message. We don't need to discard or
		// check errors because, the connection will be closed after it.
		rlp.Decode(msg.Payload, &reason)
		return reason[0]
	case msg.Code < baseProtocolLength:
		// ignore other base protocol messages
		return msg.Discard()
	default:
		// it's a subprotocol message
		// 寻找处理这条消息的子协议
		proto, err := p.getProto(msg.Code)
		if err != nil {
			return fmt.Errorf("msg code out of range: %v", msg.Code)
		}
		if metrics.Enabled {
			m := fmt.Sprintf("%s/%s/%d/%#02x", ingressMeterName, proto.Name, proto.Version, msg.Code-proto.offset)
			// 统计总共通过网络传输的多少字节的流量
			metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize))
			// 统计接收了远程多少包
			metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)
		}
		// 将数据发送给对应的协议处理
		select {
		case proto.in <- msg:
			return nil
		case <-p.closed:
			return io.EOF
		}
	}
	return nil
}

func countMatchingProtocols(protocols []Protocol, caps []Cap) int {
	n := 0
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				n++
			}
		}
	}
	return n
}

// matchProtocols creates structures for matching named subprotocols.
// 比对本地支持的协议和远程支持的协议,获得两者同时支持的协议
// protocols是本地的子协议,caps是远程节点支持的协议
func matchProtocols(protocols []Protocol, caps []Cap, rw MsgReadWriter) map[string]*protoRW {
	// 对远程节点支持的协议进行排序
	sort.Sort(capsByNameAndVersion(caps))
	offset := baseProtocolLength
	result := make(map[string]*protoRW)

outer:
	for _, cap := range caps {
		for _, proto := range protocols {
			// 找到两者共同支持的协议了
			if proto.Name == cap.Name && proto.Version == cap.Version {
				// If an old protocol version matched, revert it
				// 这个协议双方都支持某些旧版本,更新使用最新版本
				if old := result[cap.Name]; old != nil {
					// 去掉老版本的偏移量
					offset -= old.Length
				}
				// Assign the new match
				// 保存共同支持的协议
				result[cap.Name] = &protoRW{Protocol: proto, offset: offset, in: make(chan Msg), w: rw}
				// 加上新版本的偏移量
				offset += proto.Length

				// 本地已经匹配到远程节点的某个协议的某个版本了
				// 不再继续查询本地支持的其他协议，继续匹配远程节点的下一个协议
				continue outer
			}
		}
	}
	return result
}

// 启动运行所有子协议
// 每个子协议的Run函数执行在一个协程中
func (p *Peer) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {
	p.wg.Add(len(p.running))
	for _, proto := range p.running {
		proto := proto
		// 所有子协议共用一个关闭通知管道
		proto.closed = p.closed
		// 所有子协议共用一个消息可以写入的通知管道
		proto.wstart = writeStart
		proto.werr = writeErr
		var rw MsgReadWriter = proto
		// 如果events不是nil,就将原来的rw用msgEventer封装,增加发送通知的功能
		if p.events != nil {
			rw = newMsgEventer(rw, p.events, p.ID(), proto.Name, p.Info().Network.RemoteAddress, p.Info().Network.LocalAddress)
		}
		p.log.Trace(fmt.Sprintf("Starting protocol %s/%d", proto.Name, proto.Version))
		// 在协程里运行每个子协议
		go func() {
			defer p.wg.Done()
			err := proto.Run(p, rw)
			// 用户定义的协议函数返回了一个nil的错误
			// 说明用户设计的协议有问题,正常运行不应该返回
			if err == nil {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d returned", proto.Name, proto.Version))
				// 用户定义的Run函数不应该返回nil的错误
				err = errProtocolReturned
			} else if err != io.EOF {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d failed", proto.Name, proto.Version), "err", err)
			}
			p.protoErr <- err
		}()
	}
}

// getProto finds the protocol responsible for handling
// the given message code.
// 输入消息码,判断使用哪个子协议进行处理
func (p *Peer) getProto(code uint64) (*protoRW, error) {
	// 遍历所有支持的协议,在[offset,offset+Length)之间的就是支持的协议
	for _, proto := range p.running {
		if code >= proto.offset && code < proto.offset+proto.Length {
			return proto, nil
		}
	}
	// 找不到返回错误
	return nil, newPeerError(errInvalidMsgCode, "%d", code)
}

// 为每个子协议生成一个protoRW对象,实现了MsgReadWriter接口,用来收发这个子协议自己的消息
// 每个子协议从自己的in管道中接收消息
type protoRW struct {
	Protocol
	// handle函数中根据消息码识别应该将消息分配给哪个协议,分配过程就是发送到in管道中
	in chan Msg // receives read messages
	// 当节点关闭的时候此管道关闭，通知所有子协议关闭
	closed <-chan struct{} // receives when peer is shutting down
	// 所有子协议共用一个wstart，每完成一个消息发送会向此管道发送一个数据
	// 保证所有子协议同时只能有一个在发送消息
	wstart <-chan struct{} // receives when write may start
	werr   chan<- error    // for write results
	// 由于Protocol对象的消息码都是从0开始,为了避免在发送消息时重复
	// 在内部将不同的子协议进行排序,计算他们各自消息码的相对于0的偏移量
	// 每个子协议真实发送的消息码是 [proto.offset,proto.offset+proto.Length)
	// 在接收方减去offset后,再暴露给使用者
	offset uint64
	w      MsgWriter
}

// 这里输入的消息码是用户定义的从0开始
// 内部转换成实际在链路上发送消息码
func (rw *protoRW) WriteMsg(msg Msg) (err error) {
	// 接收到消息的消息码必须在[0,Length)范围内
	if msg.Code >= rw.Length {
		return newPeerError(errInvalidMsgCode, "not handled")
	}
	msg.meterCap = rw.cap()
	msg.meterCode = msg.Code

	// 加上偏移量，转换成实际传输的消息码
	msg.Code += rw.offset

	select {
	// 只有从wstart中读取到数据后，当前子协议才允许发送数据
	case <-rw.wstart:
		err = rw.w.WriteMsg(msg)
		// Report write status back to Peer.run. It will initiate
		// shutdown if the error is non-nil and unblock the next write
		// otherwise. The calling protocol code should exit for errors
		// as well but we don't want to rely on that.
		// 如果错误非nil就会让节点立刻关闭,错误是nil通知run往writeStart写入一个元素,允许继续发送
		rw.werr <- err
	case <-rw.closed:
		err = ErrShuttingDown
	}
	return err
}

// 从in管道读取一条消息并返回
func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg := <-rw.in:
		msg.Code -= rw.offset
		return msg, nil
	case <-rw.closed:
		return Msg{}, io.EOF
	}
}

// PeerInfo represents a short summary of the information known about a connected
// peer. Sub-protocol independent fields are contained and initialized here, with
// protocol specifics delegated to all connected sub-protocols.
type PeerInfo struct {
	ENR     string   `json:"enr,omitempty"` // Ethereum Node Record
	Enode   string   `json:"enode"`         // Node URL
	ID      string   `json:"id"`            // Unique node identifier
	Name    string   `json:"name"`          // Name of the node, including client type, version, OS, custom data
	Caps    []string `json:"caps"`          // Protocols advertised by this peer
	Network struct {
		LocalAddress  string `json:"localAddress"`  // Local endpoint of the TCP data connection
		RemoteAddress string `json:"remoteAddress"` // Remote endpoint of the TCP data connection
		Inbound       bool   `json:"inbound"`
		Trusted       bool   `json:"trusted"`
		Static        bool   `json:"static"`
	} `json:"network"`
	Protocols map[string]interface{} `json:"protocols"` // Sub-protocol specific metadata fields
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *Peer) Info() *PeerInfo {
	// Gather the protocol capabilities
	var caps []string
	for _, cap := range p.Caps() {
		caps = append(caps, cap.String())
	}
	// Assemble the generic peer metadata
	info := &PeerInfo{
		Enode:     p.Node().URLv4(),
		ID:        p.ID().String(),
		Name:      p.Fullname(),
		Caps:      caps,
		Protocols: make(map[string]interface{}),
	}
	if p.Node().Seq() > 0 {
		info.ENR = p.Node().String()
	}
	info.Network.LocalAddress = p.LocalAddr().String()
	info.Network.RemoteAddress = p.RemoteAddr().String()
	info.Network.Inbound = p.rw.is(inboundConn)
	info.Network.Trusted = p.rw.is(trustedConn)
	info.Network.Static = p.rw.is(staticDialedConn)

	// Gather all the running protocol infos
	for _, proto := range p.running {
		protoInfo := interface{}("unknown")
		if query := proto.Protocol.PeerInfo; query != nil {
			if metadata := query(p.ID()); metadata != nil {
				protoInfo = metadata
			} else {
				protoInfo = "handshake"
			}
		}
		info.Protocols[proto.Name] = protoInfo
	}
	return info
}
