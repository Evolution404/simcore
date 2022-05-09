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

package discover

import (
	"bytes"
	"container/list"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/discover/v4wire"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/netutil"
)

// Errors
var (
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
	errLowPort          = errors.New("low port")
)

const (
	// 发送一个请求后,等待超时的时间是500毫秒
	respTimeout = 500 * time.Millisecond
	// 发送的数据包的超时时间都是现在的时间加上20秒
	expiration = 20 * time.Second
	// 超过24小时没有沟通就发送ping
	bondExpiration = 24 * time.Hour

	maxFindnodeFailures = 5 // nodes exceeding this limit are dropped
	// 超时错误次数达到32次就进行ntp更新时间
	ntpFailureThreshold = 32 // Continuous timeouts after which to check NTP
	// ntp更新的时间间隔最少是10分钟,避免频繁尝试更新
	ntpWarningCooldown = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	// 时间误差最多十秒
	driftThreshold = 10 * time.Second // Allowed clock drift before warning user

	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	maxPacketSize = 1280
)

// UDPv4 implements the v4 wire protocol.
type UDPv4 struct {
	conn        UDPConn
	log         log.Logger
	netrestrict *netutil.Netlist
	priv        *ecdsa.PrivateKey
	localNode   *enode.LocalNode
	db          *enode.DB
	tab         *Table
	closeOnce   sync.Once
	// 用来等待loop和readLoop函数执行完成
	wg sync.WaitGroup

	addReplyMatcher chan *replyMatcher
	gotreply        chan reply
	closeCtx        context.Context
	cancelCloseCtx  context.CancelFunc
}

// replyMatcher represents a pending reply.
//
// Some implementations of the protocol wish to send more than one
// reply packet to findnode. In general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// Our implementation handles this by storing a callback function for
// each pending reply. Incoming packets from a node are dispatched
// to all callback functions for that node.
// 保存本地正在的等待的Pong、Findnode、ENRRequest包相关信息
type replyMatcher struct {
	// these fields must match in the reply.
	// 等待的包的发送者的ID
	from enode.ID
	// 等待的包的发送者的IP
	ip net.IP
	// 正在等待的包的类型
	ptype byte

	// time when the request must complete
	// 等待的包的超时时间
	deadline time.Time

	// callback is called when a matching reply arrives. If it returns matched == true, the
	// reply was acceptable. The second return value indicates whether the callback should
	// be removed from the pending reply queue. If it returns false, the reply is considered
	// incomplete and the callback will be invoked again for the next matching reply.
	callback replyMatchFunc

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	// 会话结束后此管道将接收到一个错误信息数据,没有错误也会接收到一个nil
	// 所以监听此管道将一直阻塞到会话结束,同时获得错误信息
	errc chan error

	// reply contains the most recent reply. This field is safe for reading after errc has
	// received a value.
	reply v4wire.Packet
}

// 返回包匹配到会话后调用的回调函数,返回值包括数据包是否匹配、当前会话是否完成
// Ping: 需要Pong包保存了Ping的哈希才算匹配
// Findnode: 一定匹配;需要接收到Neighbors返回了16个节点信息才结束会话
// ENRRequest: 需要ENRResponse保存了ENRRequest的哈希才算匹配
type replyMatchFunc func(v4wire.Packet) (matched bool, requestDone bool)

// reply is a reply packet from a certain node.
type reply struct {
	from enode.ID
	ip   net.IP
	data v4wire.Packet
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}

// 启动v4版本的节点发现
// 启动后开始监听远程节点发送的数据包并进行处理
func ListenV4(c UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	cfg = cfg.withDefaults()
	closeCtx, cancel := context.WithCancel(context.Background())
	t := &UDPv4{
		conn:            c,
		priv:            cfg.PrivateKey,
		netrestrict:     cfg.NetRestrict,
		localNode:       ln,
		db:              ln.Database(),
		gotreply:        make(chan reply),
		addReplyMatcher: make(chan *replyMatcher),
		closeCtx:        closeCtx,
		cancelCloseCtx:  cancel,
		log:             cfg.Log,
	}

	tab, err := newTable(t, ln.Database(), cfg.Bootnodes, t.log)
	if err != nil {
		return nil, err
	}
	t.tab = tab
	// 启动三个循环
	go tab.loop()

	t.wg.Add(2)
	// 启动会话处理循环
	go t.loop()
	// 启动网络监听循环,不断从网络连接中读取数据
	go t.readLoop(cfg.Unhandled)
	return t, nil
}

// Self returns the local node.
func (t *UDPv4) Self() *enode.Node {
	return t.localNode.Node()
}

// Close shuts down the socket and aborts any running queries.
func (t *UDPv4) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		// 等待t.loop和t.readLoop执行完成
		t.wg.Wait()
		t.tab.close()
	})
}

// Resolve searches for a specific node with the given ID and tries to get the most recent
// version of the node record for it. It returns n if the node could not be resolved.
// 获取输入节点的ENR记录的最新版本
func (t *UDPv4) Resolve(n *enode.Node) *enode.Node {
	// Try asking directly. This works if the node is still responding on the endpoint we have.
	if rn, err := t.RequestENR(n); err == nil {
		return rn
	}
	// Check table for the ID, we might have a newer version there.
	if intable := t.tab.getNode(n.ID()); intable != nil && intable.Seq() > n.Seq() {
		n = intable
		if rn, err := t.RequestENR(n); err == nil {
			return rn
		}
	}
	// Otherwise perform a network lookup.
	var key enode.Secp256k1
	if n.Load(&key) != nil {
		return n // no secp256k1 key
	}
	result := t.LookupPubkey((*ecdsa.PublicKey)(&key))
	for _, rn := range result {
		if rn.ID() == n.ID() {
			if rn, err := t.RequestENR(rn); err == nil {
				return rn
			}
		}
	}
	return n
}

// 创建本地的Endpoint对象,用于发送Ping包的时候的From字段
func (t *UDPv4) ourEndpoint() v4wire.Endpoint {
	n := t.Self()
	a := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	return v4wire.NewEndpoint(a, uint16(n.TCP()))
}

// Ping sends a ping message to the given node.
func (t *UDPv4) Ping(n *enode.Node) error {
	_, err := t.ping(n)
	return err
}

// ping sends a ping message to the given node and waits for a reply.
func (t *UDPv4) ping(n *enode.Node) (seq uint64, err error) {
	rm := t.sendPing(n.ID(), &net.UDPAddr{IP: n.IP(), Port: n.UDP()}, nil)
	// 等待会话结束
	if err = <-rm.errc; err == nil {
		seq = rm.reply.(*v4wire.Pong).ENRSeq
	}
	return seq, err
}

// sendPing sends a ping message to the given node and invokes the callback
// when the reply arrives.
// 向远程节点发送ping包,收到返回后调用callback
func (t *UDPv4) sendPing(toid enode.ID, toaddr *net.UDPAddr, callback func()) *replyMatcher {
	// 先构造ping包对象
	req := t.makePing(toaddr)
	// 编码ping包为字节流
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return &replyMatcher{errc: errc}
	}
	// Add a matcher for the reply to the pending reply queue. Pongs are matched if they
	// reference the ping we're about to send.
	// 启动Ping包的会话过程,注册Ping包的回调函数
	rm := t.pending(toid, toaddr.IP, v4wire.PongPacket, func(p v4wire.Packet) (matched bool, requestDone bool) {
		// 校验pong是否与ping对应
		matched = bytes.Equal(p.(*v4wire.Pong).ReplyTok, hash)
		if matched && callback != nil {
			callback()
		}
		return matched, matched
	})
	// Send the packet.
	t.localNode.UDPContact(toaddr)
	// 向远程节点发送数据
	t.write(toaddr, toid, req.Name(), packet)
	return rm
}

// 构造ping的数据包对象
func (t *UDPv4) makePing(toaddr *net.UDPAddr) *v4wire.Ping {
	return &v4wire.Ping{
		Version:    4,
		From:       t.ourEndpoint(),
		To:         v4wire.NewEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	}
}

// LookupPubkey finds the closest nodes to the given public key.
// 根据节点的公钥查询距离最近的节点
func (t *UDPv4) LookupPubkey(key *ecdsa.PublicKey) []*enode.Node {
	if t.tab.len() == 0 {
		// All nodes were dropped, refresh. The very first query will hit this
		// case and run the bootstrapping logic.
		<-t.tab.refresh()
	}
	return t.newLookup(t.closeCtx, encodePubkey(key)).run()
}

// RandomNodes is an iterator yielding nodes from a random walk of the DHT.
func (t *UDPv4) RandomNodes() enode.Iterator {
	return newLookupIterator(t.closeCtx, t.newRandomLookup)
}

// lookupRandom implements transport.
// 查询随机16个节点
func (t *UDPv4) lookupRandom() []*enode.Node {
	return t.newRandomLookup(t.closeCtx).run()
}

// lookupSelf implements transport.
// 用于实现transport接口
// 查询距离自己最近的几个节点
func (t *UDPv4) lookupSelf() []*enode.Node {
	return t.newLookup(t.closeCtx, encodePubkey(&t.priv.PublicKey)).run()
}

// 创建一个随机的节点,用于接下来的查询
func (t *UDPv4) newRandomLookup(ctx context.Context) *lookup {
	var target encPubkey
	crand.Read(target[:])
	return t.newLookup(ctx, target)
}

// 指定要查询的目标节点的公钥,新建lookup对象
func (t *UDPv4) newLookup(ctx context.Context, targetKey encPubkey) *lookup {
	target := enode.ID(crypto.Keccak256Hash(targetKey[:]))
	ekey := v4wire.Pubkey(targetKey)
	it := newLookup(ctx, t.tab, target, func(n *node) ([]*node, error) {
		return t.findnode(n.ID(), n.addr(), ekey)
	})
	return it
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
// 向远程节点发送findnode请求,并返回获取到的新节点
func (t *UDPv4) findnode(toid enode.ID, toaddr *net.UDPAddr, target v4wire.Pubkey) ([]*node, error) {
	t.ensureBond(toid, toaddr)

	// Add a matcher for 'neighbours' replies to the pending reply queue. The matcher is
	// active until enough nodes have been received.
	nodes := make([]*node, 0, bucketSize)
	nreceived := 0
	// 启动Findnode的会话,并注册回调函数
	// 此回调函数可能调用多次,因为返回的节点可能分成多次发送,一直返回了16个节点才结束
	rm := t.pending(toid, toaddr.IP, v4wire.NeighborsPacket, func(r v4wire.Packet) (matched bool, requestDone bool) {
		reply := r.(*v4wire.Neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				t.log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		// 接收到的数量达到16才代表完全结束
		return true, nreceived >= bucketSize
	})
	// 发送实际的Findnode包
	t.send(toaddr, toid, &v4wire.Findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	// Ensure that callers don't see a timeout if the node actually responded. Since
	// findnode can receive more than one neighbors response, the reply matcher will be
	// active until the remote node sends enough nodes. If the remote end doesn't have
	// enough nodes the reply matcher will time out waiting for the second reply, but
	// there's no need for an error in that case.
	// 等待会话结束,也就是接收到了完整的16个节点
	err := <-rm.errc
	if err == errTimeout && rm.reply != nil {
		err = nil
	}
	return nodes, err
}

// RequestENR sends enrRequest to the given node and waits for a response.
// 向远程节点请求最新的ENR记录
// RequestENR的结构
// packet = packet-header || packet-data
// packet-header = hash || signature || packet-type
// hash = keccak256(signature || packet-type || packet-data)
// signature = sign(packet-type || packet-data)
// packet-data = [expiration]
func (t *UDPv4) RequestENR(n *enode.Node) (*enode.Node, error) {
	// 构造发送的目的地址
	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	// 保证远程节点处于正常状态,没有超过24小时不沟通,错误次数没有过多
	t.ensureBond(n.ID(), addr)

	// 构造请求对象
	req := &v4wire.ENRRequest{
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	// packet是最终发送的包的字节流,hash是 keccak256(signature || packet-type || packet-data)
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		return nil, err
	}

	// Add a matcher for the reply to the pending reply queue. Responses are matched if
	// they reference the request we're about to send.
	rm := t.pending(n.ID(), addr.IP, v4wire.ENRResponsePacket, func(r v4wire.Packet) (matched bool, requestDone bool) {
		matched = bytes.Equal(r.(*v4wire.ENRResponse).ReplyTok, hash)
		return matched, matched
	})
	// Send the packet and wait for the reply.
	// 向远程节点发送packet中的内容
	t.write(addr, n.ID(), req.Name(), packet)
	// 这里会阻塞,如果一切正常会从errc中读取到nil
	if err := <-rm.errc; err != nil {
		return nil, err
	}
	// Verify the response record.
	// 使用返回的数据创建一个节点
	respN, err := enode.New(enode.ValidSchemes, &rm.reply.(*v4wire.ENRResponse).Record)
	if err != nil {
		return nil, err
	}
	if respN.ID() != n.ID() {
		return nil, fmt.Errorf("invalid ID in response record")
	}
	// 返回的信息没有本地新,还是返回原来的信息
	if respN.Seq() < n.Seq() {
		return n, nil // response record is older
	}
	// 确认返回的ip地址有效,例如避免返回的ip是特殊地址,
	if err := netutil.CheckRelayIP(addr.IP, respN.IP()); err != nil {
		return nil, fmt.Errorf("invalid IP in response record: %v", err)
	}
	return respN, nil
}

// pending adds a reply matcher to the pending reply queue.
// see the documentation of type replyMatcher for a detailed explanation.
// 发送Ping、Findnode、ENRRequest数据包后调用此方法,等待他们的返回数据包
// 构造replyMatcher对象发送到addReplyMatcher管道中等待loop中处理
// callback在接收到返回消息后调用
func (t *UDPv4) pending(id enode.ID, ip net.IP, ptype byte, callback replyMatchFunc) *replyMatcher {
	ch := make(chan error, 1)
	p := &replyMatcher{from: id, ip: ip, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addReplyMatcher <- p:
		// loop will handle it
	case <-t.closeCtx.Done():
		ch <- errClosed
	}
	return p
}

// handleReply dispatches a reply packet, invoking reply matchers. It returns
// whether any matcher considered the packet acceptable.
// 本地接收到Pong、Neighbors、ENRResponse这种返回包时调用
// 用于构造relpy对象发送到getreply管道中,等待loop中处理
func (t *UDPv4) handleReply(from enode.ID, fromIP net.IP, req v4wire.Packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, fromIP, req, matched}:
		// loop will handle it
		// loop中将是否匹配的结果写入matched管道中
		return <-matched
	case <-t.closeCtx.Done():
		return false
	}
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
// 会话处理循环,内部监听会话的启动(发送请求包)和结束(收到返回包)
func (t *UDPv4) loop() {
	defer t.wg.Done()

	var (
		plist = list.New()
		// 即将超时的会话的到期时间
		timeout = time.NewTimer(0)
		// 保存即将超时的会话,还未超时但最早超时的会话
		nextTimeout *replyMatcher // head of plist when timeout was last reset
		// 统计超时错误发生的次数,连续发生32次执行ntp更新时间
		contTimeouts = 0 // number of continuous timeouts to do NTP checks
		// 记录上次进行ntp更新的时间,用于控制执行ntp最多10分钟一次
		ntpWarnTime = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	// 找到即将超时的会话和它的到期时间
	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*replyMatcher)
			// 返回结果的超时时间是respTimeout,由于系统时间误差这里限制为2*respTimeout
			// 超过2*respTimeout直接从链表中删除
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closeCtx.Done():
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*replyMatcher).errc <- errClosed
			}
			return

		// 监听会话启动
		// 向超时链表尾部添加一个新的请求包会话,超时时间设置为500毫秒后
		case p := <-t.addReplyMatcher:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		// 监听会话结束,也就是接收到了返回包
		case r := <-t.gotreply:
			var matched bool // whether any replyMatcher considered the reply acceptable.
			// 遍历链表中所有元素,找到匹配的会话
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				// 找到对应的会话
				if p.from == r.from && p.ptype == r.data.Kind() && p.ip.Equal(r.ip) {
					ok, requestDone := p.callback(r.data)
					matched = matched || ok
					// 保存返回的数据
					p.reply = r.data
					// Remove the matcher if callback indicates that all replies have been received.
					if requestDone {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			// 通知reply对象是否匹配成功
			r.matched <- matched

		// 超时触发,向所有超时的replyMatcher发送超时错误,并从链表删除
		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			// 超时错误超过32次,通过ntp更新时间
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

// 输入v4wire.Packet对象,编码成字节数组后向远程节点发送数据包
// 返回数据包的哈希和错误
func (t *UDPv4) send(toaddr *net.UDPAddr, toid enode.ID, req v4wire.Packet) ([]byte, error) {
	// 编码数据包
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, toid, req.Name(), packet)
}

// 向toaddr发送packet中的数据
// toid和what用来打印Trace等级的日志
func (t *UDPv4) write(toaddr *net.UDPAddr, toid enode.ID, what string, packet []byte) error {
	// 向远程节点发送udp数据包
	_, err := t.conn.WriteToUDP(packet, toaddr)
	t.log.Trace(">> "+what, "id", toid, "addr", toaddr, "err", err)
	return err
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
// 不断从网络中读取udp数据包
// 没有被处理的包发送到unhandled管道中
func (t *UDPv4) readLoop(unhandled chan<- ReadPacket) {
	defer t.wg.Done()
	if unhandled != nil {
		defer close(unhandled)
	}

	buf := make([]byte, maxPacketSize)
	for {
		// 接收网络中的数据
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		// 读取数据后首先进行错误处理,忽略临时错误,发生其他错误结束监听
		// 临时错误打印错误信息,继续监听
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			t.log.Debug("Temporary UDP read error", "err", err)
			continue
			// 其他的错误直接返回函数,结束监听
		} else if err != nil {
			// Shut down the loop for permament errors.
			if err != io.EOF {
				t.log.Debug("UDP read error", "err", err)
			}
			return
		}
		// 处理数据,如果处理失败那么就将数据包发送到unhandled管道中
		if t.handlePacket(from, buf[:nbytes]) != nil && unhandled != nil {
			select {
			case unhandled <- ReadPacket{buf[:nbytes], from}:
			default:
			}
		}
	}
}

// 接收到的数据都传入handlePacket来处理
// 将buf中的数据解码为v4wire.Packet,封装为packetHandlerV4对象后调用对应的preverify和handle函数
func (t *UDPv4) handlePacket(from *net.UDPAddr, buf []byte) error {
	// 解码接收到的字节流为数据包对象
	rawpacket, fromKey, hash, err := v4wire.Decode(buf)
	if err != nil {
		t.log.Debug("Bad discv4 packet", "addr", from, "err", err)
		return err
	}
	packet := t.wrapPacket(rawpacket)
	fromID := fromKey.ID()
	// 先调用preverify再调用handle
	if err == nil && packet.preverify != nil {
		err = packet.preverify(packet, from, fromID, fromKey)
	}
	t.log.Trace("<< "+packet.Name(), "id", fromID, "addr", from, "err", err)
	if err == nil && packet.handle != nil {
		packet.handle(packet, from, fromID, hash)
	}
	return err
}

// checkBond checks if the given node has a recent enough endpoint proof.
// 检查上次收到这个节点的pong是否超过了24小时
func (t *UDPv4) checkBond(id enode.ID, ip net.IP) bool {
	return time.Since(t.db.LastPongReceived(id, ip)) < bondExpiration
}

// ensureBond solicits a ping from a node if we haven't seen a ping from it for a while.
// This ensures there is a valid endpoint proof on the remote end.
// 判断该节点的上次pong是否超过24小时,超过了24小时本地主动向对方发送ping
func (t *UDPv4) ensureBond(toid enode.ID, toaddr *net.UDPAddr) {
	// 上次ping的时间是否超过24小时
	tooOld := time.Since(t.db.LastPingReceived(toid, toaddr.IP)) > bondExpiration
	// 超时或者错误次数过多,发送ping
	if tooOld || t.db.FindFails(toid, toaddr.IP) > maxFindnodeFailures {
		rm := t.sendPing(toid, toaddr, nil)
		// 阻塞住,直到成功收到pong或者出现错误
		<-rm.errc
		// Wait for them to ping back and process our pong.
		time.Sleep(respTimeout)
	}
}

func (t *UDPv4) nodeFromRPC(sender *net.UDPAddr, rn v4wire.Node) (*node, error) {
	if rn.UDP <= 1024 {
		return nil, errLowPort
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict list")
	}
	key, err := v4wire.DecodePubkey(crypto.S256(), rn.ID)
	if err != nil {
		return nil, err
	}
	n := wrapNode(enode.NewV4(key, rn.IP, int(rn.TCP), int(rn.UDP)))
	err = n.ValidateComplete()
	return n, err
}

func nodeToRPC(n *node) v4wire.Node {
	var key ecdsa.PublicKey
	var ekey v4wire.Pubkey
	if err := n.Load((*enode.Secp256k1)(&key)); err == nil {
		ekey = v4wire.EncodePubkey(&key)
	}
	return v4wire.Node{ID: ekey, IP: n.IP(), UDP: uint16(n.UDP()), TCP: uint16(n.TCP())}
}

// wrapPacket returns the handler functions applicable to a packet.
// 将v4wire.Packet对象封装成packetHandlerV4
// 为Ping,Findnode,ENRRequest增加了preverify和handle函数
// 为Pong,Neighbors,ENRResponse增加了preverify函数
// Ping,Findnode,ENRRequest在接收到之后除了进行验证还需要发送返回给对方的数据包,所以有handle函数
func (t *UDPv4) wrapPacket(p v4wire.Packet) *packetHandlerV4 {
	var h packetHandlerV4
	h.Packet = p
	switch p.(type) {
	case *v4wire.Ping:
		h.preverify = t.verifyPing
		h.handle = t.handlePing
	case *v4wire.Pong:
		h.preverify = t.verifyPong
	case *v4wire.Findnode:
		h.preverify = t.verifyFindnode
		h.handle = t.handleFindnode
	case *v4wire.Neighbors:
		h.preverify = t.verifyNeighbors
	case *v4wire.ENRRequest:
		h.preverify = t.verifyENRRequest
		h.handle = t.handleENRRequest
	case *v4wire.ENRResponse:
		h.preverify = t.verifyENRResponse
	}
	return &h
}

// packetHandlerV4 wraps a packet with handler functions.
// 接收到的v4wire.Packet类型将会转化成packetHandlerV4类型
type packetHandlerV4 struct {
	v4wire.Packet
	// senderKey只用于ping包
	// 因为收到ping包后有可能需要对方的公钥来创建enode.Node对象,用于添加到节点表中
	senderKey *ecdsa.PublicKey // used for ping

	// preverify checks whether the packet is valid and should be handled at all.
	// 收到数据包后校验是否有效
	preverify func(p *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error
	// handle handles the packet.
	// 校验数据包有效后发送返回信息,针对Ping,Findnode,ENRRequest这三种请求包,发送对应的返回信息
	handle func(req *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte)
}

// PING/v4

// PING包主要验证过期时间,并设置packetHandlerV4.senderKey
func (t *UDPv4) verifyPing(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Ping)

	senderKey, err := v4wire.DecodePubkey(crypto.S256(), fromKey)
	if err != nil {
		return err
	}
	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	h.senderKey = senderKey
	return nil
}

// 本地收到Ping包后的处理函数
// 1. 向对方发送Pong包
// 2. 判断上次接收到对方Ping包的时间,超时的话向对方发送Ping包
func (t *UDPv4) handlePing(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Ping)

	// Reply.
	// 向对方返回Pong包
	t.send(from, fromID, &v4wire.Pong{
		To:         v4wire.NewEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	})

	// Ping back if our last pong on file is too far in the past.
	// 收到了来自对方的ping,需要在表中提前对方的位置
	// 如果本地很久没有ping对方,本地主动向对方也发一个ping
	n := wrapNode(enode.NewV4(h.senderKey, from.IP, int(req.From.TCP), from.Port))
	if time.Since(t.db.LastPongReceived(n.ID(), from.IP)) > bondExpiration {
		t.sendPing(fromID, from, func() {
			t.tab.addVerifiedNode(n)
		})
	} else {
		t.tab.addVerifiedNode(n)
	}

	// Update node database and endpoint predictor.
	t.db.UpdateLastPingReceived(n.ID(), from.IP, time.Now())
	t.localNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
}

// PONG/v4

// 验证过期时间
// 判断是否有对应的ping请求
// 更新NAT的预测以及更新last pong的时间
func (t *UDPv4) verifyPong(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Pong)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.IP, req) {
		return errUnsolicitedReply
	}
	t.localNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
	// 更新收到pong的时间
	t.db.UpdateLastPongReceived(fromID, from.IP, time.Now())
	return nil
}

// FINDNODE/v4

func (t *UDPv4) verifyFindnode(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Findnode)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	// 检查上一次接收到对方的Pong是否超过了24小时
	// 超过24小时的节点不给返回结果
	if !t.checkBond(fromID, from.IP) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors packet (which is a much bigger packet than
		// findnode) to the victim.
		return errUnknownNode
	}
	return nil
}

func (t *UDPv4) handleFindnode(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Findnode)

	// Determine closest nodes.
	target := enode.ID(crypto.Keccak256Hash(req.Target[:]))
	closest := t.tab.findnodeByID(target, bucketSize, true).entries

	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the packet size limit.
	p := v4wire.Neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	var sent bool
	for _, n := range closest {
		if netutil.CheckRelayIP(from.IP, n.IP()) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
		if len(p.Nodes) == v4wire.MaxNeighbors {
			t.send(from, fromID, &p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if len(p.Nodes) > 0 || !sent {
		t.send(from, fromID, &p)
	}
}

// NEIGHBORS/v4

func (t *UDPv4) verifyNeighbors(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Neighbors)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.IP, h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}

// ENRREQUEST/v4

func (t *UDPv4) verifyENRRequest(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.ENRRequest)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.checkBond(fromID, from.IP) {
		return errUnknownNode
	}
	return nil
}

// 收到ENRRequest,返回ENRResponse
// mac代表ENRRequest的哈希
func (t *UDPv4) handleENRRequest(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	t.send(from, fromID, &v4wire.ENRResponse{
		ReplyTok: mac,
		Record:   *t.localNode.Node().Record(),
	})
}

// ENRRESPONSE/v4

func (t *UDPv4) verifyENRResponse(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey v4wire.Pubkey) error {
	if !t.handleReply(fromID, from.IP, h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}
