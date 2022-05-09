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

// Contains the active peer-set of the downloader, maintaining both failures
// as well as reputation metrics to prioritize the block retrievals.

package downloader

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/eth/protocols/eth"
	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/msgrate"
)

const (
	maxLackingHashes = 4096 // Maximum number of entries allowed on the list or lacking items
)

var (
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

// peerConnection represents an active peer from which hashes and blocks are retrieved.
// 两个节点间的连接对象,每个与远程节点的连接都用一个peerConnection来表示
type peerConnection struct {
	id string // Unique identifier of the peer

	rates   *msgrate.Tracker         // Tracker to hone in on the number of items retrievable per second
	lacking map[common.Hash]struct{} // Set of hashes not to request (didn't have previously)

	peer Peer

	// eth协议的版本
	version uint       // Eth protocol version number to switch strategies
	log     log.Logger // Contextual logger to add extra infos to peer logs
	lock    sync.RWMutex
}

// LightPeer encapsulates the methods required to synchronise with a remote light peer.
// 远程节点是light类型
type LightPeer interface {
	Head() (common.Hash, *big.Int)
	RequestHeadersByHash(common.Hash, int, int, bool, chan *eth.Response) (*eth.Request, error)
	RequestHeadersByNumber(uint64, int, int, bool, chan *eth.Response) (*eth.Request, error)
}

// Peer encapsulates the methods required to synchronise with a remote full peer.
// 远程节点是full类型
type Peer interface {
	LightPeer
	RequestBodies([]common.Hash, chan *eth.Response) (*eth.Request, error)
	RequestReceipts([]common.Hash, chan *eth.Response) (*eth.Request, error)
}

// lightPeerWrapper wraps a LightPeer struct, stubbing out the Peer-only methods.
// 实现了Peer接口,但是只有LightPeer的函数有意义,其他的会panic
// 可以包装一个LightPeer对象成为Peer对象
// 由于Downloader.RegisterPeer只接收Peer对象,所以在外部可以包装LightPeer对象成为lightPeerWrapper
type lightPeerWrapper struct {
	peer LightPeer
}

// 调用内部的LightPeer对应的函数
func (w *lightPeerWrapper) Head() (common.Hash, *big.Int) { return w.peer.Head() }
func (w *lightPeerWrapper) RequestHeadersByHash(h common.Hash, amount int, skip int, reverse bool, sink chan *eth.Response) (*eth.Request, error) {
	return w.peer.RequestHeadersByHash(h, amount, skip, reverse, sink)
}
func (w *lightPeerWrapper) RequestHeadersByNumber(i uint64, amount int, skip int, reverse bool, sink chan *eth.Response) (*eth.Request, error) {
	return w.peer.RequestHeadersByNumber(i, amount, skip, reverse, sink)
}
func (w *lightPeerWrapper) RequestBodies([]common.Hash, chan *eth.Response) (*eth.Request, error) {
	panic("RequestBodies not supported in light client mode sync")
}
func (w *lightPeerWrapper) RequestReceipts([]common.Hash, chan *eth.Response) (*eth.Request, error) {
	panic("RequestReceipts not supported in light client mode sync")
}

// newPeerConnection creates a new downloader peer.
// 指定连接id,版本,远程节点对象和日志对象 创建一个连接对象
func newPeerConnection(id string, version uint, peer Peer, logger log.Logger) *peerConnection {
	return &peerConnection{
		id:      id,
		lacking: make(map[common.Hash]struct{}),
		peer:    peer,
		version: version,
		log:     logger,
	}
}

// Reset clears the internal state of a peer entity.
// 把Idle系列和Throughput系列都置0
func (p *peerConnection) Reset() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.lacking = make(map[common.Hash]struct{})
}

// UpdateHeaderRate updates the peer's estimated header retrieval throughput with
// the current measurement.
func (p *peerConnection) UpdateHeaderRate(delivered int, elapsed time.Duration) {
	p.rates.Update(eth.BlockHeadersMsg, elapsed, delivered)
}

// UpdateBodyRate updates the peer's estimated body retrieval throughput with the
// current measurement.
func (p *peerConnection) UpdateBodyRate(delivered int, elapsed time.Duration) {
	p.rates.Update(eth.BlockBodiesMsg, elapsed, delivered)
}

// UpdateReceiptRate updates the peer's estimated receipt retrieval throughput
// with the current measurement.
func (p *peerConnection) UpdateReceiptRate(delivered int, elapsed time.Duration) {
	p.rates.Update(eth.ReceiptsMsg, elapsed, delivered)
}

// HeaderCapacity retrieves the peer's header download allowance based on its
// previously discovered throughput.
// 输入给定的RTT时间,计算应该获取多少条区块头数据
func (p *peerConnection) HeaderCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.BlockHeadersMsg, targetRTT)
	if cap > MaxHeaderFetch {
		cap = MaxHeaderFetch
	}
	return cap
}

// BodyCapacity retrieves the peer's body download allowance based on its
// previously discovered throughput.
func (p *peerConnection) BodyCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.BlockBodiesMsg, targetRTT)
	if cap > MaxBlockFetch {
		cap = MaxBlockFetch
	}
	return cap
}

// ReceiptCapacity retrieves the peers receipt download allowance based on its
// previously discovered throughput.
// 给定RTT时间能够获取多少条收据
func (p *peerConnection) ReceiptCapacity(targetRTT time.Duration) int {
	cap := p.rates.Capacity(eth.ReceiptsMsg, targetRTT)
	if cap > MaxReceiptFetch {
		cap = MaxReceiptFetch
	}
	return cap
}

// MarkLacking appends a new entity to the set of items (blocks, receipts, states)
// that a peer is known not to have (i.e. have been requested before). If the
// set reaches its maximum allowed capacity, items are randomly dropped off.
// 让p.lacking[hash]=struct{}{}
// 如果保存的p.lacking超过上限,就从中随机删除直到小于上限
func (p *peerConnection) MarkLacking(hash common.Hash) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for len(p.lacking) >= maxLackingHashes {
		for drop := range p.lacking {
			delete(p.lacking, drop)
			break
		}
	}
	// 清空指定的peer
	p.lacking[hash] = struct{}{}
}

// Lacks retrieves whether the hash of a blockchain item is on the peers lacking
// list (i.e. whether we know that the peer does not have it).
// 判断给定hash是不是存在于p.lacking
func (p *peerConnection) Lacks(hash common.Hash) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	_, ok := p.lacking[hash]
	return ok
}

// peeringEvent is sent on the peer event feed when a remote peer connects or
// disconnects.
type peeringEvent struct {
	peer *peerConnection
	join bool
}

// peerSet represents the collection of active peer participating in the chain
// download procedure.
type peerSet struct {
	peers  map[string]*peerConnection
	rates  *msgrate.Trackers // Set of rate trackers to give the sync a common beat
	events event.Feed        // Feed to publish peer lifecycle events on

	lock sync.RWMutex
}

// newPeerSet creates a new peer set top track the active download sources.
// 创建新的peerSet
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peerConnection),
		rates: msgrate.NewTrackers(log.New("proto", "eth")),
	}
}

// SubscribeEvents subscribes to peer arrival and departure events.
func (ps *peerSet) SubscribeEvents(ch chan<- *peeringEvent) event.Subscription {
	return ps.events.Subscribe(ch)
}

// Reset iterates over the current peer set, and resets each of the known peers
// to prepare for a next batch of block retrieval.
// 让每个peer调用Reset
func (ps *peerSet) Reset() {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	for _, peer := range ps.peers {
		peer.Reset()
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
//
// The method also sets the starting throughput values of the new peer to the
// average of all existing peers, to give it a realistic chance of being used
// for data retrievals.
// 向peerSet中添加一个peerConnection, 同一个peer重复调用会报错
// 就是将新的peerConnection加入到ps.peers中,并向newPeerFeed发送通知
func (ps *peerSet) Register(p *peerConnection) error {
	// Register the new peer with some meaningful defaults
	ps.lock.Lock()
	// 已经存在的peer再调用Register会报错
	if _, ok := ps.peers[p.id]; ok {
		ps.lock.Unlock()
		return errAlreadyRegistered
	}
	p.rates = msgrate.NewTracker(ps.rates.MeanCapacities(), ps.rates.MedianRoundTrip())
	if err := ps.rates.Track(p.id, p.rates); err != nil {
		return err
	}
	ps.peers[p.id] = p
	ps.lock.Unlock()

	ps.events.Send(&peeringEvent{peer: p, join: true})
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
// 根据peerConnection.id来删除, 不存在的peer调用也会报错
// 删除成功后向peerDropFeed发送通知
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	p, ok := ps.peers[id]
	if !ok {
		ps.lock.Unlock()
		return errNotRegistered
	}
	// 直接删除即可
	delete(ps.peers, id)
	ps.rates.Untrack(id)
	ps.lock.Unlock()

	ps.events.Send(&peeringEvent{peer: p, join: false})
	return nil
}

// Peer retrieves the registered peer with the given id.
// 根据id从peerSet中获取peerConnection
func (ps *peerSet) Peer(id string) *peerConnection {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
// 获取peerSet的长度
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// AllPeers retrieves a flat list of all the peers within the set.
// 获取peerSet中的所有peerConnection对象
// 保存在peerSet中是以键值对的形式,转化成数组形式返回
func (ps *peerSet) AllPeers() []*peerConnection {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peerConnection, 0, len(ps.peers))
	for _, p := range ps.peers {
		list = append(list, p)
	}
	return list
}

// peerCapacitySort implements sort.Interface.
// It sorts peer connections by capacity (descending).
type peerCapacitySort struct {
	p  []*peerConnection
	tp []int
}

func (ps *peerCapacitySort) Len() int {
	return len(ps.p)
}

// 这里tp[i]>tp[j]才返回true
// 说明是要进行根据tp的值降序排列
func (ps *peerCapacitySort) Less(i, j int) bool {
	return ps.tp[i] > ps.tp[j]
}

func (ps *peerCapacitySort) Swap(i, j int) {
	ps.p[i], ps.p[j] = ps.p[j], ps.p[i]
	ps.tp[i], ps.tp[j] = ps.tp[j], ps.tp[i]
}
