// Copyright 2017 The go-ethereum Authors
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

package simulations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/simulations/adapters"
)

var DialBanTimeout = 200 * time.Millisecond

// NetworkConfig defines configuration options for starting a Network
// NetworkConfig指定了启动一个仿真网络需要配置
// 包括这个网络的ID,以及网络中的节点使用的默认服务
type NetworkConfig struct {
	ID             string `json:"id"`
	DefaultService string `json:"default_service,omitempty"`
}

// Network models a p2p simulation network which consists of a collection of
// simulated nodes and the connections which exist between them.
//
// The Network has a single NodeAdapter which is responsible for actually
// starting nodes and connecting them together.
//
// The Network emits events when nodes are started and stopped, when they are
// connected and disconnected, and also when messages are sent between nodes.
// Network对象代表一个仿真网络,包括了一组仿真节点和这些节点间建立的连接
type Network struct {
	NetworkConfig

	// 保存网络中的所有节点
	Nodes []*Node `json:"nodes"`
	// 用来通过节点id获取Node对象
	nodeMap map[enode.ID]int

	// Maps a node property string to node indexes of all nodes that hold this property
	// key是属性的名称,value是所有需要持有这个属性的节点在Nodes数组的下标
	propertyMap map[string][]int

	// 保存网络中所有连接
	Conns []*Conn `json:"conns"`
	// 用来通过连接的唯一字符串获取Conn对象
	connMap map[string]int

	nodeAdapter adapters.NodeAdapter
	// 当节点启动,停止,建立连接,断开连接,发送消息,接收消息都会触发事件
	events event.Feed
	lock   sync.RWMutex
	quitc  chan struct{}
}

// NewNetwork returns a Network which uses the given NodeAdapter and NetworkConfig
// 新建一个仿真网络需要NodeAdapter和NetworkConfig
// NodeAdapter用来指定如何在网络中创建节点,NetworkConfig指定了该仿真网络的一些配置
func NewNetwork(nodeAdapter adapters.NodeAdapter, conf *NetworkConfig) *Network {
	return &Network{
		NetworkConfig: *conf,
		nodeAdapter:   nodeAdapter,
		nodeMap:       make(map[enode.ID]int),
		propertyMap:   make(map[string][]int),
		connMap:       make(map[string]int),
		quitc:         make(chan struct{}),
	}
}

// Events returns the output event feed of the Network.
// 外部通过这个方法订阅网络中发生的事件
func (net *Network) Events() *event.Feed {
	return &net.events
}

// NewNodeWithConfig adds a new node to the network with the given config,
// returning an error if a node with the same ID or name already exists
// 指定节点的配置信息,在仿真网络中创建一个新的节点
func (net *Network) NewNodeWithConfig(conf *adapters.NodeConfig) (*Node, error) {
	net.lock.Lock()
	defer net.lock.Unlock()

	// 设置默认的Reachable函数
	if conf.Reachable == nil {
		conf.Reachable = func(otherID enode.ID) bool {
			_, err := net.InitConn(conf.ID, otherID)
			if err != nil && bytes.Compare(conf.ID.Bytes(), otherID.Bytes()) < 0 {
				return false
			}
			return true
		}
	}

	// check the node doesn't already exist
	// 判断节点是否已经存在于网络中,先根据ID查,再根据Name查
	// 如果节点已经存在,将返回错误
	if node := net.getNode(conf.ID); node != nil {
		return nil, fmt.Errorf("node with ID %q already exists", conf.ID)
	}
	if node := net.getNodeByName(conf.Name); node != nil {
		return nil, fmt.Errorf("node with name %q already exists", conf.Name)
	}

	// if no services are configured, use the default service
	// 如果一个服务也没有,就使用默认的服务
	if len(conf.Lifecycles) == 0 {
		conf.Lifecycles = []string{net.DefaultService}
	}

	// use the NodeAdapter to create the node
	// 通过NodeAdapter创建一个adapters.Node对象
	adapterNode, err := net.nodeAdapter.NewNode(conf)
	if err != nil {
		return nil, err
	}
	// 将adapters.Node对象封装成simulations.Node对象
	node := newNode(adapterNode, conf, false)
	log.Trace("Node created", "id", conf.ID)

	// 将这个新建的Node对象保存到Network对象中
	nodeIndex := len(net.Nodes)
	net.nodeMap[conf.ID] = nodeIndex
	net.Nodes = append(net.Nodes, node)

	// Register any node properties with the network-level propertyMap
	// 让这个节点使用的所有属性记录下来这个节点的下标
	for _, property := range conf.Properties {
		net.propertyMap[property] = append(net.propertyMap[property], nodeIndex)
	}

	// emit a "control" event
	net.events.Send(ControlEvent(node))

	return node, nil
}

// Config returns the network configuration
// 获取网络的配置信息
func (net *Network) Config() *NetworkConfig {
	return &net.NetworkConfig
}

// StartAll starts all nodes in the network
// 启动网络中的所有节点
func (net *Network) StartAll() error {
	for _, node := range net.Nodes {
		// 已经启动的跳过
		if node.Up() {
			continue
		}
		// 没启动的节点执行Start启动
		if err := net.Start(node.ID()); err != nil {
			return err
		}
	}
	return nil
}

// StopAll stops all nodes in the network
// 停止网络中的所有节点
func (net *Network) StopAll() error {
	for _, node := range net.Nodes {
		if !node.Up() {
			continue
		}
		if err := net.Stop(node.ID()); err != nil {
			return err
		}
	}
	return nil
}

// Start starts the node with the given ID
// 启动网络中指定id的节点
// 执行节点的Start方法,并设置节点的Up为true
// 最后监听针对这个节点的rpc事件,例如增加或减少对等节点,发送或接收到消息
func (net *Network) Start(id enode.ID) error {
	return net.startWithSnapshots(id, nil)
}

// startWithSnapshots starts the node with the given ID using the give
// snapshots
func (net *Network) startWithSnapshots(id enode.ID, snapshots map[string][]byte) error {
	net.lock.Lock()
	defer net.lock.Unlock()

	// 先找到指定的节点
	// 然后调用node.Start(snapshots)
	// 然后设置节点的Up为true
	node := net.getNode(id)
	if node == nil {
		return fmt.Errorf("node %v does not exist", id)
	}
	if node.Up() {
		return fmt.Errorf("node %v already up", id)
	}
	log.Trace("Starting node", "id", id, "adapter", net.nodeAdapter.Name())
	if err := node.Start(snapshots); err != nil {
		log.Warn("Node startup failed", "id", id, "err", err)
		return err
	}
	node.SetUp(true)
	log.Info("Started node", "id", id)
	// 发送新建节点的事件
	ev := NewEvent(node)
	net.events.Send(ev)

	// subscribe to peer events
	client, err := node.Client()
	if err != nil {
		return fmt.Errorf("error getting rpc client  for node %v: %s", id, err)
	}
	events := make(chan *p2p.PeerEvent)
	// 订阅了privateAdminAPI.PeerEvents方法
	// node.Node订阅了内部p2p.Server发送的事件然后转发到这里
	sub, err := client.Subscribe(context.Background(), "admin", events, "peerEvents")
	if err != nil {
		return fmt.Errorf("error getting peer events for node %v: %s", id, err)
	}
	go net.watchPeerEvents(id, events, sub)
	return nil
}

// watchPeerEvents reads peer events from the given channel and emits
// corresponding network events
// 监听来自节点内部p2p.Server发送的事件,然后转换成simulations.Event
func (net *Network) watchPeerEvents(id enode.ID, events chan *p2p.PeerEvent, sub event.Subscription) {
	defer func() {
		// 结束的时候取消订阅
		sub.Unsubscribe()

		// assume the node is now down
		// 这个函数停止了,假设节点已经停止运行了
		net.lock.Lock()
		defer net.lock.Unlock()

		node := net.getNode(id)
		if node == nil {
			return
		}
		node.SetUp(false)
		ev := NewEvent(node)
		net.events.Send(ev)
	}()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return
			}
			peer := event.Peer
			switch event.Type {

			case p2p.PeerEventTypeAdd:
				net.DidConnect(id, peer)

			case p2p.PeerEventTypeDrop:
				net.DidDisconnect(id, peer)

			case p2p.PeerEventTypeMsgSend:
				net.DidSend(id, peer, event.Protocol, *event.MsgCode)

			case p2p.PeerEventTypeMsgRecv:
				net.DidReceive(peer, id, event.Protocol, *event.MsgCode)

			}

		case err := <-sub.Err():
			if err != nil {
				log.Error("Error in peer event subscription", "id", id, "err", err)
			}
			return
		}
	}
}

// Stop stops the node with the given ID
// 停止仿真网络中的某个节点,其实就是调用节点的Stop方法
func (net *Network) Stop(id enode.ID) error {
	// IMPORTANT: node.Stop() must NOT be called under net.lock as
	// node.Reachable() closure has a reference to the network and
	// calls net.InitConn() what also locks the network. => DEADLOCK
	// That holds until the following ticket is not resolved:

	var err error

	node, err := func() (*Node, error) {
		net.lock.Lock()
		defer net.lock.Unlock()

		node := net.getNode(id)
		if node == nil {
			return nil, fmt.Errorf("node %v does not exist", id)
		}
		if !node.Up() {
			return nil, fmt.Errorf("node %v already down", id)
		}
		node.SetUp(false)
		return node, nil
	}()
	if err != nil {
		return err
	}

	err = node.Stop() // must be called without net.lock

	net.lock.Lock()
	defer net.lock.Unlock()

	// 停止失败,重新设置Up为true
	if err != nil {
		node.SetUp(true)
		return err
	}
	log.Info("Stopped node", "id", id, "err", err)
	ev := ControlEvent(node)
	net.events.Send(ev)
	return nil
}

// Connect connects two nodes together by calling the "admin_addPeer" RPC
// method on the "one" node so that it connects to the "other" node
// 建立两个节点间的连接,通过调用admin_addPerr这个RPC方法
func (net *Network) Connect(oneID, otherID enode.ID) error {
	net.lock.Lock()
	defer net.lock.Unlock()
	return net.connect(oneID, otherID)
}

func (net *Network) connect(oneID, otherID enode.ID) error {
	log.Debug("Connecting nodes with addPeer", "id", oneID, "other", otherID)
	// 创建Conn对象
	conn, err := net.initConn(oneID, otherID)
	if err != nil {
		return err
	}
	client, err := conn.one.Client()
	if err != nil {
		return err
	}
	net.events.Send(ControlEvent(conn))
	// 使用节点的rpc客户端对象调用admin_addPeer方法
	return client.Call(nil, "admin_addPeer", string(conn.other.Addr()))
}

// Disconnect disconnects two nodes by calling the "admin_removePeer" RPC
// method on the "one" node so that it disconnects from the "other" node
// 断开两个节点间的连接,调用了admin_removePeer这个RPC方法
func (net *Network) Disconnect(oneID, otherID enode.ID) error {
	// 获取连接对象
	conn := net.GetConn(oneID, otherID)
	// 根本没建立连接或者连接没启动都返回错误
	if conn == nil {
		return fmt.Errorf("connection between %v and %v does not exist", oneID, otherID)
	}
	if !conn.Up {
		return fmt.Errorf("%v and %v already disconnected", oneID, otherID)
	}
	client, err := conn.one.Client()
	if err != nil {
		return err
	}
	net.events.Send(ControlEvent(conn))
	// 调用RPC方法admin_removePeer
	return client.Call(nil, "admin_removePeer", string(conn.other.Addr()))
}

// DidConnect tracks the fact that the "one" node connected to the "other" node
func (net *Network) DidConnect(one, other enode.ID) error {
	net.lock.Lock()
	defer net.lock.Unlock()
	conn, err := net.getOrCreateConn(one, other)
	if err != nil {
		return fmt.Errorf("connection between %v and %v does not exist", one, other)
	}
	if conn.Up {
		return fmt.Errorf("%v and %v already connected", one, other)
	}
	conn.Up = true
	net.events.Send(NewEvent(conn))
	return nil
}

// DidDisconnect tracks the fact that the "one" node disconnected from the
// "other" node
func (net *Network) DidDisconnect(one, other enode.ID) error {
	net.lock.Lock()
	defer net.lock.Unlock()
	conn := net.getConn(one, other)
	if conn == nil {
		return fmt.Errorf("connection between %v and %v does not exist", one, other)
	}
	if !conn.Up {
		return fmt.Errorf("%v and %v already disconnected", one, other)
	}
	conn.Up = false
	conn.initiated = time.Now().Add(-DialBanTimeout)
	net.events.Send(NewEvent(conn))
	return nil
}

// DidSend tracks the fact that "sender" sent a message to "receiver"
func (net *Network) DidSend(sender, receiver enode.ID, proto string, code uint64) error {
	msg := &Msg{
		One:      sender,
		Other:    receiver,
		Protocol: proto,
		Code:     code,
		Received: false,
	}
	net.events.Send(NewEvent(msg))
	return nil
}

// DidReceive tracks the fact that "receiver" received a message from "sender"
func (net *Network) DidReceive(sender, receiver enode.ID, proto string, code uint64) error {
	msg := &Msg{
		One:      sender,
		Other:    receiver,
		Protocol: proto,
		Code:     code,
		Received: true,
	}
	net.events.Send(NewEvent(msg))
	return nil
}

// GetNode gets the node with the given ID, returning nil if the node does not
// exist
func (net *Network) GetNode(id enode.ID) *Node {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getNode(id)
}

// 通过节点ID获得网络中的Node对象
func (net *Network) getNode(id enode.ID) *Node {
	i, found := net.nodeMap[id]
	if !found {
		return nil
	}
	return net.Nodes[i]
}

// GetNodeByName gets the node with the given name, returning nil if the node does
// not exist
// 通过节点的名称查询Node对象,如果节点不存在返回nil
func (net *Network) GetNodeByName(name string) *Node {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getNodeByName(name)
}

// 查询名称与输入的匹配的Node对象
func (net *Network) getNodeByName(name string) *Node {
	for _, node := range net.Nodes {
		if node.Config.Name == name {
			return node
		}
	}
	return nil
}

// GetNodeIDs returns the IDs of all existing nodes
// Nodes can optionally be excluded by specifying their enode.ID.
func (net *Network) GetNodeIDs(excludeIDs ...enode.ID) []enode.ID {
	net.lock.RLock()
	defer net.lock.RUnlock()

	return net.getNodeIDs(excludeIDs)
}

func (net *Network) getNodeIDs(excludeIDs []enode.ID) []enode.ID {
	// Get all current nodeIDs
	nodeIDs := make([]enode.ID, 0, len(net.nodeMap))
	for id := range net.nodeMap {
		nodeIDs = append(nodeIDs, id)
	}

	if len(excludeIDs) > 0 {
		// Return the difference of nodeIDs and excludeIDs
		return filterIDs(nodeIDs, excludeIDs)
	}
	return nodeIDs
}

// GetNodes returns the existing nodes.
// Nodes can optionally be excluded by specifying their enode.ID.
func (net *Network) GetNodes(excludeIDs ...enode.ID) []*Node {
	net.lock.RLock()
	defer net.lock.RUnlock()

	return net.getNodes(excludeIDs)
}

func (net *Network) getNodes(excludeIDs []enode.ID) []*Node {
	if len(excludeIDs) > 0 {
		nodeIDs := net.getNodeIDs(excludeIDs)
		return net.getNodesByID(nodeIDs)
	}
	return net.Nodes
}

// GetNodesByID returns existing nodes with the given enode.IDs.
// If a node doesn't exist with a given enode.ID, it is ignored.
func (net *Network) GetNodesByID(nodeIDs []enode.ID) []*Node {
	net.lock.RLock()
	defer net.lock.RUnlock()

	return net.getNodesByID(nodeIDs)
}

func (net *Network) getNodesByID(nodeIDs []enode.ID) []*Node {
	nodes := make([]*Node, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		node := net.getNode(id)
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

// GetNodesByProperty returns existing nodes that have the given property string registered in their NodeConfig
func (net *Network) GetNodesByProperty(property string) []*Node {
	net.lock.RLock()
	defer net.lock.RUnlock()

	return net.getNodesByProperty(property)
}

func (net *Network) getNodesByProperty(property string) []*Node {
	nodes := make([]*Node, 0, len(net.propertyMap[property]))
	for _, nodeIndex := range net.propertyMap[property] {
		nodes = append(nodes, net.Nodes[nodeIndex])
	}

	return nodes
}

// GetNodeIDsByProperty returns existing node's enode IDs that have the given property string registered in the NodeConfig
func (net *Network) GetNodeIDsByProperty(property string) []enode.ID {
	net.lock.RLock()
	defer net.lock.RUnlock()

	return net.getNodeIDsByProperty(property)
}

func (net *Network) getNodeIDsByProperty(property string) []enode.ID {
	nodeIDs := make([]enode.ID, 0, len(net.propertyMap[property]))
	for _, nodeIndex := range net.propertyMap[property] {
		node := net.Nodes[nodeIndex]
		nodeIDs = append(nodeIDs, node.ID())
	}

	return nodeIDs
}

// GetRandomUpNode returns a random node on the network, which is running.
func (net *Network) GetRandomUpNode(excludeIDs ...enode.ID) *Node {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getRandomUpNode(excludeIDs...)
}

// GetRandomUpNode returns a random node on the network, which is running.
func (net *Network) getRandomUpNode(excludeIDs ...enode.ID) *Node {
	return net.getRandomNode(net.getUpNodeIDs(), excludeIDs)
}

func (net *Network) getUpNodeIDs() (ids []enode.ID) {
	for _, node := range net.Nodes {
		if node.Up() {
			ids = append(ids, node.ID())
		}
	}
	return ids
}

// GetRandomDownNode returns a random node on the network, which is stopped.
func (net *Network) GetRandomDownNode(excludeIDs ...enode.ID) *Node {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getRandomNode(net.getDownNodeIDs(), excludeIDs)
}

func (net *Network) getDownNodeIDs() (ids []enode.ID) {
	for _, node := range net.Nodes {
		if !node.Up() {
			ids = append(ids, node.ID())
		}
	}
	return ids
}

// GetRandomNode returns a random node on the network, regardless of whether it is running or not
func (net *Network) GetRandomNode(excludeIDs ...enode.ID) *Node {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getRandomNode(net.getNodeIDs(nil), excludeIDs) // no need to exclude twice
}

func (net *Network) getRandomNode(ids []enode.ID, excludeIDs []enode.ID) *Node {
	filtered := filterIDs(ids, excludeIDs)

	l := len(filtered)
	if l == 0 {
		return nil
	}
	return net.getNode(filtered[rand.Intn(l)])
}

func filterIDs(ids []enode.ID, excludeIDs []enode.ID) []enode.ID {
	exclude := make(map[enode.ID]bool)
	for _, id := range excludeIDs {
		exclude[id] = true
	}
	var filtered []enode.ID
	for _, id := range ids {
		if _, found := exclude[id]; !found {
			filtered = append(filtered, id)
		}
	}
	return filtered
}

// GetConn returns the connection which exists between "one" and "other"
// regardless of which node initiated the connection
// 获取仿真网络中两个节点之间的连接对象,没建立连接返回nil
func (net *Network) GetConn(oneID, otherID enode.ID) *Conn {
	net.lock.RLock()
	defer net.lock.RUnlock()
	return net.getConn(oneID, otherID)
}

// GetOrCreateConn is like GetConn but creates the connection if it doesn't
// already exist
// 获取仿真网络中两个节点之间的连接对象,没建立连接新创建一个连接返回
func (net *Network) GetOrCreateConn(oneID, otherID enode.ID) (*Conn, error) {
	net.lock.Lock()
	defer net.lock.Unlock()
	return net.getOrCreateConn(oneID, otherID)
}

// 获取两个节点的连接对象
// 首先判断之前是否已经建立了连接,如果没有建立连接创建一个返回
func (net *Network) getOrCreateConn(oneID, otherID enode.ID) (*Conn, error) {
	// 首先尝试获取已经建立的连接对象
	if conn := net.getConn(oneID, otherID); conn != nil {
		return conn, nil
	}
	// 没有建立连接,那么就先确保这两个节点都存在于网络中
	one := net.getNode(oneID)
	if one == nil {
		return nil, fmt.Errorf("node %v does not exist", oneID)
	}
	other := net.getNode(otherID)
	if other == nil {
		return nil, fmt.Errorf("node %v does not exist", otherID)
	}
	// 构造这两个节点的连接对象
	conn := &Conn{
		One:   oneID,
		Other: otherID,
		one:   one,
		other: other,
	}
	// 将新连接保存到Network对象中
	// 要维护net.connMap和net.Conns两个字段
	label := ConnLabel(oneID, otherID)
	net.connMap[label] = len(net.Conns)
	net.Conns = append(net.Conns, conn)
	return conn, nil
}

// 找到两个节点已经建立的Conn对象,如果没有建立连接返回nil
func (net *Network) getConn(oneID, otherID enode.ID) *Conn {
	label := ConnLabel(oneID, otherID)
	i, found := net.connMap[label]
	if !found {
		return nil
	}
	return net.Conns[i]
}

// InitConn(one, other) retrieves the connection model for the connection between
// peers one and other, or creates a new one if it does not exist
// the order of nodes does not matter, i.e., Conn(i,j) == Conn(j, i)
// it checks if the connection is already up, and if the nodes are running
// NOTE:
// it also checks whether there has been recent attempt to connect the peers
// this is cheating as the simulation is used as an oracle and know about
// remote peers attempt to connect to a node which will then not initiate the connection
// 初始化一个连接
// 调用时两个节点间要么没建立连接,要么连接还没启动
// 而且这两个节点必须是启动状态的
func (net *Network) InitConn(oneID, otherID enode.ID) (*Conn, error) {
	net.lock.Lock()
	defer net.lock.Unlock()
	return net.initConn(oneID, otherID)
}

// 初始化一个连接
// 调用时两个节点间要么没建立连接,要么连接还没启动
// 而且这两个节点必须是启动状态的
func (net *Network) initConn(oneID, otherID enode.ID) (*Conn, error) {
	if oneID == otherID {
		return nil, fmt.Errorf("refusing to connect to self %v", oneID)
	}
	conn, err := net.getOrCreateConn(oneID, otherID)
	if err != nil {
		return nil, err
	}
	if conn.Up {
		return nil, fmt.Errorf("%v and %v already connected", oneID, otherID)
	}
	if time.Since(conn.initiated) < DialBanTimeout {
		return nil, fmt.Errorf("connection between %v and %v recently attempted", oneID, otherID)
	}

	err = conn.nodesUp()
	if err != nil {
		log.Trace("Nodes not up", "err", err)
		return nil, fmt.Errorf("nodes not up: %v", err)
	}
	log.Debug("Connection initiated", "id", oneID, "other", otherID)
	conn.initiated = time.Now()
	return conn, nil
}

// Shutdown stops all nodes in the network and closes the quit channel
// 用来停止整个仿真网络
// 调用所有Node对象的Stop方法,如果实现了Close方法的话也调用Close
// 关闭所有节点后再关闭net.quitc管道
func (net *Network) Shutdown() {
	for _, node := range net.Nodes {
		log.Debug("Stopping node", "id", node.ID())
		if err := node.Stop(); err != nil {
			log.Warn("Can't stop node", "id", node.ID(), "err", err)
		}
	}
	close(net.quitc)
}

// Reset resets all network properties:
// empties the nodes and the connection list
// 重置整个网络,清空建立的节点和连接
func (net *Network) Reset() {
	net.lock.Lock()
	defer net.lock.Unlock()
	//re-initialize the maps
	net.connMap = make(map[string]int)
	net.nodeMap = make(map[enode.ID]int)
	net.propertyMap = make(map[string][]int)

	net.Nodes = nil
	net.Conns = nil
}

// Node is a wrapper around adapters.Node which is used to track the status
// of a node in the network
// 这里的Node是对adapters.Node一层封装,用来追踪节点在仿真网络中的状态
// 它也实现了adapters.Node接口
type Node struct {
	adapters.Node `json:"-"`

	// Config if the config used to created the node
	// 创建adapters.Node的时候使用的配置
	Config *adapters.NodeConfig `json:"config"`

	// up tracks whether or not the node is running
	// 标记节点是否正在运行
	up   bool
	upMu *sync.RWMutex
}

// 创建一个Node对象,需要指定封装的adapters.Node以及它使用的配置,还有设置新建的节点是否在运行
func newNode(an adapters.Node, ac *adapters.NodeConfig, up bool) *Node {
	return &Node{Node: an, Config: ac, up: up, upMu: new(sync.RWMutex)}
}

// 复制当前的节点对象
func (n *Node) copy() *Node {
	// 复制其实是将NodeConfig对象复制了一份
	configCpy := *n.Config
	return newNode(n.Node, &configCpy, n.Up())
}

// Up returns whether the node is currently up (online)
// 得知当前节点是否正在运行
func (n *Node) Up() bool {
	n.upMu.RLock()
	defer n.upMu.RUnlock()
	return n.up
}

// SetUp sets the up (online) status of the nodes with the given value
// 设置up为输入的值
func (n *Node) SetUp(up bool) {
	n.upMu.Lock()
	defer n.upMu.Unlock()
	n.up = up
}

// ID returns the ID of the node
func (n *Node) ID() enode.ID {
	return n.Config.ID
}

// String returns a log-friendly string
func (n *Node) String() string {
	return fmt.Sprintf("Node %v", n.ID().TerminalString())
}

// NodeInfo returns information about the node
// 获取NodeInfo
func (n *Node) NodeInfo() *p2p.NodeInfo {
	// avoid a panic if the node is not started yet
	if n.Node == nil {
		return nil
	}
	info := n.Node.NodeInfo()
	// n.Config.Name可能被修改过,以这个为准
	info.Name = n.Config.Name
	return info
}

// MarshalJSON implements the json.Marshaler interface so that the encoded
// JSON includes the NodeInfo
func (n *Node) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Info   *p2p.NodeInfo        `json:"info,omitempty"`
		Config *adapters.NodeConfig `json:"config,omitempty"`
		Up     bool                 `json:"up"`
	}{
		Info:   n.NodeInfo(),
		Config: n.Config,
		Up:     n.Up(),
	})
}

// UnmarshalJSON implements json.Unmarshaler interface so that we don't lose Node.up
// status. IMPORTANT: The implementation is incomplete; we lose p2p.NodeInfo.
func (n *Node) UnmarshalJSON(raw []byte) error {
	// TODO: How should we turn back NodeInfo into n.Node?
	// Ticket: https://github.com/ethersphere/go-ethereum/issues/1177
	var node struct {
		Config *adapters.NodeConfig `json:"config,omitempty"`
		Up     bool                 `json:"up"`
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		return err
	}
	*n = *newNode(nil, node.Config, node.Up)
	return nil
}

// Conn represents a connection between two nodes in the network
// 仿真网络中的一个连接
type Conn struct {
	// One is the node which initiated the connection
	// 连接的发起方的节点id
	One enode.ID `json:"one"`

	// Other is the node which the connection was made to
	// 连接的接收方的节点id
	Other enode.ID `json:"other"`

	// Up tracks whether or not the connection is active
	// 连接的状态
	Up bool `json:"up"`
	// Registers when the connection was grabbed to dial
	// 这个时间在InitConn中设置
	initiated time.Time

	one   *Node
	other *Node
}

// nodesUp returns whether both nodes are currently up
// 连接对象用于判断这个连接的双方节点是否启动
func (c *Conn) nodesUp() error {
	if !c.one.Up() {
		return fmt.Errorf("one %v is not up", c.One)
	}
	if !c.other.Up() {
		return fmt.Errorf("other %v is not up", c.Other)
	}
	return nil
}

// String returns a log-friendly string
func (c *Conn) String() string {
	return fmt.Sprintf("Conn %v->%v", c.One.TerminalString(), c.Other.TerminalString())
}

// Msg represents a p2p message sent between two nodes in the network
// 代表仿真网络中发送的消息
type Msg struct {
	One      enode.ID `json:"one"`
	Other    enode.ID `json:"other"`
	Protocol string   `json:"protocol"`
	Code     uint64   `json:"code"`
	Received bool     `json:"received"`
}

// String returns a log-friendly string
func (m *Msg) String() string {
	return fmt.Sprintf("Msg(%d) %v->%v", m.Code, m.One.TerminalString(), m.Other.TerminalString())
}

// ConnLabel generates a deterministic string which represents a connection
// between two nodes, used to compare if two connections are between the same
// nodes
// 输入两个相同的节点id将生成相同的字符串,输入中不区分两者的顺序
// 该方法用于判断两个连接对象是不是建立在两个相同的节点
func ConnLabel(source, target enode.ID) string {
	var first, second enode.ID
	// 比较一下两个节点id的大小,将小的放在前面
	if bytes.Compare(source.Bytes(), target.Bytes()) > 0 {
		first = target
		second = source
	} else {
		first = source
		second = target
	}
	return fmt.Sprintf("%v-%v", first, second)
}

// Snapshot represents the state of a network at a single point in time and can
// be used to restore the state of a network
// Snapshot对象用于保存仿真网络在某个时刻的状态,可以用来恢复整个网络
type Snapshot struct {
	Nodes []NodeSnapshot `json:"nodes,omitempty"`
	Conns []Conn         `json:"conns,omitempty"`
}

// NodeSnapshot represents the state of a node in the network
// 用于保存一个节点的快照
type NodeSnapshot struct {
	Node Node `json:"node,omitempty"`

	// Snapshots is arbitrary data gathered from calling node.Snapshots()
	Snapshots map[string][]byte `json:"snapshots,omitempty"`
}

// Snapshot creates a network snapshot
// 创建网络快照
func (net *Network) Snapshot() (*Snapshot, error) {
	return net.snapshot(nil, nil)
}

// 创建网络快照,可以让快照中所有的启动的节点都有或者没有指定的服务
func (net *Network) SnapshotWithServices(addServices []string, removeServices []string) (*Snapshot, error) {
	return net.snapshot(addServices, removeServices)
}

// 生成仿真网络的快照
// 生成快照包括两个主要过程,节点快照和连接快照
// 快照中的所有启动的节点都有addServices中的服务,没有removeServices中的服务
func (net *Network) snapshot(addServices []string, removeServices []string) (*Snapshot, error) {
	net.lock.Lock()
	defer net.lock.Unlock()
	snap := &Snapshot{
		// 快照中需要保存所有的节点,不论节点是否启动,所以这里直接分配好空间
		Nodes: make([]NodeSnapshot, len(net.Nodes)),
		// 这里没有初始化Conns,因为快照中只保存Up状态的连接,现在还不知道有多少Up状态的连接
	}
	// 保存网络的快照包括两个部分,节点的快照和连接的快照

	// 这个循环用来保存节点的快照
	// 保存节点的快照又分为三个部分,后两步是针对运行中的节点
	//   保存Node对象
	//   调用Node对象的Snapshots方法,保存结果
	//   根据输入的addServices和removeServices处理Node对象应该具有的服务
	for i, node := range net.Nodes {
		snap.Nodes[i] = NodeSnapshot{Node: *node.copy()}
		// 没启动的节点只保存它的Node对象就行了
		// 启动的节点需要得到它的快照
		if !node.Up() {
			continue
		}
		snapshots, err := node.Snapshots()
		if err != nil {
			return nil, err
		}
		snap.Nodes[i].Snapshots = snapshots
		// 接下来处理节点的服务
		// 将addServices中的服务添加到节点的服务中
		for _, addSvc := range addServices {
			haveSvc := false
			for _, svc := range snap.Nodes[i].Node.Config.Lifecycles {
				if svc == addSvc {
					haveSvc = true
					break
				}
			}
			if !haveSvc {
				snap.Nodes[i].Node.Config.Lifecycles = append(snap.Nodes[i].Node.Config.Lifecycles, addSvc)
			}
		}
		// 从节点的服务中移除removeServices中有的
		if len(removeServices) > 0 {
			var cleanedServices []string
			for _, svc := range snap.Nodes[i].Node.Config.Lifecycles {
				haveSvc := false
				for _, rmSvc := range removeServices {
					if rmSvc == svc {
						haveSvc = true
						break
					}
				}
				if !haveSvc {
					cleanedServices = append(cleanedServices, svc)
				}

			}
			snap.Nodes[i].Node.Config.Lifecycles = cleanedServices
		}
	}
	// 这个循环用来保存连接的快照
	// 快照中只保存当前网络中Up的连接
	for _, conn := range net.Conns {
		if conn.Up {
			snap.Conns = append(snap.Conns, *conn)
		}
	}
	return snap, nil
}

// longrunning tests may need a longer timeout
var snapshotLoadTimeout = 900 * time.Second

// Load loads a network snapshot
// 从快照中恢复一个仿真网络
func (net *Network) Load(snap *Snapshot) error {
	// Start nodes.
	for _, n := range snap.Nodes {
		if _, err := net.NewNodeWithConfig(n.Node.Config); err != nil {
			return err
		}
		if !n.Node.Up() {
			continue
		}
		if err := net.startWithSnapshots(n.Node.Config.ID, n.Snapshots); err != nil {
			return err
		}
	}

	// Prepare connection events counter.
	allConnected := make(chan struct{}) // closed when all connections are established
	done := make(chan struct{})         // ensures that the event loop goroutine is terminated
	defer close(done)

	// Subscribe to event channel.
	// It needs to be done outside of the event loop goroutine (created below)
	// to ensure that the event channel is blocking before connect calls are made.
	events := make(chan *Event)
	sub := net.Events().Subscribe(events)
	defer sub.Unsubscribe()

	go func() {
		// Expected number of connections.
		total := len(snap.Conns)
		// Set of all established connections from the snapshot, not other connections.
		// Key array element 0 is the connection One field value, and element 1 connection Other field.
		connections := make(map[[2]enode.ID]struct{}, total)

		for {
			select {
			case e := <-events:
				// Ignore control events as they do not represent
				// connect or disconnect (Up) state change.
				if e.Control {
					continue
				}
				// Detect only connection events.
				if e.Type != EventTypeConn {
					continue
				}
				connection := [2]enode.ID{e.Conn.One, e.Conn.Other}
				// Nodes are still not connected or have been disconnected.
				if !e.Conn.Up {
					// Delete the connection from the set of established connections.
					// This will prevent false positive in case disconnections happen.
					delete(connections, connection)
					log.Warn("load snapshot: unexpected disconnection", "one", e.Conn.One, "other", e.Conn.Other)
					continue
				}
				// Check that the connection is from the snapshot.
				for _, conn := range snap.Conns {
					if conn.One == e.Conn.One && conn.Other == e.Conn.Other {
						// Add the connection to the set of established connections.
						connections[connection] = struct{}{}
						if len(connections) == total {
							// Signal that all nodes are connected.
							close(allConnected)
							return
						}

						break
					}
				}
			case <-done:
				// Load function returned, terminate this goroutine.
				return
			}
		}
	}()

	// Start connecting.
	for _, conn := range snap.Conns {

		if !net.GetNode(conn.One).Up() || !net.GetNode(conn.Other).Up() {
			//in this case, at least one of the nodes of a connection is not up,
			//so it would result in the snapshot `Load` to fail
			continue
		}
		if err := net.Connect(conn.One, conn.Other); err != nil {
			return err
		}
	}

	select {
	// Wait until all connections from the snapshot are established.
	case <-allConnected:
	// Make sure that we do not wait forever.
	case <-time.After(snapshotLoadTimeout):
		return errors.New("snapshot connections not established")
	}
	return nil
}

// Subscribe reads control events from a channel and executes them
// 从输入的events管道中接收到Control类型的事件,然后执行这些事件
func (net *Network) Subscribe(events chan *Event) {
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return
			}
			if event.Control {
				net.executeControlEvent(event)
			}
		case <-net.quitc:
			return
		}
	}
}

// 执行三种不同类型的控制事件
// Msg类型的控制事件会被忽略
func (net *Network) executeControlEvent(event *Event) {
	log.Trace("Executing control event", "type", event.Type, "event", event)
	switch event.Type {
	case EventTypeNode:
		if err := net.executeNodeEvent(event); err != nil {
			log.Error("Error executing node event", "event", event, "err", err)
		}
	case EventTypeConn:
		if err := net.executeConnEvent(event); err != nil {
			log.Error("Error executing conn event", "event", event, "err", err)
		}
	case EventTypeMsg:
		log.Warn("Ignoring control msg event")
	}
}

// node类型事件代表启动和停止节点,执行相应的操作
func (net *Network) executeNodeEvent(e *Event) error {
	if !e.Node.Up() {
		return net.Stop(e.Node.ID())
	}

	if _, err := net.NewNodeWithConfig(e.Node.Config); err != nil {
		return err
	}
	return net.Start(e.Node.ID())
}

// conn类型事件代表建立或者断开连接,执行对应的操作
func (net *Network) executeConnEvent(e *Event) error {
	if e.Conn.Up {
		return net.Connect(e.Conn.One, e.Conn.Other)
	}
	return net.Disconnect(e.Conn.One, e.Conn.Other)
}
