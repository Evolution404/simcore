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

package adapters

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/node"
	"github.com/Evolution404/simcore/p2p"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/simulations/pipes"
	"github.com/Evolution404/simcore/rpc"
	"github.com/gorilla/websocket"
)

// SimAdapter is a NodeAdapter which creates in-memory simulation nodes and
// connects them using net.Pipe
// 用来创建使用net.Pipe进行通信的仿真节点
// 实现了p2p.NodeDialer,adapters.NodeAdapter,adapters.RPCDialer接口
type SimAdapter struct {
	// 用来创建net.Conn对象的函数
	pipe func() (net.Conn, net.Conn, error)
	mtx  sync.RWMutex
	// 保存这个Adapter已经创建的节点
	nodes      map[enode.ID]*SimNode
	lifecycles LifecycleConstructors
}

// NewSimAdapter creates a SimAdapter which is capable of running in-memory
// simulation nodes running any of the given services (the services to run on a
// particular node are passed to the NewNode function in the NodeConfig)
// the adapter uses a net.Pipe for in-memory simulated network connections
// 创建SimAdapter需要输入支持的服务,因为SimAdapter不使用RegisterLifecycles中注册的服务
func NewSimAdapter(services LifecycleConstructors) *SimAdapter {
	return &SimAdapter{
		pipe:       pipes.NetPipe,
		nodes:      make(map[enode.ID]*SimNode),
		lifecycles: services,
	}
}

// Name returns the name of the adapter for logging purposes
func (s *SimAdapter) Name() string {
	return "sim-adapter"
}

// NewNode returns a new SimNode using the given config
// 输入内存节点的配置用来创建内存型节点
// 配置必须包含私钥和节点运行的服务，配置可以由RandomNodeConfig方法生成
func (s *SimAdapter) NewNode(config *NodeConfig) (Node, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	id := config.ID
	// verify that the node has a private key in the config
	// 保证配置中私钥存在
	if config.PrivateKey == nil {
		return nil, fmt.Errorf("node is missing private key: %s", id)
	}

	// check a node with the ID doesn't already exist
	// 保证节点ID在网络中没有重复
	if _, exists := s.nodes[id]; exists {
		return nil, fmt.Errorf("node already exists: %s", id)
	}

	// check the services are valid
	if len(config.Lifecycles) == 0 {
		return nil, errors.New("node must have at least one service")
	}
	// 确保这个节点使用的服务在SimAdapter中已经注册了
	for _, service := range config.Lifecycles {
		if _, exists := s.lifecycles[service]; !exists {
			return nil, fmt.Errorf("unknown node service %q", service)
		}
	}

	err := config.initDummyEnode()
	if err != nil {
		return nil, err
	}

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			PrivateKey:      config.PrivateKey,
			MaxPeers:        math.MaxInt32,
			NoDiscovery:     true,
			Dialer:          s,
			EnableMsgEvents: config.EnableMsgEvents,
		},
		ExternalSigner: config.ExternalSigner,
		Logger:         log.New("node.id", id.String()),
	})
	if err != nil {
		return nil, err
	}

	simNode := &SimNode{
		ID:      id,
		config:  config,
		node:    n,
		adapter: s,
		running: make(map[string]node.Lifecycle),
	}
	// 往SimAdapter里保存新创建的节点
	s.nodes[id] = simNode
	return simNode, nil
}

// Dial implements the p2p.NodeDialer interface by connecting to the node using
// an in-memory net.Pipe
// 实现p2p.NodeDialer接口
func (s *SimAdapter) Dial(ctx context.Context, dest *enode.Node) (conn net.Conn, err error) {
	node, ok := s.GetNode(dest.ID())
	if !ok {
		return nil, fmt.Errorf("unknown node: %s", dest.ID())
	}
	srv := node.Server()
	if srv == nil {
		return nil, fmt.Errorf("node not running: %s", dest.ID())
	}
	// SimAdapter.pipe is net.Pipe (NewSimAdapter)
	// 在这里创建一对连接,其中一个返回给拨号方,另一个通过SetupConn通知到被拨号的节点
	pipe1, pipe2, err := s.pipe()
	if err != nil {
		return nil, err
	}
	// this is simulated 'listening'
	// asynchronously call the dialed destination node's p2p server
	// to set up connection on the 'listening' side
	go srv.SetupConn(pipe1, 0, nil)
	return pipe2, nil
}

// DialRPC implements the RPCDialer interface by creating an in-memory RPC
// client of the given node
func (s *SimAdapter) DialRPC(id enode.ID) (*rpc.Client, error) {
	node, ok := s.GetNode(id)
	if !ok {
		return nil, fmt.Errorf("unknown node: %s", id)
	}
	return node.node.Attach()
}

// GetNode returns the node with the given ID if it exists
// 查找SimAdapter.nodes[id]
func (s *SimAdapter) GetNode(id enode.ID) (*SimNode, bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	node, ok := s.nodes[id]
	return node, ok
}

// SimNode is an in-memory simulation node which connects to other nodes using
// net.Pipe (see SimAdapter.Dial), running devp2p protocols directly over that
// pipe
// 由SimAdapter.NewNode创建的节点就是SimNode对象
// SimNode实现了adapters.Node接口,但是还额外实现了几个函数
// Close,Node,Server,Service,ServiceMap,Services,SubscribeEvents
type SimNode struct {
	lock    sync.RWMutex
	ID      enode.ID
	config  *NodeConfig
	adapter *SimAdapter
	node    *node.Node
	running map[string]node.Lifecycle
	client  *rpc.Client
	// 确保注册服务的过程只被执行一次
	registerOnce sync.Once
}

// Close closes the underlaying node.Node to release
// acquired resources.
func (sn *SimNode) Close() error {
	return sn.node.Close()
}

// Addr returns the node's discovery address
func (sn *SimNode) Addr() []byte {
	return []byte(sn.Node().String())
}

// Node returns a node descriptor representing the SimNode
func (sn *SimNode) Node() *enode.Node {
	return sn.config.Node()
}

// Client returns an rpc.Client which can be used to communicate with the
// underlying services (it is set once the node has started)
func (sn *SimNode) Client() (*rpc.Client, error) {
	sn.lock.RLock()
	defer sn.lock.RUnlock()
	if sn.client == nil {
		return nil, errors.New("node not started")
	}
	return sn.client, nil
}

// ServeRPC serves RPC requests over the given connection by creating an
// in-memory client to the node's RPC server.
func (sn *SimNode) ServeRPC(conn *websocket.Conn) error {
	handler, err := sn.node.RPCHandler()
	if err != nil {
		return err
	}
	codec := rpc.NewFuncCodec(conn, conn.WriteJSON, conn.ReadJSON)
	handler.ServeCodec(codec, 0)
	return nil
}

// Snapshots creates snapshots of the services by calling the
// simulation_snapshot RPC method
func (sn *SimNode) Snapshots() (map[string][]byte, error) {
	sn.lock.RLock()
	services := make(map[string]node.Lifecycle, len(sn.running))
	for name, service := range sn.running {
		services[name] = service
	}
	sn.lock.RUnlock()
	if len(services) == 0 {
		return nil, errors.New("no running services")
	}
	snapshots := make(map[string][]byte)
	for name, service := range services {
		if s, ok := service.(interface {
			Snapshot() ([]byte, error)
		}); ok {
			snap, err := s.Snapshot()
			if err != nil {
				return nil, err
			}
			snapshots[name] = snap
		}
	}
	return snapshots, nil
}

// Start registers the services and starts the underlying devp2p node
// 为节点注册服务,并启动节点
func (sn *SimNode) Start(snapshots map[string][]byte) error {
	// ensure we only register the services once in the case of the node
	// being stopped and then started again
	var regErr error
	sn.registerOnce.Do(func() {
		for _, name := range sn.config.Lifecycles {
			ctx := &ServiceContext{
				RPCDialer: sn.adapter,
				Config:    sn.config,
			}
			if snapshots != nil {
				ctx.Snapshot = snapshots[name]
			}
			// 找到服务对应的构造函数
			serviceFunc := sn.adapter.lifecycles[name]
			// 调用构造函数生成服务对象
			service, err := serviceFunc(ctx, sn.node)
			if err != nil {
				regErr = err
				break
			}
			// if the service has already been registered, don't register it again.
			// 跳过已经注册的服务
			if _, ok := sn.running[name]; ok {
				continue
			}
			// 将Lifecycle对象保存起来
			sn.running[name] = service
		}
	})
	if regErr != nil {
		return regErr
	}

	if err := sn.node.Start(); err != nil {
		return err
	}
	// create an in-process RPC client
	client, err := sn.node.Attach()
	if err != nil {
		return err
	}
	sn.lock.Lock()
	sn.client = client
	sn.lock.Unlock()
	return nil
}

// Stop closes the RPC client and stops the underlying devp2p node
func (sn *SimNode) Stop() error {
	sn.lock.Lock()
	if sn.client != nil {
		sn.client.Close()
		sn.client = nil
	}
	sn.lock.Unlock()
	return sn.node.Close()
}

// Service returns a running service by name
func (sn *SimNode) Service(name string) node.Lifecycle {
	sn.lock.RLock()
	defer sn.lock.RUnlock()
	return sn.running[name]
}

// Services returns a copy of the underlying services
func (sn *SimNode) Services() []node.Lifecycle {
	sn.lock.RLock()
	defer sn.lock.RUnlock()
	services := make([]node.Lifecycle, 0, len(sn.running))
	for _, service := range sn.running {
		services = append(services, service)
	}
	return services
}

// ServiceMap returns a map by names of the underlying services
func (sn *SimNode) ServiceMap() map[string]node.Lifecycle {
	sn.lock.RLock()
	defer sn.lock.RUnlock()
	services := make(map[string]node.Lifecycle, len(sn.running))
	for name, service := range sn.running {
		services[name] = service
	}
	return services
}

// Server returns the underlying p2p.Server
func (sn *SimNode) Server() *p2p.Server {
	return sn.node.Server()
}

// SubscribeEvents subscribes the given channel to peer events from the
// underlying p2p.Server
func (sn *SimNode) SubscribeEvents(ch chan *p2p.PeerEvent) event.Subscription {
	srv := sn.Server()
	if srv == nil {
		panic("node not running")
	}
	return srv.SubscribeEvents(ch)
}

// NodeInfo returns information about the node
func (sn *SimNode) NodeInfo() *p2p.NodeInfo {
	server := sn.Server()
	if server == nil {
		return &p2p.NodeInfo{
			ID:    sn.ID.String(),
			Enode: sn.Node().String(),
		}
	}
	return server.NodeInfo()
}
