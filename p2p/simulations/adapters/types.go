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
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/docker/docker/pkg/reexec"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/node"
	"github.com/Evolution404/simcore/p2p"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rpc"
	"github.com/gorilla/websocket"
)

// Node represents a node in a simulation network which is created by a
// NodeAdapter, for example:
//
// * SimNode    - An in-memory node
// * ExecNode   - A child process node
// * DockerNode - A Docker container node
//
// Node代表在仿真网络中由NodeAdapter创建的节点对象
// 该接口由SimNode和ExecNode实现
// SimNode 内存中的节点
// ExecNode 使用子进程的节点
type Node interface {
	// Addr returns the node's address (e.g. an Enode URL)
	Addr() []byte

	// Client returns the RPC client which is created once the node is
	// up and running
	Client() (*rpc.Client, error)

	// ServeRPC serves RPC requests over the given connection
	ServeRPC(*websocket.Conn) error

	// Start starts the node with the given snapshots
	Start(snapshots map[string][]byte) error

	// Stop stops the node
	Stop() error

	// NodeInfo returns information about the node
	NodeInfo() *p2p.NodeInfo

	// Snapshots creates snapshots of the running services
	Snapshots() (map[string][]byte, error)
}

// NodeAdapter is used to create Nodes in a simulation network
// NodeAdapter用来在仿真网络中创建节点
// 有SimAdapter和ExecAdapter
type NodeAdapter interface {
	// Name returns the name of the adapter for logging purposes
	Name() string

	// NewNode creates a new node with the given configuration
	NewNode(config *NodeConfig) (Node, error)
}

// NodeConfig is the configuration used to start a node in a simulation
// network
// 使用适配器创建节点的配置,在NodeAdapter.NewNode函数中需要传入NodeConfig对象
type NodeConfig struct {
	// ID is the node's ID which is used to identify the node in the
	// simulation network
	ID enode.ID

	// PrivateKey is the node's private key which is used by the devp2p
	// stack to encrypt communications
	// 必须指定私钥
	PrivateKey *ecdsa.PrivateKey

	// Enable peer events for Msgs
	EnableMsgEvents bool

	// Name is a human friendly name for the node like "node01"
	Name string

	// Use an existing database instead of a temporary one if non-empty
	DataDir string

	// Lifecycles are the names of the service lifecycles which should be run when
	// starting the node (for SimNodes it should be the names of service lifecycles
	// contained in SimAdapter.lifecycles, for other nodes it should be
	// service lifecycles registered by calling the RegisterLifecycle function)
	// 必须指定至少一个服务名称
	Lifecycles []string

	// Properties are the names of the properties this node should hold
	// within running services (e.g. "bootnode", "lightnode" or any custom values)
	// These values need to be checked and acted upon by node Services
	Properties []string

	// ExternalSigner specifies an external URI for a clef-type signer
	ExternalSigner string

	// Enode
	node *enode.Node

	// ENR Record with entries to overwrite
	// 这里记录的信息优先级低,如果设置了Port会,记录中的端口也会更新
	Record enr.Record

	// function to sanction or prevent suggesting a peer
	Reachable func(id enode.ID) bool

	Port uint16

	// LogFile is the log file name of the p2p node at runtime.
	//
	// The default value is empty so that the default log writer
	// is the system standard output.
	LogFile string

	// LogVerbosity is the log verbosity of the p2p node at runtime.
	//
	// The default verbosity is INFO.
	LogVerbosity log.Lvl
}

// nodeConfigJSON is used to encode and decode NodeConfig as JSON by encoding
// all fields as strings
// 将各种字段转化为字符串类型,用于Config对象与jSON格式之间的转换
type nodeConfigJSON struct {
	ID              string   `json:"id"`
	PrivateKey      string   `json:"private_key"`
	Name            string   `json:"name"`
	Lifecycles      []string `json:"lifecycles"`
	Properties      []string `json:"properties"`
	EnableMsgEvents bool     `json:"enable_msg_events"`
	Port            uint16   `json:"port"`
	LogFile         string   `json:"logfile"`
	LogVerbosity    int      `json:"log_verbosity"`
}

// MarshalJSON implements the json.Marshaler interface by encoding the config
// fields as strings
// 将NodeConfig对象编码为json字符串
func (n *NodeConfig) MarshalJSON() ([]byte, error) {
	confJSON := nodeConfigJSON{
		// id是以hex字符串的格式保存
		ID:              n.ID.String(),
		Name:            n.Name,
		Lifecycles:      n.Lifecycles,
		Properties:      n.Properties,
		Port:            n.Port,
		EnableMsgEvents: n.EnableMsgEvents,
		LogFile:         n.LogFile,
		LogVerbosity:    int(n.LogVerbosity),
	}
	// 私钥也是以hex字符串保存
	if n.PrivateKey != nil {
		confJSON.PrivateKey = hex.EncodeToString(crypto.FromECDSA(n.PrivateKey))
	}
	return json.Marshal(confJSON)
}

// UnmarshalJSON implements the json.Unmarshaler interface by decoding the json
// string values into the config fields
// 将json字符串转化为NodeConfig对象
func (n *NodeConfig) UnmarshalJSON(data []byte) error {
	var confJSON nodeConfigJSON
	if err := json.Unmarshal(data, &confJSON); err != nil {
		return err
	}

	// ID和PrivateKey需要特殊处理,其他的字段直接赋值
	if confJSON.ID != "" {
		if err := n.ID.UnmarshalText([]byte(confJSON.ID)); err != nil {
			return err
		}
	}

	if confJSON.PrivateKey != "" {
		key, err := hex.DecodeString(confJSON.PrivateKey)
		if err != nil {
			return err
		}
		privKey, err := crypto.ToECDSA(key)
		if err != nil {
			return err
		}
		n.PrivateKey = privKey
	}

	n.Name = confJSON.Name
	n.Lifecycles = confJSON.Lifecycles
	n.Properties = confJSON.Properties
	n.Port = confJSON.Port
	n.EnableMsgEvents = confJSON.EnableMsgEvents
	n.LogFile = confJSON.LogFile
	n.LogVerbosity = log.Lvl(confJSON.LogVerbosity)

	return nil
}

// Node returns the node descriptor represented by the config.
func (n *NodeConfig) Node() *enode.Node {
	return n.node
}

// RandomNodeConfig returns node configuration with a randomly generated ID and
// PrivateKey
// 构造一个NodeConfig对象,随机生成节点的ID和私钥
func RandomNodeConfig() *NodeConfig {
	prvkey, err := crypto.GenerateKey()
	if err != nil {
		panic("unable to generate key")
	}

	port, err := assignTCPPort()
	if err != nil {
		panic("unable to assign tcp port")
	}

	// 通过随机生成的私钥对应的公钥计算出ID
	enodId := enode.PubkeyToIDV4(&prvkey.PublicKey)
	// 生成NodeConfig对象
	return &NodeConfig{
		PrivateKey:      prvkey,
		ID:              enodId,
		Name:            fmt.Sprintf("node_%s", enodId.String()),
		Port:            port,
		EnableMsgEvents: true,
		// 默认日志等级是INFO
		LogVerbosity: log.LvlInfo,
	}
}

// 获取一个空闲的端口
func assignTCPPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return 0, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}

// ServiceContext is a collection of options and methods which can be utilised
// when starting services
type ServiceContext struct {
	RPCDialer

	Config   *NodeConfig
	Snapshot []byte
}

// RPCDialer is used when initialising services which need to connect to
// other nodes in the network (for example a simulated Swarm node which needs
// to connect to a Geth node to resolve ENS names)
type RPCDialer interface {
	DialRPC(id enode.ID) (*rpc.Client, error)
}

// LifecycleConstructor allows a Lifecycle to be constructed during node start-up.
// While the service-specific package usually takes care of Lifecycle creation and registration,
// for testing purposes, it is useful to be able to construct a Lifecycle on spot.
// LifecycleConstructor在节点启动的时候用来构造Lifecycle对象
type LifecycleConstructor func(ctx *ServiceContext, stack *node.Node) (node.Lifecycle, error)

// LifecycleConstructors stores LifecycleConstructor functions to call during node start-up.
// 使用一个map封装多个服务的构造方法, string->LifecycleConstructor代表服务的名称->该服务的构造函数
type LifecycleConstructors map[string]LifecycleConstructor

// lifecycleConstructorFuncs is a map of registered services which are used to boot devp2p
// nodes
// 保存Exec或者Docker类型的节点注册的服务,该变量在RegisterLifecycles函数中设置
var lifecycleConstructorFuncs = make(LifecycleConstructors)

// RegisterLifecycles registers the given Services which can then be used to
// start devp2p nodes using either the Exec or Docker adapters.
//
// It should be called in an init function so that it has the opportunity to
// execute the services before main() is called.
// 为Exec或者Docker类型注册多个服务,这里注册的服务不对Sim类型生效
// Sim类型注册服务在创建适配器的时候进行,adapters.NewSimAdapter(services)
func RegisterLifecycles(lifecycles LifecycleConstructors) {
	for name, f := range lifecycles {
		if _, exists := lifecycleConstructorFuncs[name]; exists {
			panic(fmt.Sprintf("node service already exists: %q", name))
		}
		lifecycleConstructorFuncs[name] = f
	}

	// now we have registered the services, run reexec.Init() which will
	// potentially start one of the services if the current binary has
	// been exec'd with argv[0] set to "p2p-node"
	if reexec.Init() {
		os.Exit(0)
	}
}

// adds the host part to the configuration's ENR, signs it
// creates and  the corresponding enode object to the configuration
// 根据输入的ip和端口,初始化NodeConfig.Record和NodeConfig.node字段
func (n *NodeConfig) initEnode(ip net.IP, tcpport int, udpport int) error {
	// 先设置n.Record,然后根据Record对象生成enode.Node对象
	enrIp := enr.IP(ip)
	n.Record.Set(&enrIp)
	enrTcpPort := enr.TCP(tcpport)
	n.Record.Set(&enrTcpPort)
	enrUdpPort := enr.UDP(udpport)
	n.Record.Set(&enrUdpPort)

	// 修改了Record后需要重新签名
	err := enode.SignV4(&n.Record, n.PrivateKey)
	if err != nil {
		return fmt.Errorf("unable to generate ENR: %v", err)
	}
	// 生成enode.Node对象
	nod, err := enode.New(enode.V4ID{}, &n.Record)
	if err != nil {
		return fmt.Errorf("unable to create enode: %v", err)
	}
	log.Trace("simnode new", "record", n.Record)
	n.node = nod
	return nil
}

// 使用127.0.0.1和已经设置的端口初始化NodeConfig.Record和NodeConfig.node字段
func (n *NodeConfig) initDummyEnode() error {
	return n.initEnode(net.IPv4(127, 0, 0, 1), int(n.Port), 0)
}
