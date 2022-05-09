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
	"crypto/ecdsa"
	"net"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/p2p/netutil"
)

// UDPConn is a network connection on which discovery can operate.
// UDPConn接口是节点发现过程中使用的网络连接
// 可以使用别的对象实现该接口就可以替换节点发现过程使用的通信链路
type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// Config holds settings for the discovery listener.
// 启动节点发现监听服务使用的配置
// 必须设置的字段是PrivateKey
type Config struct {
	// These settings are required and configure the UDP listener:
	// 必选字段
	PrivateKey *ecdsa.PrivateKey

	// These settings are optional:
	// 可选字段
	NetRestrict *netutil.Netlist // list of allowed IP networks
	Bootnodes   []*enode.Node    // list of bootstrap nodes
	// 可选字段,所有没被处理的数据包发送到这里
	Unhandled chan<- ReadPacket // unhandled packets are sent on this channel
	// 默认是log.Root()
	Log log.Logger // if set, log messages go here
	// 默认是当前所有节点标识方案
	ValidSchemes enr.IdentityScheme // allowed identity schemes
	// 默认使用系统时钟
	Clock mclock.Clock
}

// 如果Log,ValidSchemes以及Clock没有设置,为Config对象设置默认值
// Log = log.Root()
// ValidSchemes = enode.ValidSchemes
// Clock = mclock.System{}
func (cfg Config) withDefaults() Config {
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

// ListenUDP starts listening for discovery packets on the given UDP socket.
// ListenUDP在UDP端口上启动监听节点发现的数据包
// 有ListenV4和ListenV5两个参数完全一致的函数,现在ListenUDP还默认使用ListenV4实现
func ListenUDP(c UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	return ListenV4(c, ln, cfg)
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
// 用于表示不能被处理的数据包,他们被发送到unhandled管道
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}
