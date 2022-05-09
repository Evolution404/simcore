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
	"fmt"

	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
)

// Protocol represents a P2P subprotocol implementation.
// 由外部定义的子协议对象
type Protocol struct {
	// Name should contain the official protocol name,
	// often a three-letter word.
	// 官方的协议名称,一般是一个三个字母的单词
	Name string

	// Version should contain the version number of the protocol.
	Version uint

	// Length should contain the number of message codes used
	// by the protocol.
	// 代表不同messsage code的个数,也就是消息的类型总数
	// 由于message code从0开始,所以所有的message code都必须小于Length
	Length uint64

	// Run is called in a new goroutine when the protocol has been
	// negotiated with a peer. It should read and write messages from
	// rw. The Payload for each message must be fully consumed.
	//
	// The peer connection is closed when Start returns. It should return
	// any protocol-level error (such as an I/O error) that is
	// encountered.
	// Run 在与一个节点握手成功后调用,在单独协程中执行.
	// 可以通过rw来接收和发送消息,所有接收的消息的Payload必须被全部读取
	Run func(peer *Peer, rw MsgReadWriter) error

	// NodeInfo is an optional helper method to retrieve protocol specific metadata
	// about the host node.
	NodeInfo func() interface{}

	// PeerInfo is an optional helper method to retrieve protocol specific metadata
	// about a certain peer in the network. If an info retrieval function is set,
	// but returns nil, it is assumed that the protocol handshake is still running.
	PeerInfo func(id enode.ID) interface{}

	// DialCandidates, if non-nil, is a way to tell Server about protocol-specific nodes
	// that should be dialed. The server continuously reads nodes from the iterator and
	// attempts to create connections to them.
	// 用于为不同的协议指定不同的节点
	DialCandidates enode.Iterator

	// Attributes contains protocol specific information for the node record.
	// 节点记录中增加的额外信息
	Attributes []enr.Entry
}

func (p Protocol) cap() Cap {
	return Cap{p.Name, p.Version}
}

// Cap is the structure of a peer capability.
// Cap代表一个远程节点协议的能力
// 通过协议名称和协议版本来描述能力
type Cap struct {
	Name    string
	Version uint
}

// Cap的打印格式 name/version
// 例如 protocol/1
func (cap Cap) String() string {
	return fmt.Sprintf("%s/%d", cap.Name, cap.Version)
}

// 排序首先按照Name的字典序排序,Name相同按照Version排序
// 实现了sort接口
type capsByNameAndVersion []Cap

func (cs capsByNameAndVersion) Len() int      { return len(cs) }
func (cs capsByNameAndVersion) Swap(i, j int) { cs[i], cs[j] = cs[j], cs[i] }
func (cs capsByNameAndVersion) Less(i, j int) bool {
	return cs[i].Name < cs[j].Name || (cs[i].Name == cs[j].Name && cs[i].Version < cs[j].Version)
}
