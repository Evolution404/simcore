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

package discover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enode"
)

// node represents a host on the network.
// The fields of Node may not be modified.
// 将enode.Node外面又增加了两个字段
// 在Table中使用的节点
type node struct {
	enode.Node
	addedAt time.Time // time when the node was added to the table
	// 此节点重生效过程中Ping成功过多少次
	livenessChecks uint // how often liveness was checked
}

// 64字节的公钥 32字节保存X,32字节保存Y
type encPubkey [64]byte

// 将ecdsa.PublicKey转化成64字节的encPubkey类型
func encodePubkey(key *ecdsa.PublicKey) encPubkey {
	var e encPubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

// 根据曲线和公钥的字节数组e恢复出来PublicKey对象
// 64字节e中保存横纵坐标X,Y
func decodePubkey(curve elliptic.Curve, e []byte) (*ecdsa.PublicKey, error) {
	if len(e) != len(encPubkey{}) {
		return nil, errors.New("wrong size public key data")
	}
	p := &ecdsa.PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid curve point")
	}
	return p, nil
}

// 对64字节公钥计算一次哈希即可得到id
func (e encPubkey) id() enode.ID {
	return enode.ID(crypto.Keccak256Hash(e[:]))
}

// 将enode.Node封装成discover.node
func wrapNode(n *enode.Node) *node {
	return &node{Node: *n}
}

// 将一组enode.Node封装成discover.node
func wrapNodes(ns []*enode.Node) []*node {
	result := make([]*node, len(ns))
	for i, n := range ns {
		result[i] = wrapNode(n)
	}
	return result
}

// discover.Node -> enode.Node
// 将discover.node去掉封装,取出enode.Node
func unwrapNode(n *node) *enode.Node {
	return &n.Node
}

// 一组discover.Node -> enode.Node
func unwrapNodes(ns []*node) []*enode.Node {
	result := make([]*enode.Node, len(ns))
	for i, n := range ns {
		result[i] = unwrapNode(n)
	}
	return result
}

// 获取节点监听的udp地址
func (n *node) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
}

func (n *node) String() string {
	return n.Node.String()
}
