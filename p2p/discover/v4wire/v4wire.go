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

// Package v4wire implements the Discovery v4 Wire Protocol.
package v4wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
)

// RPC packet types
// 定义了六种包类型
const (
	PingPacket = iota + 1 // zero is 'reserved'
	PongPacket
	FindnodePacket
	NeighborsPacket
	ENRRequestPacket
	ENRResponsePacket
)

// RPC request structures
// 以下定义了六种包的具体数据结构
type (
	Ping struct {
		// 协议版本，就是4
		Version uint
		// ping包的发送方和接收方的ip、端口信息
		From, To Endpoint
		// ping包的过期时间
		Expiration uint64
		// 本地节点的记录序号
		ENRSeq uint64 `rlp:"optional"` // Sequence number of local record, added by EIP-868.

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Pong is the reply to ping.
	Pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		// Pong包返回的目的地址
		To Endpoint
		// 这个pong包对应的ping包的哈希
		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		ENRSeq     uint64 `rlp:"optional"` // Sequence number of local record, added by EIP-868.

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Findnode is a query for nodes close to the given target.
	Findnode struct {
		// 要查询与Target最近的节点
		Target     Pubkey
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Neighbors is the reply to findnode.
	Neighbors struct {
		// 查询到的结果
		Nodes      []Node
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// enrRequest queries for the remote node's record.
	ENRRequest struct {
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// enrResponse is the reply to enrRequest.
	ENRResponse struct {
		// 响应的ENRRequest包的哈希
		ReplyTok []byte // Hash of the enrRequest packet.
		Record   enr.Record
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}
)

// This number is the maximum number of neighbor nodes in a Neighbors packet.
const MaxNeighbors = 12

// This code computes the MaxNeighbors constant value.

// func init() {
// 	var maxNeighbors int
// 	p := Neighbors{Expiration: ^uint64(0)}
// 	maxSizeNode := Node{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
// 	for n := 0; ; n++ {
// 		p.Nodes = append(p.Nodes, maxSizeNode)
// 		size, _, err := rlp.EncodeToReader(p)
// 		if err != nil {
// 			// If this ever happens, it will be caught by the unit tests.
// 			panic("cannot encode: " + err.Error())
// 		}
// 		if headSize+size+1 >= 1280 {
// 			maxNeighbors = n
// 			break
// 		}
// 	}
// 	fmt.Println("maxNeighbors", maxNeighbors)
// }

// Pubkey represents an encoded 64-byte secp256k1 public key.
type Pubkey [64]byte

// ID returns the node ID corresponding to the public key.
// 将64字节公钥计算哈希得到节点ID
func (e Pubkey) ID() enode.ID {
	return enode.ID(crypto.Keccak256Hash(e[:]))
}

// Node represents information about a node.
// 一个节点信息
// 相比于Endpoint,增加了对方的公钥所以就成为了一个节点
type Node struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for RLPx protocol
	ID  Pubkey
}

// Endpoint represents a network endpoint.
// 一个网络端点,包括对方的ip,UDP端口,TCP端口
type Endpoint struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for RLPx protocol
}

// NewEndpoint creates an endpoint.
func NewEndpoint(addr *net.UDPAddr, tcpPort uint16) Endpoint {
	ip := net.IP{}
	if ip4 := addr.IP.To4(); ip4 != nil {
		ip = ip4
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		ip = ip6
	}
	return Endpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

// v4版本的Packet对象
type Packet interface {
	// packet name and type for logging purposes.
	Name() string
	Kind() byte
}

func (req *Ping) Name() string { return "PING/v4" }
func (req *Ping) Kind() byte   { return PingPacket }

func (req *Pong) Name() string { return "PONG/v4" }
func (req *Pong) Kind() byte   { return PongPacket }

func (req *Findnode) Name() string { return "FINDNODE/v4" }
func (req *Findnode) Kind() byte   { return FindnodePacket }

func (req *Neighbors) Name() string { return "NEIGHBORS/v4" }
func (req *Neighbors) Kind() byte   { return NeighborsPacket }

func (req *ENRRequest) Name() string { return "ENRREQUEST/v4" }
func (req *ENRRequest) Kind() byte   { return ENRRequestPacket }

func (req *ENRResponse) Name() string { return "ENRRESPONSE/v4" }
func (req *ENRResponse) Kind() byte   { return ENRResponsePacket }

// Expired checks whether the given UNIX time stamp is in the past.
// 判断输入的时间戳是不是早于现在的时间
// 返回true也就是说明输入的时间过期了
func Expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

// Encoder/decoder.

const (
	// 数据包头最开始的32字节哈希用于校验
	macSize = 32
	// 数据包头的第二部分是65字节签名
	sigSize = crypto.SignatureLength
	// 头部长度97字节,哈希32字节,签名65字节
	headSize = macSize + sigSize // space of packet frame data
)

var (
	ErrPacketTooSmall = errors.New("too small")
	ErrBadHash        = errors.New("bad hash")
	ErrBadPoint       = errors.New("invalid curve point")
)

// 用于占位,还不知道头部数据的内容时先填充一个全零空间
var headSpace = make([]byte, headSize)

// Decode reads a discovery v4 packet.
// 输入v4数据包的字节数组,解码出来数据包对象和远程节点公钥
// 数据包的结构
// 32字节哈希 65字节签名 其余数据
// 其余数据的第一个字节保存了包类型
// 返回包对象,远程节点的公钥,包中签名和数据整体的哈希,错误
func Decode(input []byte) (Packet, Pubkey, []byte, error) {
	// 如果什么数据都没有那么数据包是数据头97字节,还有一字节类型
	// 显然不能再短于这个了
	if len(input) < headSize+1 {
		return nil, Pubkey{}, nil, ErrPacketTooSmall
	}
	// 拆分哈希,签名,数据
	hash, sig, sigdata := input[:macSize], input[macSize:headSize], input[headSize:]
	// 对签名和数据重新计算哈希,校验数据包最开始的哈希是否正确
	shouldhash := crypto.Keccak256(input[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, Pubkey{}, nil, ErrBadHash
	}
	// 根据数据的哈希和签名恢复出来对方节点的公钥
	fromKey, err := recoverNodeKey(crypto.Keccak256(input[headSize:]), sig)
	if err != nil {
		return nil, fromKey, hash, err
	}

	var req Packet
	// 根据实际数据的第一个字节,创建包对象
	switch ptype := sigdata[0]; ptype {
	case PingPacket:
		req = new(Ping)
	case PongPacket:
		req = new(Pong)
	case FindnodePacket:
		req = new(Findnode)
	case NeighborsPacket:
		req = new(Neighbors)
	case ENRRequestPacket:
		req = new(ENRRequest)
	case ENRResponsePacket:
		req = new(ENRResponse)
	default:
		return nil, fromKey, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	// sigdata第一字节是包类型,不是rlp编码
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	// 解码出实际的包
	err = s.Decode(req)
	return req, fromKey, hash, err
}

// Encode encodes a discovery packet.
// 构造数据包的字节数组,返回的哈希是签名和数据的哈希,就是包字节数组的最开始部分
// packet = packet-header || packet-data
// packet-header = hash || signature || packet-type
// hash = keccak256(signature || packet-type || packet-data)
// signature = sign(packet-type || packet-data)
// hash长度32字节,signature长度65字节
// 1. 留空97字节,写入一字节类型
// 2. 对数据包进行编码写入bytes.Buffer
// 3. 对编码计算哈希然后签名填入前面留空的后65字节
// 4. 对签名和编码计算哈希,填入最开始32字节
func Encode(priv *ecdsa.PrivateKey, req Packet) (packet, hash []byte, err error) {
	b := new(bytes.Buffer)
	// 留空头部的97字节,哈希32,签名65
	b.Write(headSpace)
	// 写入一字节的包类型
	b.WriteByte(req.Kind())
	if err := rlp.Encode(b, req); err != nil {
		return nil, nil, err
	}
	packet = b.Bytes()
	// 计算签名,填充到[macSize,headSize]这一段
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		return nil, nil, err
	}
	copy(packet[macSize:], sig)
	// Add the hash to the front. Note: this doesn't protect the packet in any way.
	// 计算签名和数据整体的哈希
	hash = crypto.Keccak256(packet[macSize:])
	// 填充到数据包最开始
	copy(packet, hash)
	return packet, hash, nil
}

// recoverNodeKey computes the public key used to sign the given hash from the signature.
// 从签名和数据部分的哈希恢复出来远程节点的公钥
func recoverNodeKey(hash, sig []byte) (key Pubkey, err error) {
	pubkey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return key, err
	}
	// 恢复出来的公钥第一个字节是前缀04
	// 这里不需要所以去掉
	copy(key[:], pubkey[1:])
	return key, nil
}

// EncodePubkey encodes a secp256k1 public key.
// 编码公钥对象到64字节数组,去掉固定前缀04
func EncodePubkey(key *ecdsa.PublicKey) Pubkey {
	var e Pubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

// DecodePubkey reads an encoded secp256k1 public key.
// 输入曲线和64字节数组解码出来公钥对象
func DecodePubkey(curve elliptic.Curve, e Pubkey) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, ErrBadPoint
	}
	return p, nil
}
