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

package enr

import (
	"fmt"
	"io"
	"net"

	"github.com/Evolution404/simcore/rlp"
)

// Entry is implemented by known node record entry types.
//
// To define a new entry that is to be included in a node record,
// create a Go type that satisfies this interface. The type should
// also implement rlp.Decoder if additional checks are needed on the value.
// Entry代表Record对象中的一条记录, 记录类型包括预定义类型和通用类型
// 预定义类型: ID,Secp256k1,IP,IPv4,IPv6,TCP,TCP6,UDP,UDP6
type Entry interface {
	ENRKey() string
}

// 通用的Entry类型,用来表示没有特殊定义的用户自己指定的键值对
type generic struct {
	key   string
	value interface{}
}

func (g generic) ENRKey() string { return g.key }

// 编码的时候只编码value字段到w里
func (g generic) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, g.value)
}

// 解码的时候从s中读取只解码到value中
func (g *generic) DecodeRLP(s *rlp.Stream) error {
	return s.Decode(g.value)
}

// WithEntry wraps any value with a key name. It can be used to set and load arbitrary values
// in a record. The value v must be supported by rlp. To use WithEntry with Load, the value
// must be a pointer.
// 构造一个通用的Entry对象,用于用户设置自定义的键值对,例如:
// r := enr.Record{}
// r.Set(enr.WithEntry("myentry","hello"))  // 设置键值对 "myentry":"hello"
// var m string
// r.Load(enr.WithEntry("myentry",&m))      // 重新加载myentry对应的值到m中,这里要使用m的指针
func WithEntry(k string, v interface{}) Entry {
	return &generic{key: k, value: v}
}

// TCP is the "tcp" key, which holds the TCP port of the node.
type TCP uint16

func (v TCP) ENRKey() string { return "tcp" }

// UDP is the "udp" key, which holds the IPv6-specific UDP port of the node.
type TCP6 uint16

func (v TCP6) ENRKey() string { return "tcp6" }

// UDP is the "udp" key, which holds the UDP port of the node.
type UDP uint16

func (v UDP) ENRKey() string { return "udp" }

// UDP6 is the "udp6" key, which holds the IPv6-specific UDP port of the node.
type UDP6 uint16

func (v UDP6) ENRKey() string { return "udp6" }

// ID is the "id" key, which holds the name of the identity scheme.
type ID string

const IDv4 = ID("v4") // the default identity scheme

func (v ID) ENRKey() string { return "id" }

// IP is either the "ip" or "ip6" key, depending on the value.
// Use this value to encode IP addresses that can be either v4 or v6.
// To load an address from a record use the IPv4 or IPv6 types.
// IP类型可以处理ipv4和ipv6
type IP net.IP

func (v IP) ENRKey() string {
	if net.IP(v).To4() == nil {
		return "ip6"
	}
	return "ip"
}

// EncodeRLP implements rlp.Encoder.
func (v IP) EncodeRLP(w io.Writer) error {
	if ip4 := net.IP(v).To4(); ip4 != nil {
		return rlp.Encode(w, ip4)
	}
	if ip6 := net.IP(v).To16(); ip6 != nil {
		return rlp.Encode(w, ip6)
	}
	return fmt.Errorf("invalid IP address: %v", net.IP(v))
}

// DecodeRLP implements rlp.Decoder.
func (v *IP) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err
	}
	// ipv4的长度是4字节,ipv6的长度是16字节
	if len(*v) != 4 && len(*v) != 16 {
		return fmt.Errorf("invalid IP address, want 4 or 16 bytes: %v", *v)
	}
	return nil
}

// IPv4 is the "ip" key, which holds the IP address of the node.
// 明确代表ipv4,代表的key是ip
type IPv4 net.IP

func (v IPv4) ENRKey() string { return "ip" }

// EncodeRLP implements rlp.Encoder.
func (v IPv4) EncodeRLP(w io.Writer) error {
	ip4 := net.IP(v).To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %v", net.IP(v))
	}
	return rlp.Encode(w, ip4)
}

// DecodeRLP implements rlp.Decoder.
func (v *IPv4) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err
	}
	if len(*v) != 4 {
		return fmt.Errorf("invalid IPv4 address, want 4 bytes: %v", *v)
	}
	return nil
}

// IPv6 is the "ip6" key, which holds the IP address of the node.
// 明确表示ipv6,代表的key是ip6
type IPv6 net.IP

func (v IPv6) ENRKey() string { return "ip6" }

// EncodeRLP implements rlp.Encoder.
func (v IPv6) EncodeRLP(w io.Writer) error {
	ip6 := net.IP(v).To16()
	if ip6 == nil {
		return fmt.Errorf("invalid IPv6 address: %v", net.IP(v))
	}
	return rlp.Encode(w, ip6)
}

// DecodeRLP implements rlp.Decoder.
func (v *IPv6) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err
	}
	if len(*v) != 16 {
		return fmt.Errorf("invalid IPv6 address, want 16 bytes: %v", *v)
	}
	return nil
}

// KeyError is an error related to a key.
type KeyError struct {
	Key string
	Err error
}

// Error implements error.
func (err *KeyError) Error() string {
	if err.Err == errNotFound {
		return fmt.Sprintf("missing ENR key %q", err.Key)
	}
	return fmt.Sprintf("ENR key %q: %v", err.Key, err.Err)
}

// IsNotFound reports whether the given error means that a key/value pair is
// missing from a record.
func IsNotFound(err error) bool {
	kerr, ok := err.(*KeyError)
	return ok && kerr.Err == errNotFound
}
