// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enr"
)

var (
	// (?i)代表不区分大小写
	// 正则表达式后面包括了两个分组
	// (?:enode://)? 用来匹配链接前缀,里面的?:代表这个分组不被捕获,也就是FindStringSubmatch返回的数组中不包括这个分组的匹配
	// ([0-9a-f]+)   用来匹配节点的公钥
	incompleteNodeURL = regexp.MustCompile("(?i)^(?:enode://)?([0-9a-f]+)$")
	lookupIPFunc      = net.LookupIP
)

// MustParseV4 parses a node URL. It panics if the URL is not valid.
func MustParseV4(rawurl string) *Node {
	n, err := ParseV4(rawurl)
	if err != nil {
		panic("invalid node URL: " + err.Error())
	}
	return n
}

// ParseV4 parses a node URL.
//
// There are two basic forms of node URLs:
//
//   - incomplete nodes, which only have the public key (node ID)
//   - complete nodes, which contain the public key and IP/Port information
//
// For incomplete nodes, the designator must look like one of these
//
//    enode://<hex node id>
//    <hex node id>
//
// For complete nodes, the node ID is encoded in the username portion
// of the URL, separated from the host by an @ sign. The hostname can
// only be given as an IP address or using DNS domain name.
// The port in the host name section is the TCP listening port. If the
// TCP and UDP (discovery) ports differ, the UDP port is specified as
// query parameter "discport".
//
// In the following example, the node URL describes
// a node with IP address 10.3.58.6, TCP listening port 30303
// and UDP discovery port 30301.
//
//    enode://<hex node id>@10.3.58.6:30303?discport=30301
// 解析V4版本的链接,有两种类型,不完整版和完整版
// 不完整版的格式如下
//   enode://<hex node id>
//   <hex node id>
// 完整版的格式包括了ip以及端口号,例如
//   enode://<hex node id>@10.3.58.6:30303?discport=30301
func ParseV4(rawurl string) (*Node, error) {
	// 返回结果是一个数组
	// 数组中的第一个元素是正则表达式的匹配结果,后面的依次是各个分组匹配到的结果
	if m := incompleteNodeURL.FindStringSubmatch(rawurl); m != nil {
		id, err := parsePubkey(m[1])
		if err != nil {
			return nil, fmt.Errorf("invalid public key (%v)", err)
		}
		return NewV4(id, nil, 0, 0), nil
	}
	return parseComplete(rawurl)
}

// NewV4 creates a node from discovery v4 node information. The record
// contained in the node has a zero-length signature.
// 创建一个v4版本的节点对象
// 需要提供节点的公钥,ip,tcp和udp端口
func NewV4(pubkey *ecdsa.PublicKey, ip net.IP, tcp, udp int) *Node {
	var r enr.Record
	if len(ip) > 0 {
		r.Set(enr.IP(ip))
	}
	if udp != 0 {
		r.Set(enr.UDP(udp))
	}
	if tcp != 0 {
		r.Set(enr.TCP(tcp))
	}
	signV4Compat(&r, pubkey)
	// 这里本质还是调用了New方法
	n, err := New(v4CompatID{}, &r)
	if err != nil {
		panic(err)
	}
	return n
}

// isNewV4 returns true for nodes created by NewV4.
// 判断是不是NewV4创建的节点
func isNewV4(n *Node) bool {
	var k s256raw
	return n.r.IdentityScheme() == "" && n.r.Load(&k) == nil && len(n.r.Signature()) == 0
}

// 对enode链接进行解析,格式如下
// enode://xxx@ip:port?discport=port
// 假设u为url.URL对象,则它有
// u.Scheme为"enode"
// u.User为"xxx"
// u.Hostname()为ip
func parseComplete(rawurl string) (*Node, error) {
	var (
		id               *ecdsa.PublicKey
		tcpPort, udpPort uint64
	)
	// 使用url.Parse对链接进行解析
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	// 必须以enode开头
	if u.Scheme != "enode" {
		return nil, errors.New("invalid URL scheme, want \"enode\"")
	}
	// Parse the Node ID from the user portion.
	// 这个User字段保存了节点的公钥
	if u.User == nil {
		return nil, errors.New("does not contain node ID")
	}
	if id, err = parsePubkey(u.User.String()); err != nil {
		return nil, fmt.Errorf("invalid public key (%v)", err)
	}
	// Parse the IP address.
	// Hostname可能是保存了ip也可能保存的域名
	ip := net.ParseIP(u.Hostname())
	// 解析失败,可能是保存了域名,也可能是格式错误
	// 不能确定是哪种情况,执行dns解析试试
	if ip == nil {
		ips, err := lookupIPFunc(u.Hostname())
		if err != nil {
			return nil, err
		}
		ip = ips[0]
	}
	// Ensure the IP is 4 bytes long for IPv4 addresses.
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	// Parse the port numbers.
	// 解析tcp端口
	if tcpPort, err = strconv.ParseUint(u.Port(), 10, 16); err != nil {
		return nil, errors.New("invalid port")
	}
	// 默认udp端口与tcp端口一致
	udpPort = tcpPort
	qv := u.Query()
	// 根据链接中discport参数确定udp端口
	if qv.Get("discport") != "" {
		udpPort, err = strconv.ParseUint(qv.Get("discport"), 10, 16)
		if err != nil {
			return nil, errors.New("invalid discport in query")
		}
	}
	// 创建enode.Node对象
	return NewV4(id, ip, int(tcpPort), int(udpPort)), nil
}

// parsePubkey parses a hex-encoded secp256k1 public key.
// 输入长度是128的hex字符串,转化为ecdsa.PublicKey对象
func parsePubkey(in string) (*ecdsa.PublicKey, error) {
	// 转换为64字节的字节数组
	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	} else if len(b) != 64 {
		return nil, fmt.Errorf("wrong length, want %d hex chars", 128)
	}
	// 加上公钥的一字节固定前缀
	b = append([]byte{0x4}, b...)
	return crypto.UnmarshalPubkey(b)
}

// 构造enode链接
func (n *Node) URLv4() string {
	var (
		scheme enr.ID
		nodeid string
		key    ecdsa.PublicKey
	)
	n.Load(&scheme)
	n.Load((*Secp256k1)(&key))
	switch {
	case scheme == "v4" || key != ecdsa.PublicKey{}:
		nodeid = fmt.Sprintf("%x", crypto.FromECDSAPub(&key)[1:])
	default:
		nodeid = fmt.Sprintf("%s.%x", scheme, n.id[:])
	}
	u := url.URL{Scheme: "enode"}
	if n.Incomplete() {
		u.Host = nodeid
	} else {
		addr := net.TCPAddr{IP: n.IP(), Port: n.TCP()}
		u.User = url.User(nodeid)
		u.Host = addr.String()
		if n.UDP() != n.TCP() {
			u.RawQuery = "discport=" + strconv.Itoa(n.UDP())
		}
	}
	return u.String()
}

// PubkeyToIDV4 derives the v4 node address from the given public key.
// 将公钥转换成节点ID
// 计算方法: keccak256(pub.X || pub.Y)
func PubkeyToIDV4(key *ecdsa.PublicKey) ID {
	// 公钥的X填充前32字节,Y填充后32字节
	e := make([]byte, 64)
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	// 对64字节内容计算哈希就是最终的节点ID
	return ID(crypto.Keccak256Hash(e))
}
