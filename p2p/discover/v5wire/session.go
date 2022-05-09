// Copyright 2020 The go-ethereum Authors
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

package v5wire

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"time"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/hashicorp/golang-lru/simplelru"
)

// 用来缓存两个节点之间沟通的密钥

// 握手的超时时间是一秒
const handshakeTimeout = time.Second

// The SessionCache keeps negotiated encryption keys and
// state for in-progress handshakes in the Discovery v5 wire protocol.
type SessionCache struct {
	// sessions中保存了sessionID与session的一一对应
	sessions   *simplelru.LRU
	// 缓存握手要使用的信息
	// 保存本地发送的WHOAREYOU包
	handshakes map[sessionID]*Whoareyou
	clock      mclock.Clock

	// hooks for overriding randomness.
	// 以下定义的两个函数没有写死便于在测试的时候替换
	// 默认返回12字节Nonce,前4字节为输入的uint32,后8字节随机填充
	nonceGen        func(uint32) (Nonce, error)
	// 用来生成随机数IV的函数
	maskingIVGen    func([]byte) error
	ephemeralKeyGen func() (*ecdsa.PrivateKey, error)
}

// sessionID identifies a session or handshake.
// 用来从SessionCache.sessions中索引session对象
// 一条网络连接对应一个session
// 需要节点的ID和它的网络地址才能唯一确定一条连接,才对应一个session
type sessionID struct {
	id   enode.ID
	addr string
}

// session contains session information
// 代表两个节点沟通的一次会话
type session struct {
	// 本地发送消息加密使用的密钥
	writeKey     []byte
	// 本地接收消息解密使用的密钥
	readKey      []byte
	// nonce的计数器
	nonceCounter uint32
}

// keysFlipped returns a copy of s with the read and write keys flipped.
// 当前的session对象将writeKey和readKey反转后生成一个新session对象
func (s *session) keysFlipped() *session {
	return &session{s.readKey, s.writeKey, s.nonceCounter}
}

// 创建一个SessionCache对象
// maxItems代表缓存的最大条目
func NewSessionCache(maxItems int, clock mclock.Clock) *SessionCache {
	cache, err := simplelru.NewLRU(maxItems, nil)
	if err != nil {
		panic("can't create session cache")
	}
	return &SessionCache{
		sessions:        cache,
		handshakes:      make(map[sessionID]*Whoareyou),
		clock:           clock,
		nonceGen:        generateNonce,
		maskingIVGen:    generateMaskingIV,
		ephemeralKeyGen: crypto.GenerateKey,
	}
}

// 生成12字节的Nonce
// Nonce的前4字节是输入的counter
// 后面8字节是随机生成
func generateNonce(counter uint32) (n Nonce, err error) {
	binary.BigEndian.PutUint32(n[:4], counter)
	_, err = crand.Read(n[4:])
	return n, err
}

// 使用随机数填充buf
func generateMaskingIV(buf []byte) error {
	_, err := crand.Read(buf)
	return err
}

// nextNonce creates a nonce for encrypting a message to the given session.
// 获取下一个nonce
// 让nonceCounter自增,并生成一个新的Nonce
func (sc *SessionCache) nextNonce(s *session) (Nonce, error) {
	s.nonceCounter++
	return sc.nonceGen(s.nonceCounter)
}

// session returns the current session for the given node, if any.
// 从SessionCache中查询一个session对象
func (sc *SessionCache) session(id enode.ID, addr string) *session {
	item, ok := sc.sessions.Get(sessionID{id, addr})
	if !ok {
		return nil
	}
	return item.(*session)
}

// readKey returns the current read key for the given node.
// 从缓存中获取解密消息用的密钥
func (sc *SessionCache) readKey(id enode.ID, addr string) []byte {
	if s := sc.session(id, addr); s != nil {
		return s.readKey
	}
	return nil
}

// storeNewSession stores new encryption keys in the cache.
// 向缓存中添加新的会话
func (sc *SessionCache) storeNewSession(id enode.ID, addr string, s *session) {
	sc.sessions.Add(sessionID{id, addr}, s)
}

// getHandshake gets the handshake challenge we previously sent to the given remote node.
// 获取刚才发送给对方的那个WHOAREYOU包
func (sc *SessionCache) getHandshake(id enode.ID, addr string) *Whoareyou {
	return sc.handshakes[sessionID{id, addr}]
}

// storeSentHandshake stores the handshake challenge sent to the given remote node.
// 保存发送给对方的WHOAREYOU包
func (sc *SessionCache) storeSentHandshake(id enode.ID, addr string, challenge *Whoareyou) {
	challenge.sent = sc.clock.Now()
	sc.handshakes[sessionID{id, addr}] = challenge
}

// deleteHandshake deletes handshake data for the given node.
// 删除缓存的WHOAREYOU包
func (sc *SessionCache) deleteHandshake(id enode.ID, addr string) {
	delete(sc.handshakes, sessionID{id, addr})
}

// handshakeGC deletes timed-out handshakes.
// 清除所有已经存在超过一秒的缓存WHOAREYOU包
func (sc *SessionCache) handshakeGC() {
	deadline := sc.clock.Now().Add(-handshakeTimeout)
	for key, challenge := range sc.handshakes {
		if challenge.sent < deadline {
			delete(sc.handshakes, key)
		}
	}
}
