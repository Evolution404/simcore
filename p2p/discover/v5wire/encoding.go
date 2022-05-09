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

package v5wire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
)

// TODO concurrent WHOAREYOU tie-breaker
// TODO rehandshake after X packets

// Header represents a packet header.
// 数据包的头部
// 头部包括16字节明文的IV,以及加密部分
//   加密使用AES-CTR模式,密钥是对方节点的id前16字节,IV就是最开始16字节明文的IV
// 加密前的原始头部信息包括 定长信息和认证信息,分别由StaticHeader和AuthData表示
type Header struct {
	IV [sizeofMaskingIV]byte
	StaticHeader
	AuthData []byte

	src enode.ID // used by decoder
}

// StaticHeader contains the static fields of a packet header.
// 头部中定长的信息,总共23字节,5个字段
type StaticHeader struct {
	// 使用6个字节保存协议版本,现在是 "discv5"
	ProtocolID [6]byte
	// 2字节version
	Version    uint16
	// 1字节flag
	Flag       byte
	// 12字节Nonce
	Nonce      Nonce
	// 2字节AuthSize,代表头部后面AuthData的长度
	AuthSize   uint16
}

// Authdata layouts.
// 三种数据包的AuthData
type (
	whoareyouAuthData struct {
		IDNonce   [16]byte // ID proof data
		RecordSeq uint64   // highest known ENR sequence of requester
	}

	// 握手包的AuthData可以分为四部分
	// authdata-head || id-signature || eph-pubkey || record
	// authdata-head又有三个部分,src-id || 后面签名的长度 || 后面公钥的长度
	// record代表节点的记录
	handshakeAuthData struct {
		h struct {
			SrcID      enode.ID
			SigSize    byte // ignature data
			PubkeySize byte // offset of
		}
		// Trailing variable-size data.
		signature, pubkey, record []byte
	}

	messageAuthData struct {
		SrcID enode.ID
	}
)

// Packet header flag values.
const (
	flagMessage = iota
	flagWhoareyou
	flagHandshake
)

// Protocol constants.
const (
	version         = 1
	minVersion      = 1
	// IV的长度固定为16字节
	sizeofMaskingIV = 16

	// 对于消息包staticHeader后面都有32字节src-id
	// 由于有认证信息,后面的加密信息最小16字节
	minMessageSize      = 48 // this refers to data after static headers
	randomPacketMsgSize = 20
)

var protocolID = [6]byte{'d', 'i', 's', 'c', 'v', '5'}

// Errors.
var (
	errTooShort            = errors.New("packet too short")
	errInvalidHeader       = errors.New("invalid packet header")
	errInvalidFlag         = errors.New("invalid flag value in header")
	errMinVersion          = errors.New("version of packet header below minimum")
	errMsgTooShort         = errors.New("message/handshake packet below minimum size")
	errAuthSize            = errors.New("declared auth size is beyond packet length")
	errUnexpectedHandshake = errors.New("unexpected auth response, not in handshake")
	errInvalidAuthKey      = errors.New("invalid ephemeral pubkey")
	errNoRecord            = errors.New("expected ENR in handshake but none sent")
	errInvalidNonceSig     = errors.New("invalid ID nonce signature")
	errMessageTooShort     = errors.New("message contains no data")
	errMessageDecrypt      = errors.New("cannot decrypt message")
)

// Public errors.
var (
	ErrInvalidReqID = errors.New("request ID larger than 8 bytes")
)

// Packet sizes.
var (
	// 23字节,代表数据包头部定长不包括IV的部分
	sizeofStaticHeader      = binary.Size(StaticHeader{})
	// 三种类型数据包的AuthData的长度
	// 24字节,whoareyou数据包
	// 16字节nonce与8字节序号
	sizeofWhoareyouAuthData = binary.Size(whoareyouAuthData{})
	// 34字节,握手数据包
	sizeofHandshakeAuthData = binary.Size(handshakeAuthData{}.h)
	// 32字节,普通数据包
	// 普通数据包就是本地节点的ID,使用32字节
	sizeofMessageAuthData   = binary.Size(messageAuthData{})
	// 39字节,代表数据包头部不包括AuthData的大小
	sizeofStaticPacketData  = sizeofMaskingIV + sizeofStaticHeader
)

// Codec encodes and decodes Discovery v5 packets.
// This type is not safe for concurrent use.
type Codec struct {
	sha256    hash.Hash
	localnode *enode.LocalNode
	privkey   *ecdsa.PrivateKey
	sc        *SessionCache

	// encoder buffers
	// 整个数据包
	buf      bytes.Buffer // whole packet
	// 头部数据
	headbuf  bytes.Buffer // packet header
	// 缓存消息的原文,第一字节包类型,接着是Packet对象的RLP编码
	msgbuf   bytes.Buffer // message RLP plaintext
	// 消息的密文
	msgctbuf []byte       // message data ciphertext

	// decoder buffer
	reader bytes.Reader
}

// NewCodec creates a wire codec.
// 创建一个Codec对象,需要LocalNode对象和本地私钥
func NewCodec(ln *enode.LocalNode, key *ecdsa.PrivateKey, clock mclock.Clock) *Codec {
	c := &Codec{
		sha256:    sha256.New(),
		localnode: ln,
		privkey:   key,
		// 最多保存1024个会话的SessionCache
		sc:        NewSessionCache(1024, clock),
	}
	return c
}

// Encode encodes a packet to a node. 'id' and 'addr' specify the destination node. The
// 'challenge' parameter should be the most recently received WHOAREYOU packet from that
// node.
// 编码一个数据包,数据包有三种 普通包,WHOAREYOU包,握手包
// id,addr代表了数据包发送到节点,packet代表要发送的消息,challenge不为nil代表要发送握手包
func (c *Codec) Encode(id enode.ID, addr string, packet Packet, challenge *Whoareyou) ([]byte, Nonce, error) {
	// Create the packet header.
	var (
		head    Header
		session *session
		msgData []byte
		err     error
	)
	// 分三种情况来判断要编码成什么类型的数据包
	switch {
	// 编码成WHOAREYOU
	case packet.Kind() == WhoareyouPacket:
		head, err = c.encodeWhoareyou(id, packet.(*Whoareyou))
	// 编码成握手包
	case challenge != nil:
		// We have an unanswered challenge, send handshake.
		head, session, err = c.encodeHandshakeHeader(id, addr, challenge)
	// 编码成普通数据包
	default:
		// 编码普通数据包也分成两种情况
		// 本地保存了与对方沟通的密钥,编码数据
		// 本地没有与对方沟通的密钥,生成一个随机的数据包,促使对面解密不成功发送WHOAREYOU数据包
		session = c.sc.session(id, addr)
		if session != nil {
			// There is a session, use it.
			head, err = c.encodeMessageHeader(id, session)
		} else {
			// No keys, send random data to kick off the handshake.
			head, msgData, err = c.encodeRandom(id)
		}
	}
	if err != nil {
		return nil, Nonce{}, err
	}

	// Generate masking IV.
	// 生成随机的IV
	if err := c.sc.maskingIVGen(head.IV[:]); err != nil {
		return nil, Nonce{}, fmt.Errorf("can't generate masking IV: %v", err)
	}

	// Encode header data.
	// 编码Header对象,将header data保存到c.buf中
	c.writeHeaders(&head)

	// 接下来编码Packet对象为msgData
	// WHOAREYOU包没有msgData,前面调用encodeRandom可能已经生成了随机msgData
	// 下面要处理这两种情况

	// Store sent WHOAREYOU challenges.
	// 发送WHOAREYOU包要将包的内容缓存下来
	if challenge, ok := packet.(*Whoareyou); ok {
		challenge.ChallengeData = bytesCopy(&c.buf)
		c.sc.storeSentHandshake(id, addr, challenge)
	// 如果本地保存了会话的密钥对Packet对象编码后使用密钥加密
	} else if msgData == nil {
		headerData := c.buf.Bytes()
		// 获得加密消息内容
		msgData, err = c.encryptMessage(session, packet, &head, headerData)
		if err != nil {
			return nil, Nonce{}, err
		}
	}

	// 编码最终的字节内容到c.buf中
	// 写入IV
	// 使用id加密head内容并写入c.buf
	// 写入加密的msgData
	enc, err := c.EncodeRaw(id, head, msgData)
	return enc, head.Nonce, err
}

// EncodeRaw encodes a packet with the given header.
// 给定数据包头Header对象和已经处理好的消息字节,编码成一个实际发送的字节数组
// msgdata就是真正发送的消息,不需要再进行加密
// 需要提供接收者的id,用来对Header对象编码后的结果加密
// 1. 编码Header对象到c.buf中
// 2. 利用id前16字节作为密钥对c.buf的IV后面部分进行加密
// 3. 再向c.buf写入msgdata
// 4. 返回c.buf.Bytes()
func (c *Codec) EncodeRaw(id enode.ID, head Header, msgdata []byte) ([]byte, error) {
	// 编码成字节流
	c.writeHeaders(&head)

	// Apply masking.
	// 接下来要将IV后面的数据进行加密
	// 取出IV后面的数据
	masked := c.buf.Bytes()[sizeofMaskingIV:]
	// 生成AES-CTR模式加密器
	mask := head.mask(id)
	// 利用加密器对IV后面的数据进行加密
	mask.XORKeyStream(masked[:], masked[:])

	// Write message data.
	c.buf.Write(msgdata)
	return c.buf.Bytes(), nil
}

// 将Header对象的三个部分写入到c.buf中,编码成字节数组
// 三个部分分别是IV,StaticHeader,AuthData
func (c *Codec) writeHeaders(head *Header) {
	c.buf.Reset()
	c.buf.Write(head.IV[:])
	binary.Write(&c.buf, binary.BigEndian, &head.StaticHeader)
	c.buf.Write(head.AuthData)
}

// makeHeader creates a packet header.
// 填充Header对象的StaticHeader五个字段中的四个,缺少12字节Nonce字段
// 这个函数需要设置的就是Flag和AuthSize字段
func (c *Codec) makeHeader(toID enode.ID, flag byte, authsizeExtra int) Header {
	var authsize int
	// 区分三种包类型,设置AuthSize
	switch flag {
	case flagMessage:
		authsize = sizeofMessageAuthData
	case flagWhoareyou:
		authsize = sizeofWhoareyouAuthData
	case flagHandshake:
		authsize = sizeofHandshakeAuthData
	default:
		panic(fmt.Errorf("BUG: invalid packet header flag %x", flag))
	}
	authsize += authsizeExtra
	if authsize > int(^uint16(0)) {
		panic(fmt.Errorf("BUG: auth size %d overflows uint16", authsize))
	}
	// 构造Header对象
	return Header{
		StaticHeader: StaticHeader{
			ProtocolID: protocolID,
			Version:    version,
			Flag:       flag,
			AuthSize:   uint16(authsize),
		},
	}
}

// 接下来的四个函数都是用来生成一个Header对象,填充了除了IV之外的内容
// 这四个函数的主要工作是用来填充Nonce和AuthData
// encodeRandom
//   Nonce:12字节随机 AuthData:src-id
//   除了返回Header对象还返回了2字节的随机msgData
// encodeMessageHeader,
//   Nonce:4字节序号,8字节随机 AuthData:src-id
// encodeWhoareyou
//   Nonce:在输入的packet中保存 AuthData:在输入的packet保存 IDNonce,RecordSeq
// encodeHandshakeMessage
//   Nonce:4字节序号,8字节随机 AuthData:src-id

// encodeRandom encodes a packet with random content.
// 编码普通数据包,返回数据包头和20字节的随机消息
// 生成长度12随机字节填充了Nonce
// 使用32字节本地节点的ID填充AuthData
// Codec.msgctbuf填充随机字符串
func (c *Codec) encodeRandom(toID enode.ID) (Header, []byte, error) {
	head := c.makeHeader(toID, flagMessage, 0)

	// Encode auth data.
	// AuthData是本地节点的id, 32字节
	auth := messageAuthData{SrcID: c.localnode.ID()}
	// 填充StaticHeader部分的Nonce
	if _, err := crand.Read(head.Nonce[:]); err != nil {
		return head, nil, fmt.Errorf("can't get random data: %v", err)
	}
	// 使用headbuf转换messageAuthData对象为字节数组保存到Header对象中
	c.headbuf.Reset()
	binary.Write(&c.headbuf, binary.BigEndian, auth)
	head.AuthData = c.headbuf.Bytes()

	// Fill message ciphertext buffer with random bytes.
	// 生成20字节的随机字符串保存到msgctbuf中
	c.msgctbuf = append(c.msgctbuf[:0], make([]byte, randomPacketMsgSize)...)
	crand.Read(c.msgctbuf)
	return head, c.msgctbuf, nil
}

// encodeWhoareyou encodes a WHOAREYOU packet.
// WHOAREYOU数据包的Nonce字段是之前对消息解密失败的包的Nonce,所以使用packet.Node填充Nonce
// 使用packet.IDNonce和packet.RecordSeq总共24字节填充AuthData
func (c *Codec) encodeWhoareyou(toID enode.ID, packet *Whoareyou) (Header, error) {
	// Sanity check node field to catch misbehaving callers.
	if packet.RecordSeq > 0 && packet.Node == nil {
		panic("BUG: missing node in whoareyou with non-zero seq")
	}

	// Create header.
	head := c.makeHeader(toID, flagWhoareyou, 0)
	head.AuthData = bytesCopy(&c.buf)
	head.Nonce = packet.Nonce

	// Encode auth data.
	auth := &whoareyouAuthData{
		IDNonce:   packet.IDNonce,
		RecordSeq: packet.RecordSeq,
	}
	c.headbuf.Reset()
	binary.Write(&c.headbuf, binary.BigEndian, auth)
	head.AuthData = c.headbuf.Bytes()
	return head, nil
}

// encodeHandshakeMessage encodes the handshake message packet header.
// 构造握手包的头部
// 除了返回Header对象外还返回session对象
func (c *Codec) encodeHandshakeHeader(toID enode.ID, addr string, challenge *Whoareyou) (Header, *session, error) {
	// Ensure calling code sets challenge.node.
	if challenge.Node == nil {
		panic("BUG: missing challenge.Node in encode")
	}

	// Generate new secrets.
	auth, session, err := c.makeHandshakeAuth(toID, addr, challenge)
	if err != nil {
		return Header{}, nil, err
	}

	// Generate nonce for message.
	// 生成4字节序号8字节随机的Nonce
	nonce, err := c.sc.nextNonce(session)
	if err != nil {
		return Header{}, nil, fmt.Errorf("can't generate nonce: %v", err)
	}

	// TODO: this should happen when the first authenticated message is received
	// 将会话保存下来
	c.sc.storeNewSession(toID, addr, session)

	// Encode the auth header.
	var (
		authsizeExtra = len(auth.pubkey) + len(auth.signature) + len(auth.record)
		head          = c.makeHeader(toID, flagHandshake, authsizeExtra)
	)
	c.headbuf.Reset()
	// 将handshakeAuthData编码成字节
	binary.Write(&c.headbuf, binary.BigEndian, &auth.h)
	c.headbuf.Write(auth.signature)
	c.headbuf.Write(auth.pubkey)
	c.headbuf.Write(auth.record)
	head.AuthData = c.headbuf.Bytes()
	head.Nonce = nonce
	return head, session, err
}

// encodeAuthHeader creates the auth header on a request packet following WHOAREYOU.
// 构造握手包的authData,返回session对象
// 首先填充src-id
// 然后填充pubkey,PubkeySize
// 然后填充signature,SigSize
// 然后WHOAREYOU中seq小于本地节点的话写入record
func (c *Codec) makeHandshakeAuth(toID enode.ID, addr string, challenge *Whoareyou) (*handshakeAuthData, *session, error) {
	auth := new(handshakeAuthData)
	auth.h.SrcID = c.localnode.ID()

	// Create the ephemeral key. This needs to be first because the
	// key is part of the ID nonce signature.
	var remotePubkey = new(ecdsa.PublicKey)
	if err := challenge.Node.Load((*enode.Secp256k1)(remotePubkey)); err != nil {
		return nil, nil, fmt.Errorf("can't find secp256k1 key for recipient")
	}
	// 生成临时私钥
	ephkey, err := c.sc.ephemeralKeyGen()
	if err != nil {
		return nil, nil, fmt.Errorf("can't generate ephemeral key")
	}
	// 设置authData的pubkey和pubkeysize
	ephpubkey := EncodePubkey(&ephkey.PublicKey)
	auth.pubkey = ephpubkey[:]
	auth.h.PubkeySize = byte(len(auth.pubkey))

	// Add ID nonce signature to response.
	// 接下来计算id-signature
	cdata := challenge.ChallengeData
	// 使用本地真正的私钥对挑战数据签名和本地临时公钥签名
	idsig, err := makeIDSignature(c.sha256, c.privkey, cdata, ephpubkey[:], toID)
	if err != nil {
		return nil, nil, fmt.Errorf("can't sign: %v", err)
	}
	auth.signature = idsig
	auth.h.SigSize = byte(len(auth.signature))

	// Add our record to response if it's newer than what remote side has.
	// 判断是否需要加入record
	ln := c.localnode.Node()
	if challenge.RecordSeq < ln.Seq() {
		auth.record, _ = rlp.EncodeToBytes(ln.Record())
	}

	// Create session keys.
	// 创建两个节点交流的会话对象,生成两者沟通的密钥
	sec := deriveKeys(sha256.New, ephkey, remotePubkey, c.localnode.ID(), challenge.Node.ID(), cdata)
	if sec == nil {
		return nil, nil, fmt.Errorf("key derivation failed")
	}
	return auth, sec, err
}

// encodeMessage encodes an encrypted message packet.
// 编码普通数据包的包头
// 先用makeHeader生成staticHeader除了Nonce的部分
// 再生成AuthData,和Nonce
func (c *Codec) encodeMessageHeader(toID enode.ID, s *session) (Header, error) {
	head := c.makeHeader(toID, flagMessage, 0)

	// Create the header.
	// 接下来填充Nonce和AuthData
	nonce, err := c.sc.nextNonce(s)
	if err != nil {
		return Header{}, fmt.Errorf("can't generate nonce: %v", err)
	}
	auth := messageAuthData{SrcID: c.localnode.ID()}
	c.buf.Reset()
	binary.Write(&c.buf, binary.BigEndian, &auth)
	head.AuthData = bytesCopy(&c.buf)
	head.Nonce = nonce
	return head, err
}

// 对消息加密,并返回加密后的消息
// msgbuf保存了明文,msgctbuf保存了密文
func (c *Codec) encryptMessage(s *session, p Packet, head *Header, headerData []byte) ([]byte, error) {
	// Encode message plaintext.
	// 生成消息的明文写入c.msgbuf,第一字节包类型,然后是Packet对象的rlp编码
	c.msgbuf.Reset()
	// 先写入消息的类型
	c.msgbuf.WriteByte(p.Kind())
	// 再写入消息的rlp编码
	if err := rlp.Encode(&c.msgbuf, p); err != nil {
		return nil, err
	}
	// 获取完整的消息明文
	messagePT := c.msgbuf.Bytes()

	// Encrypt into message ciphertext buffer.
	// 对消息明文进行加密获取消息的密文
	messageCT, err := encryptGCM(c.msgctbuf[:0], s.writeKey, head.Nonce[:], messagePT, headerData)
	if err == nil {
		// 密文保存到msgctbuf中
		c.msgctbuf = messageCT
	}
	// 返回密文
	return messageCT, err
}

// Decode decodes a discovery packet.
// addr是数据包的来源ip地址,input是要进行解码的数据包
// input最开始保存了IV,恢复前16字节到head中
// 利用IV和本地id解码头部信息,恢复静态部分到head中
// 继续解密恢复authData到head中
// 消息包利用msgData构造Packet对象,WHOAREYOU包构造Whoareyou类型的Packet对象
// 当解码的数据包是握手包时返回的enode.Node对象可能不是nil
func (c *Codec) Decode(input []byte, addr string) (src enode.ID, n *enode.Node, p Packet, err error) {
	// Unmask the static header.
	if len(input) < sizeofStaticPacketData {
		return enode.ID{}, nil, nil, errTooShort
	}
	var head Header
	// 恢复IV到head中
	copy(head.IV[:], input[:sizeofMaskingIV])
	mask := head.mask(c.localnode.ID())
	// 利用IV和本地id,解密23字节的静态头部啥数据
	staticHeader := input[sizeofMaskingIV:sizeofStaticPacketData]
	mask.XORKeyStream(staticHeader, staticHeader)

	// Decode and verify the static header.
	c.reader.Reset(staticHeader)
	// 恢复头部静态部分的数据
	binary.Read(&c.reader, binary.BigEndian, &head.StaticHeader)
	// 数据包剩下的部分还有authData和msgData
	remainingInput := len(input) - sizeofStaticPacketData
	// 检查一下剩下的部分是不是满足基本的要求
	if err := head.checkValid(remainingInput); err != nil {
		return enode.ID{}, nil, nil, err
	}

	// Unmask auth data.
	// 继续解密authData
	authDataEnd := sizeofStaticPacketData + int(head.AuthSize)
	authData := input[sizeofStaticPacketData:authDataEnd]
	mask.XORKeyStream(authData, authData)
	head.AuthData = authData

	// Delete timed-out handshakes. This must happen before decoding to avoid
	// processing the same handshake twice.
	c.sc.handshakeGC()

	// Decode auth part and message.
	// 解密剩余的消息,恢复成Packet对象
	headerData := input[:authDataEnd]
	msgData := input[authDataEnd:]
	switch head.Flag {
	case flagWhoareyou:
		p, err = c.decodeWhoareyou(&head, headerData)
	case flagHandshake:
		n, p, err = c.decodeHandshakeMessage(addr, &head, headerData, msgData)
	case flagMessage:
		p, err = c.decodeMessage(addr, &head, headerData, msgData)
	default:
		err = errInvalidFlag
	}
	return head.src, n, p, err
}

// decodeWhoareyou reads packet data after the header as a WHOAREYOU packet.
// 解码WHOAREYOU数据包,WHOAREYOU中没有消息,所以解码成Whoareyou对象
func (c *Codec) decodeWhoareyou(head *Header, headerData []byte) (Packet, error) {
	if len(head.AuthData) != sizeofWhoareyouAuthData {
		return nil, fmt.Errorf("invalid auth size %d for WHOAREYOU", len(head.AuthData))
	}
	// 从head中解析出来whoareyouAuthData
	var auth whoareyouAuthData
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth)
	p := &Whoareyou{
		Nonce:         head.Nonce,
		IDNonce:       auth.IDNonce,
		RecordSeq:     auth.RecordSeq,
		// 将整个数据包头的数据视作ChallengeData
		ChallengeData: make([]byte, len(headerData)),
	}
	copy(p.ChallengeData, headerData)
	return p, nil
}

func (c *Codec) decodeHandshakeMessage(fromAddr string, head *Header, headerData, msgData []byte) (n *enode.Node, p Packet, err error) {
	node, auth, session, err := c.decodeHandshake(fromAddr, head)
	if err != nil {
		c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
		return nil, nil, err
	}

	// Decrypt the message using the new session keys.
	msg, err := c.decryptMessage(msgData, head.Nonce[:], headerData, session.readKey)
	if err != nil {
		c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
		return node, msg, err
	}

	// Handshake OK, drop the challenge and store the new session keys.
	c.sc.storeNewSession(auth.h.SrcID, fromAddr, session)
	c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
	return node, msg, nil
}

func (c *Codec) decodeHandshake(fromAddr string, head *Header) (n *enode.Node, auth handshakeAuthData, s *session, err error) {
	// 恢复出来handshakeAuthData对象
	if auth, err = c.decodeHandshakeAuthData(head); err != nil {
		return nil, auth, nil, err
	}

	// Verify against our last WHOAREYOU.
	// 接下来要验证握手包中的签名信息是否正确
	// 从本地读取之前发送WHOAREYOU包时保存的与这个对应的挑战信息
	challenge := c.sc.getHandshake(auth.h.SrcID, fromAddr)
	if challenge == nil {
		return nil, auth, nil, errUnexpectedHandshake
	}
	// Get node record.
	// 获取对方节点的Node对象,challenge.Node可能保存了最新的结果,也可能从握手包中发来的新结果
	n, err = c.decodeHandshakeRecord(challenge.Node, auth.h.SrcID, auth.record)
	if err != nil {
		return nil, auth, nil, err
	}
	// Verify ID nonce signature.
	sig := auth.signature
	cdata := challenge.ChallengeData
	// 验证对方节点n是否使用自己的私钥对挑战数据进行了签名
	// 这个私钥是节点A的的私钥,不是为了会话生成的临时私钥
	err = verifyIDSignature(c.sha256, sig, n, cdata, auth.pubkey, c.localnode.ID())
	if err != nil {
		return nil, auth, nil, err
	}
	// Verify ephemeral key is on curve.
	ephkey, err := DecodePubkey(c.privkey.Curve, auth.pubkey)
	if err != nil {
		return nil, auth, nil, errInvalidAuthKey
	}
	// Derive sesssion keys.
	// 生成接下来沟通使用的对称加密的密钥,注意输入的节点ID必须是AID和BID
	// 参考makeHandshakeAuth函数的结束位置调用deriveKeys,那里传入的节点ID与这里相反
	// 本地和远程writeKey和readKey应该反过来
	// 所以这里session使用keysFlipped交换writeKey和readKey
	session := deriveKeys(sha256.New, c.privkey, ephkey, auth.h.SrcID, c.localnode.ID(), cdata)
	session = session.keysFlipped()
	return n, auth, session, nil
}

// decodeHandshakeAuthData reads the authdata section of a handshake packet.
// 从head.AuthData中恢复出来握手包的handshakeAuthData对象
func (c *Codec) decodeHandshakeAuthData(head *Header) (auth handshakeAuthData, err error) {
	// Decode fixed size part.
	if len(head.AuthData) < sizeofHandshakeAuthData {
		return auth, fmt.Errorf("header authsize %d too low for handshake", head.AuthSize)
	}
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth.h)
	head.src = auth.h.SrcID

	// Decode variable-size part.
	var (
		vardata       = head.AuthData[sizeofHandshakeAuthData:]
		sigAndKeySize = int(auth.h.SigSize) + int(auth.h.PubkeySize)
		keyOffset     = int(auth.h.SigSize)
		recOffset     = keyOffset + int(auth.h.PubkeySize)
	)
	if len(vardata) < sigAndKeySize {
		return auth, errTooShort
	}
	auth.signature = vardata[:keyOffset]
	auth.pubkey = vardata[keyOffset:recOffset]
	auth.record = vardata[recOffset:]
	return auth, nil
}

// decodeHandshakeRecord verifies the node record contained in a handshake packet. The
// remote node should include the record if we don't have one or if ours is older than the
// latest sequence number.
// 获取最新的远程节点记录
// local代表本地保存的记录,wantID代表握手包的来源节点id,remote代表远程节点发送的记录
// 需要验证remote是否被wantID签名,如果验证通过且记录更新就返回远程的记录
func (c *Codec) decodeHandshakeRecord(local *enode.Node, wantID enode.ID, remote []byte) (*enode.Node, error) {
	node := local
	if len(remote) > 0 {
		var record enr.Record
		if err := rlp.DecodeBytes(remote, &record); err != nil {
			return nil, err
		}
		if local == nil || local.Seq() < record.Seq() {
			// 首先解析remote为合法的Node对象
			// 说明remote中的数据签名通过,但是这条记录的签名者不一定是远程节点
			n, err := enode.New(enode.ValidSchemes, &record)
			if err != nil {
				return nil, fmt.Errorf("invalid node record: %v", err)
			}
			// 验证ID与远程节点的ID匹配
			if n.ID() != wantID {
				return nil, fmt.Errorf("record in handshake has wrong ID: %v", n.ID())
			}
			// 使用远程节点的记录
			node = n
		}
	}
	if node == nil {
		return nil, errNoRecord
	}
	return node, nil
}

// decodeMessage reads packet data following the header as an ordinary message packet.
// decodeHandshakeMessage和decodeMessage分别用来解密握手包和普通包内的消息
// 要解密普通包的消息,解密需要的密钥已经在session中保存了,读取后直接解密
// 将加密的msgData解密为Packet对象
func (c *Codec) decodeMessage(fromAddr string, head *Header, headerData, msgData []byte) (Packet, error) {
	if len(head.AuthData) != sizeofMessageAuthData {
		return nil, fmt.Errorf("invalid auth size %d for message packet", len(head.AuthData))
	}
	var auth messageAuthData
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth)
	head.src = auth.SrcID

	// Try decrypting the message.
	// 从session的缓存中得到解密消息的密钥
	key := c.sc.readKey(auth.SrcID, fromAddr)
	// 解密消息的内容
	msg, err := c.decryptMessage(msgData, head.Nonce[:], headerData, key)
	// 如果解密失败了,接下来需要开始执行握手过程
	if err == errMessageDecrypt {
		// It didn't work. Start the handshake since this is an ordinary message packet.
		return &Unknown{Nonce: head.Nonce}, nil
	}
	return msg, err
}

// 将消息的加密字节流解密到Packet对象
// input是加密的内容
// nonce是在包头保存的随机数
// headerData是整个头部,作为aes-gcm解密时的额外信息
func (c *Codec) decryptMessage(input, nonce, headerData, readKey []byte) (Packet, error) {
	// input是加密的消息内容,解密input
	msgdata, err := decryptGCM(readKey, nonce, input, headerData)
	if err != nil {
		return nil, errMessageDecrypt
	}
	if len(msgdata) == 0 {
		return nil, errMessageTooShort
	}
	// msgdata[0]是消息类型,msgdata[1:]是消息的rlp编码
	return DecodeMessage(msgdata[0], msgdata[1:])
}

// checkValid performs some basic validity checks on the header.
// The packetLen here is the length remaining after the static header.
// 检查一些基本信息
//   检查ProtocolID是不是discv5
//   检查Version是不是1
//   剩余内容长度是否大于最小值
//   检查AuthSize是否大于剩余内容长度
func (h *StaticHeader) checkValid(packetLen int) error {
	if h.ProtocolID != protocolID {
		return errInvalidHeader
	}
	// 当前的版本是1,不能小于1
	if h.Version < minVersion {
		return errMinVersion
	}
	if h.Flag != flagWhoareyou && packetLen < minMessageSize {
		return errMsgTooShort
	}
	if int(h.AuthSize) > packetLen {
		return errAuthSize
	}
	return nil
}

// headerMask returns a cipher for 'masking' / 'unmasking' packet headers.
// 生成Header的加密器,用来头部中加密IV后的内容
// AES-CTR模式加密需要密钥和IV
//   密钥使用输入的目的节点ID的前16字节,IV保存在Header对象中
func (h *Header) mask(destID enode.ID) cipher.Stream {
	block, err := aes.NewCipher(destID[:16])
	if err != nil {
		panic("can't create cipher")
	}
	return cipher.NewCTR(block, h.IV[:])
}

// 复制一份Buffer中的内容为字节数组
func bytesCopy(r *bytes.Buffer) []byte {
	b := make([]byte, r.Len())
	copy(b, r.Bytes())
	return b
}
