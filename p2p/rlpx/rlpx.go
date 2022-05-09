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

// Package rlpx implements the RLPx transport protocol.
package rlpx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/crypto/ecies"
	"github.com/Evolution404/simcore/rlp"
	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"
)

// Conn is an RLPx network connection. It wraps a low-level network connection. The
// underlying connection should not be used for other activity when it is wrapped by Conn.
//
// Before sending messages, a handshake must be performed by calling the Handshake method.
// This type is not generally safe for concurrent use, but reading and writing of messages
// may happen concurrently after the handshake.
// Conn代表了基于RLPx协议的网络连接
// 内部封装了net.Conn对象实现真正的传输层通信
type Conn struct {
	// diaDest代表远程节点的公钥
	dialDest *ecdsa.PublicKey
	conn     net.Conn
	session  *sessionState

	// These are the buffers for snappy compression.
	// Compression is enabled if they are non-nil.
	snappyReadBuffer  []byte
	snappyWriteBuffer []byte
}

// sessionState contains the session keys.
type sessionState struct {
	// 用于加密发送的消息的aes ctr模式的流
	enc cipher.Stream
	// 用于解密接收的消息的aes ctr模式的流
	dec cipher.Stream

	// 用于验证接收到的消息
	egressMAC hashMAC
	// 用于为发送的内容生成消息验证码
	ingressMAC hashMAC
	rbuf       readBuffer
	wbuf       writeBuffer
}

// hashMAC holds the state of the RLPx v4 MAC contraption.
type hashMAC struct {
  // 指定了MAC密钥的底层块加/解密器
	cipher     cipher.Block
	hash       hash.Hash
	aesBuffer  [16]byte
	hashBuffer [32]byte
	seedBuffer [32]byte
}

func newHashMAC(cipher cipher.Block, h hash.Hash) hashMAC {
	m := hashMAC{cipher: cipher, hash: h}
	if cipher.BlockSize() != len(m.aesBuffer) {
		panic(fmt.Errorf("invalid MAC cipher block size %d", cipher.BlockSize()))
	}
	if h.Size() != len(m.hashBuffer) {
		panic(fmt.Errorf("invalid MAC digest size %d", h.Size()))
	}
	return m
}

// NewConn wraps the given network connection. If dialDest is non-nil, the connection
// behaves as the initiator during the handshake.
// dialDest不为nil说明本地是握手的发起方
// dialDest是nil说明本地是握手的接收方
func NewConn(conn net.Conn, dialDest *ecdsa.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

// SetSnappy enables or disables snappy compression of messages. This is usually called
// after the devp2p Hello message exchange when the negotiated version indicates that
// compression is available on both ends of the connection.
// 用于设置此连接上是否启用数据压缩
func (c *Conn) SetSnappy(snappy bool) {
	if snappy {
		c.snappyReadBuffer = []byte{}
		c.snappyWriteBuffer = []byte{}
	} else {
		c.snappyReadBuffer = nil
		c.snappyWriteBuffer = nil
	}
}

// SetReadDeadline sets the deadline for all future read operations.
// 超过指定时间后不能再Read
func (c *Conn) SetReadDeadline(time time.Time) error {
	return c.conn.SetReadDeadline(time)
}

// SetWriteDeadline sets the deadline for all future write operations.
// 超过指定时间后不能再Write
func (c *Conn) SetWriteDeadline(time time.Time) error {
	return c.conn.SetWriteDeadline(time)
}

// SetDeadline sets the deadline for all future read and write operations.
// 超过指定时间后不能再Read和Write
func (c *Conn) SetDeadline(time time.Time) error {
	return c.conn.SetDeadline(time)
}

// Read reads a message from the connection.
// The returned data buffer is valid until the next call to Read.
// 通过网络读取一个消息,获取code和消息内的数据
// 从链路中读取一个帧,返回code和真实的数据,以及通过链路传输的数据的长度
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	if c.session == nil {
		panic("can't ReadMsg before handshake")
	}

	frame, err := c.session.readFrame(c.conn)
	if err != nil {
		return 0, nil, 0, err
	}
	// 帧数据是code和data两个部分
	code, data, err = rlp.SplitUint64(frame)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("invalid message code: %v", err)
	}
	// 代表通过网络传输的数据
	wireSize = len(data)

	// If snappy is enabled, verify and decompress message.
	// 如果启用了压缩,就将获取的数据进行解压
	if c.snappyReadBuffer != nil {
		var actualSize int
		actualSize, err = snappy.DecodedLen(data)
		if err != nil {
			return code, nil, 0, err
		}
		if actualSize > maxUint24 {
			return code, nil, 0, errPlainMessageTooLarge
		}
		c.snappyReadBuffer = growslice(c.snappyReadBuffer, actualSize)
		data, err = snappy.Decode(c.snappyReadBuffer, data)
	}
	return code, data, wireSize, err
}

// 从网络中读取并解析一帧信息，帧结构如下
// frame = header-ciphertext(16字节) || header-mac(16字节) || frame-data-ciphertext || frame-mac(16字节)
// header-ciphertext = aes(aes-secret, header)
// header = frame-size || 固定的3字节zeroHeader || 补齐至16字节
// frame-ciphertext = aes(aes-secret, frame-data || 补齐至16字节倍数)
func (h *sessionState) readFrame(conn io.Reader) ([]byte, error) {
	h.rbuf.reset()

	// Read the frame header.
  // 读取header-ciphertext以及header-mac
  // 两个16字节总共32字节
	header, err := h.rbuf.read(conn, 32)
	if err != nil {
		return nil, err
	}

	// Verify header MAC.
  // 校验header-mac
	wantHeaderMAC := h.ingressMAC.computeHeader(header[:16])
	if !hmac.Equal(wantHeaderMAC, header[16:]) {
		return nil, errors.New("bad header MAC")
	}

	// Decrypt the frame header to get the frame size.
  // 解密头信息
	h.dec.XORKeyStream(header[:16], header[:16])
  // 头信息的前3字节代表后面frame的长度
	fsize := readUint24(header[:16])
	// Frame size rounded up to 16 byte boundary for padding.
  // frame的长度是16字节的倍数，补齐缺少的长度
	rsize := fsize
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}

	// Read the frame content.
  // 读取frame-content
	frame, err := h.rbuf.read(conn, int(rsize))
	if err != nil {
		return nil, err
	}

	// Validate frame MAC.
  // 再读取16字节frame-mac并进行校验
	frameMAC, err := h.rbuf.read(conn, 16)
	if err != nil {
		return nil, err
	}
	wantFrameMAC := h.ingressMAC.computeFrame(frame)
	if !hmac.Equal(wantFrameMAC, frameMAC) {
		return nil, errors.New("bad frame MAC")
	}

	// Decrypt the frame data.
  // 解密帧内容
	h.dec.XORKeyStream(frame, frame)
  // 返回帧内容，去除后面补的零
	return frame[:fsize], nil
}

// Write writes a message to the connection.
//
// Write returns the written size of the message data. This may be less than or equal to
// len(data) depending on whether snappy compression is enabled.
// 通过网络发送一个消息,指定code和数据
// 返回进行网络传输的数据长度,不使用压缩时就等于data的长度,压缩的话可能小于data的长度
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	if c.session == nil {
		panic("can't WriteMsg before handshake")
	}
	if len(data) > maxUint24 {
		return 0, errPlainMessageTooLarge
	}
	if c.snappyWriteBuffer != nil {
		// Ensure the buffer has sufficient size.
		// Package snappy will allocate its own buffer if the provided
		// one is smaller than MaxEncodedLen.
		c.snappyWriteBuffer = growslice(c.snappyWriteBuffer, snappy.MaxEncodedLen(len(data)))
		data = snappy.Encode(c.snappyWriteBuffer, data)
	}

	wireSize := uint32(len(data))
	err := c.session.writeFrame(c.conn, code, data)
	return wireSize, err
}

// 将输入的数据封装成帧写入到conn中
// 帧分为四个部分,这四个部分长度都是16字节的整数倍,对于header和frame-data都是不足16字节进行补零
// frame = header-ciphertext(16字节) || header-mac(16字节) || frame-data-ciphertext || frame-mac(16字节)
// header-ciphertext = aes(aes-secret, header)
// header = frame-size || 固定的3字节zeroHeader || 补齐至16字节
// frame-ciphertext = aes(aes-secret, frame-data || 补齐至16字节倍数)
func (h *sessionState) writeFrame(conn io.Writer, code uint64, data []byte) error {
	h.wbuf.reset()

	// Write header.
	fsize := rlp.IntSize(code) + len(data)
	if fsize > maxUint24 {
		return errPlainMessageTooLarge
	}
	// 生成一个16字节的空间用来保存header
	header := h.wbuf.appendZero(16)
	putUint24(uint32(fsize), header)
	copy(header[3:], zeroHeader)
  // 加密header
	h.enc.XORKeyStream(header, header)

	// Write header MAC.
  // 计算并写入header-mac
	h.wbuf.Write(h.egressMAC.computeHeader(header))

	// Encode and encrypt the frame data.
	offset := len(h.wbuf.data)
	h.wbuf.data = rlp.AppendUint64(h.wbuf.data, code)
	h.wbuf.Write(data)
	if padding := fsize % 16; padding > 0 {
		h.wbuf.appendZero(16 - padding)
	}
	framedata := h.wbuf.data[offset:]
	h.enc.XORKeyStream(framedata, framedata)

	// Write frame MAC.
	h.wbuf.Write(h.egressMAC.computeFrame(framedata))

	_, err := conn.Write(h.wbuf.data)
	return err
}

// computeHeader computes the MAC of a frame header.
// 输入header-ciphertext计算MAC
// 1. 计算当前状态哈希
// 2. 将16字节的头数据作为种子
func (m *hashMAC) computeHeader(header []byte) []byte {
	sum1 := m.hash.Sum(m.hashBuffer[:0])
	return m.compute(sum1, header)
}

// computeFrame computes the MAC of framedata.
// 输入frame-ciphertext计算MAC
// 1. 将帧数据写入当前哈希状态
// 2. 计算写入帧数据后的哈希
// 3. 将当前哈希前16字节作为种子
func (m *hashMAC) computeFrame(framedata []byte) []byte {
	m.hash.Write(framedata)
	seed := m.hash.Sum(m.seedBuffer[:0])
	return m.compute(seed, seed[:16])
}

// compute computes the MAC of a 16-byte 'seed'.
//
// To do this, it encrypts the current value of the hash state, then XORs the ciphertext
// with seed. The obtained value is written back into the hash state and hash output is
// taken again. The first 16 bytes of the resulting sum are the MAC value.
//
// This MAC construction is a horrible, legacy thing.
// 利用当前哈希和种子来计算MAC
// 1. 利用MAC密钥加密当前哈希
// 2. 将加密哈希与种子异或
// 3. 将异或结果写入哈希状态
// 4. 重新计算哈希，取前16字节作为MAC
func (m *hashMAC) compute(sum1, seed []byte) []byte {
	if len(seed) != len(m.aesBuffer) {
		panic("invalid MAC seed")
	}

	m.cipher.Encrypt(m.aesBuffer[:], sum1)
	for i := range m.aesBuffer {
		m.aesBuffer[i] ^= seed[i]
	}
	m.hash.Write(m.aesBuffer[:])
	sum2 := m.hash.Sum(m.hashBuffer[:0])
	return sum2[:16]
}

// Handshake performs the handshake. This must be called before any data is written
// or read from the connection.
// 利用本地私钥开始执行握手过程，返回远程节点的临时公钥
// 握手过程应该在传输任何数据之前，也就是NewConn后立刻执行Handshake
func (c *Conn) Handshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	var (
		sec Secrets
		err error
		h   handshakeState
	)
	// 区分是握手的发起方还是接收方
	if c.dialDest != nil {
		sec, err = h.runInitiator(c.conn, prv, c.dialDest)
	} else {
		sec, err = h.runRecipient(c.conn, prv)
	}
	if err != nil {
		return nil, err
	}
	// 设置c.handshake
	c.InitWithSecrets(sec)
	c.session.rbuf = h.rbuf
	c.session.wbuf = h.wbuf
	return sec.remote, err
}

// InitWithSecrets injects connection secrets as if a handshake had
// been performed. This cannot be called after the handshake.
// 用于模拟握手完成,不执行真正的握手过程,直接需要握手过程共享的秘密保存到Conn中
// 就是用Secrets对象生成handshakeState对象
func (c *Conn) InitWithSecrets(sec Secrets) {
	if c.session != nil {
		panic("can't handshake twice")
	}
	// 利用MAC和ENC的密钥，分别创建针对MAC和ENC过程的底层块加/解密器
	macc, err := aes.NewCipher(sec.MAC)
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	encc, err := aes.NewCipher(sec.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	// 使用的IV是16字节的全零数组,因为每次通信的密钥都不同所以IV可以一样
	iv := make([]byte, encc.BlockSize())
	c.session = &sessionState{
		// 基于底层块加/解密器，创建CTR模式的加/解密器
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		egressMAC:  newHashMAC(macc, sec.EgressMAC),
		ingressMAC: newHashMAC(macc, sec.IngressMAC),
	}
}

// Close closes the underlying network connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Constants for the handshake.
const (
	sskLen = 16                     // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = crypto.SignatureLength // elliptic S256
	pubLen = 64                     // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32                     // hash length (for nonce etc)

	// 使用椭圆曲线加密后密文相比明文增加的长度
	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */
)

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	zeroHeader = []byte{0xC2, 0x80, 0x80}

	// errPlainMessageTooLarge is returned if a decompressed message length exceeds
	// the allowed 24 bits (i.e. length >= 16MB).
	errPlainMessageTooLarge = errors.New("message length >= 16MB")
)

// Secrets represents the connection secrets which are negotiated during the handshake.
// Secrets是握手的成果，用于后续消息发送的对称加密
type Secrets struct {
	// AES和MAC长度都是32字节,作为AES-256算法的密钥
	AES, MAC              []byte
	EgressMAC, IngressMAC hash.Hash
	// 保存远程节点的公钥
	remote *ecdsa.PublicKey
}

// handshakeState contains the state of the encryption handshake.
// 代表握手过程的状态
type handshakeState struct {
	// 标记本地是连接的发起方还是接收方
	initiator bool
	// remote代表远程节点的公钥
	remote *ecies.PublicKey // remote-pubk
	// initNonce: 发送方生成的随机nonce
	// respNonce: 接收方生成的随机nonce
	initNonce, respNonce []byte // nonce
	// 握手过程中双方都成一对随机的公私钥
	// 本地保存自己随机生成的私钥,通过握手能得到远程节点随机生成的公钥
	randomPrivKey   *ecies.PrivateKey // ecdhe-random
	remoteRandomPub *ecies.PublicKey  // ecdhe-random-pubk

	rbuf readBuffer
	wbuf writeBuffer
}

// RLPx v4 handshake auth (defined in EIP-8).
// 握手过程中总共发送两条消息,分别是发起方发送auth包和接收方接收后回复ack包
// auth包对应了authMsgV4对象,ack包对应authRespV4对象

// 用于描述auth包
type authMsgV4 struct {
	// 双方的静态公私钥可以推导出共享秘密token
	// 使用发送方生成的随机私钥对 Nonce与token 的异或结果进行签名
	// 接收方有Nonce和token可以推导出发送方的随机公钥
	Signature [sigLen]byte
	// 发送方的静态公钥
	InitiatorPubkey [pubLen]byte
	// 发送authMsg生成的随机数
	Nonce [shaLen]byte
	// 当前一定是4
	Version uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
// 用于描述ack包
type authRespV4 struct {
	// 接收方生成的随机公钥
	RandomPubkey [pubLen]byte
	// 接收方生成的随机Nonce
	Nonce [shaLen]byte
	// 当前一定是4
	Version uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// runRecipient negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.
// 接收方接收auth包并发送ack包的函数
func (h *handshakeState) runRecipient(conn io.ReadWriter, prv *ecdsa.PrivateKey) (s Secrets, err error) {
	// 从网络字节流中解析出来authMsg对象,authPacket代表authMsg的rlp编码
	authMsg := new(authMsgV4)
	authPacket, err := h.readMsg(authMsg, prv, conn)
	if err != nil {
		return s, err
	}
	if err := h.handleAuthMsg(authMsg, prv); err != nil {
		return s, err
	}

	// 接收方收到authMsg后开始发送authResp
	authRespMsg, err := h.makeAuthResp()
	if err != nil {
		return s, err
	}
	authRespPacket, err := h.sealEIP8(authRespMsg)
	if err != nil {
		return s, err
	}
	// 将数据发送给发送方
	if _, err = conn.Write(authRespPacket); err != nil {
		return s, err
	}

	return h.secrets(authPacket, authRespPacket)
}

// 接收方处理auth包的函数
func (h *handshakeState) handleAuthMsg(msg *authMsgV4, prv *ecdsa.PrivateKey) error {
	// Import the remote identity.
	rpub, err := importPublicKey(msg.InitiatorPubkey[:])
	if err != nil {
		return err
	}
	h.initNonce = msg.Nonce[:]
	h.remote = rpub

	// Generate random keypair for ECDH.
	// If a private key is already set, use it instead of generating one (for testing).
	// 生成接收方的随机私钥
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
		if err != nil {
			return err
		}
	}

	// Check the signature.
	// 利用签名信息恢复出来发送方的临时公钥
	// 首先生成共享秘密token
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return err
	}
	// 计算被签名的信息：token与nonce异或
	signedMsg := xor(token, h.initNonce)
	// 使用被签名的信息和签名恢复出来发送方的临时公钥
	remoteRandomPub, err := crypto.Ecrecover(signedMsg, msg.Signature[:])
	if err != nil {
		return err
	}
	h.remoteRandomPub, _ = importPublicKey(remoteRandomPub)
	return nil
}

// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.
// 利用握手过程中发送的两个数据包构建出Secrets对象
func (h *handshakeState) secrets(auth, authResp []byte) (Secrets, error) {
	// 计算临时共享秘密
	ecdheSecret, err := h.randomPrivKey.GenerateShared(h.remoteRandomPub, sskLen, sskLen)
	if err != nil {
		return Secrets{}, err
	}

	// derive base secrets from ephemeral key agreement
	// 利用临时共享秘密以及发送方和接收方生成的随机nonce生成AES和MAC使用的密钥
	sharedSecret := crypto.Keccak256(ecdheSecret, crypto.Keccak256(h.respNonce, h.initNonce))
	aesSecret := crypto.Keccak256(ecdheSecret, sharedSecret)
	s := Secrets{
		remote: h.remote.ExportECDSA(),
		AES:    aesSecret,
		MAC:    crypto.Keccak256(ecdheSecret, aesSecret),
	}

	// setup sha3 instances for the MACs
  // 初始化发送方和接收方的MAC计算流
	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce))
	mac1.Write(auth)
	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce))
	mac2.Write(authResp)
	// 发送方和接收方的egress和ingress正好相反
	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2
	} else {
		s.EgressMAC, s.IngressMAC = mac2, mac1
	}

	return s, nil
}

// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.
// 利用本地私钥和远程节点公钥计算出来共享秘密
func (h *handshakeState) staticSharedSecret(prv *ecdsa.PrivateKey) ([]byte, error) {
	return ecies.ImportECDSA(prv).GenerateShared(h.remote, sskLen, sskLen)
}

// runInitiator negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.
// 发送方发送auth包并接收ack包的函数
func (h *handshakeState) runInitiator(conn io.ReadWriter, prv *ecdsa.PrivateKey, remote *ecdsa.PublicKey) (s Secrets, err error) {
	h.initiator = true
	h.remote = ecies.ImportECDSAPublic(remote)
	authMsg, err := h.makeAuthMsg(prv)
	if err != nil {
		return s, err
	}
	// 对authMsg对象进行编码
	authPacket, err := h.sealEIP8(authMsg)
	if err != nil {
		return s, err
	}

	// 将数据发送出去
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}

	authRespMsg := new(authRespV4)
	authRespPacket, err := h.readMsg(authRespMsg, prv, conn)
	if err != nil {
		return s, err
	}
	if err := h.handleAuthResp(authRespMsg); err != nil {
		return s, err
	}

	return h.secrets(authPacket, authRespPacket)
}

// makeAuthMsg creates the initiator handshake message.
// 创建消息发起方的握手信息
// 发起方生成了initNonce
func (h *handshakeState) makeAuthMsg(prv *ecdsa.PrivateKey) (*authMsgV4, error) {
	// Generate random initiator nonce.
	// 生成随机的initNonce
	h.initNonce = make([]byte, shaLen)
	_, err := rand.Read(h.initNonce)
	if err != nil {
		return nil, err
	}
	// Generate random keypair to for ECDH.
	// 生成临时随机私钥
	h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, err
	}

	// Sign known message: static-shared-secret ^ nonce
	// 利用本地的静态私钥和对方的静态公钥计算双方共享的秘密token
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return nil, err
	}
	// 将共享秘密token与生成的随机数异或,得到signed
	signed := xor(token, h.initNonce)
	// 使用本地的随机私钥对signed签名
	signature, err := crypto.Sign(signed, h.randomPrivKey.ExportECDSA())
	if err != nil {
		return nil, err
	}

	// 构造authMsg
	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)
	copy(msg.InitiatorPubkey[:], crypto.FromECDSAPub(&prv.PublicKey)[1:])
	copy(msg.Nonce[:], h.initNonce)
	msg.Version = 4
	return msg, nil
}

func (h *handshakeState) handleAuthResp(msg *authRespV4) (err error) {
	h.respNonce = msg.Nonce[:]
	h.remoteRandomPub, err = importPublicKey(msg.RandomPubkey[:])
	return err
}

// 构造authRespV4对象
// 生成随机的Nonce,利用handleAuthMsg生成的随机私钥导出公钥保存的msg中
func (h *handshakeState) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce.
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)
	copy(msg.RandomPubkey[:], exportPubkey(&h.randomPrivKey.PublicKey))
	msg.Version = 4
	return msg, nil
}

// readMsg reads an encrypted handshake message, decoding it into msg.
// 从r中读取包内容，并解码到msg对象中
// msg对象可以是authMsgV4或者authRespV4类型
func (h *handshakeState) readMsg(msg interface{}, prv *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {
	h.rbuf.reset()
	h.rbuf.grow(512)

	// Read the size prefix.
	// auth包和ack包的最开始两字节代表后面加密数据的长度
	prefix, err := h.rbuf.read(r, 2)
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(prefix)

	// Read the handshake packet.
	packet, err := h.rbuf.read(r, int(size))
	if err != nil {
		return nil, err
	}
	dec, err := ecies.ImportECDSA(prv).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, err
	}
	// Can't use rlp.DecodeBytes here because it rejects
	// trailing data (forward-compatibility).
	s := rlp.NewStream(bytes.NewReader(dec), 0)
	err = s.Decode(msg)
	return h.rbuf.data[:len(prefix)+len(packet)], err
}

// sealEIP8 encrypts a handshake message.
// 将握手包对象转换成RLP编码，然后利用远程节点公钥进行加密
func (h *handshakeState) sealEIP8(msg interface{}) ([]byte, error) {
	h.wbuf.reset()

	// Write the message plaintext.
  // 消息对象编码成RLP编码
	if err := rlp.Encode(&h.wbuf, msg); err != nil {
		return nil, err
	}
	// Pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
  // 往RLP编码后面填充100-200个随机0字节
	h.wbuf.appendZero(mrand.Intn(100) + 100)

  // 握手数据包前两字节保存后面加密数据的长度
	prefix := make([]byte, 2)
  // 加密数据长度=原始数据长度+非对称加密额外增加的长度
	binary.BigEndian.PutUint16(prefix, uint16(len(h.wbuf.data)+eciesOverhead))

  // 使用远程节点公钥进行非对称加密
	enc, err := ecies.Encrypt(rand.Reader, h.remote, h.wbuf.data, nil, prefix)
	return append(prefix, enc...), err
}

// importPublicKey unmarshals 512 bit public keys.
// 通过字节数组恢复出来公钥
// 输入的公钥有可能有两种形式: 65字节, 64字节(去掉04前缀)
func importPublicKey(pubKey []byte) (*ecies.PublicKey, error) {
	var pubKey65 []byte
	switch len(pubKey) {
	case 64:
		// add 'uncompressed key' flag
		pubKey65 = append([]byte{0x04}, pubKey...)
	case 65:
		pubKey65 = pubKey
	default:
		return nil, fmt.Errorf("invalid public key length %v (expect 64/65)", len(pubKey))
	}
	// TODO: fewer pointless conversions
	pub, err := crypto.UnmarshalPubkey(pubKey65)
	if err != nil {
		return nil, err
	}
	return ecies.ImportECDSAPublic(pub), nil
}

// 编码公钥到字节数组
func exportPubkey(pub *ecies.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)[1:]
}

// 计算one与other异或的结果,返回结果的长度是one的长度
func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}
