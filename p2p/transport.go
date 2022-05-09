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

package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/common/bitutil"
	"github.com/Evolution404/simcore/metrics"
	"github.com/Evolution404/simcore/p2p/rlpx"
	"github.com/Evolution404/simcore/rlp"
)

const (
	// total timeout for encryption handshake and protocol
	// handshake in both directions.
	// 整个握手过程持续的时间不能超过5秒
	handshakeTimeout = 5 * time.Second

	// This is the timeout for sending the disconnect reason.
	// This is shorter than the usual timeout because we don't want
	// to wait if the connection is known to be bad anyway.
	discWriteTimeout = 1 * time.Second
)

// rlpxTransport is the transport used by actual (non-test) connections.
// It wraps an RLPx connection with locks and read/write deadlines.
// 实现了transport接口
// 需要实现消息读写器的两个方法，以及加密握手和协议握手
type rlpxTransport struct {
	rmu, wmu sync.Mutex
	// 用于缓存即将发送的消息
	wbuf bytes.Buffer
	// 代表与远程节点建立的加密连接
	conn *rlpx.Conn
}

// 创建一个rlpxTransport对象,并返回transport接口
// 将输入的底层网络连接(net.Conn)封装为rlpx.Conn对象
// 需要提供与远程节点建立的连接以及对方节点的公钥,公钥可以是nil
func newRLPX(conn net.Conn, dialDest *ecdsa.PublicKey) transport {
	return &rlpxTransport{conn: rlpx.NewConn(conn, dialDest)}
}

// 通过rlpxTransport.conn.Read获取网络中的数据
// 构造Msg对象并返回
func (t *rlpxTransport) ReadMsg() (Msg, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()

	var msg Msg
	t.conn.SetReadDeadline(time.Now().Add(frameReadTimeout))
	// 接收rlpx加密链路上的一条消息
	code, data, wireSize, err := t.conn.Read()
	if err == nil {
		// Protocol messages are dispatched to subprotocol handlers asynchronously,
		// but package rlpx may reuse the returned 'data' buffer on the next call
		// to Read. Copy the message data to avoid this being an issue.
		// 将读取到的字节内容封装成Msg对象
		data = common.CopyBytes(data)
		msg = Msg{
			ReceivedAt: time.Now(),
			Code:       code,
			Size:       uint32(len(data)),
			meterSize:  uint32(wireSize),
			Payload:    bytes.NewReader(data),
		}
	}
	return msg, err
}

// 通过rlpxTransport.conn.Write将消息发送出去
func (t *rlpxTransport) WriteMsg(msg Msg) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	// Copy message data to write buffer.
	// 首先将要发送的消息拷贝到t.wbuf中
	t.wbuf.Reset()
	if _, err := io.CopyN(&t.wbuf, msg.Payload, int64(msg.Size)); err != nil {
		return err
	}

	// Write the message.
	// 设置超时时间,并发送消息
	t.conn.SetWriteDeadline(time.Now().Add(frameWriteTimeout))
	size, err := t.conn.Write(msg.Code, t.wbuf.Bytes())
	if err != nil {
		return err
	}

	// Set metrics.
	// 记录每种协议不同消息发送的数据包个数和总数据量
	msg.meterSize = size
	if metrics.Enabled && msg.meterCap.Name != "" { // don't meter non-subprotocol messages
		// 每个协议的每种不同的消息都有一个专属的度量
		m := fmt.Sprintf("%s/%s/%d/%#02x", egressMeterName, msg.meterCap.Name, msg.meterCap.Version, msg.meterCode)
		metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize))
		metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)
	}
	return nil
}

// 关闭rlpxTransport.conn,在关闭之前如果网络通信正常的话会通知对方节点关闭的原因
func (t *rlpxTransport) close(err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	// Tell the remote end why we're disconnecting if possible.
	// We only bother doing this if the underlying connection supports
	// setting a timeout tough.
	// 如果可能的话向对面节点通知我们关闭的原因
	if t.conn != nil {
		if r, ok := err.(DiscReason); ok && r != DiscNetworkError {
			deadline := time.Now().Add(discWriteTimeout)
			if err := t.conn.SetWriteDeadline(deadline); err == nil {
				// Connection supports write deadline.
				t.wbuf.Reset()
				rlp.Encode(&t.wbuf, []DiscReason{r})
				// 向远程节点发送关闭的原因
				t.conn.Write(discMsg, t.wbuf.Bytes())
			}
		}
	}
	t.conn.Close()
}

// 进行rlpx协议的握手过程，直接调用rlpx.Conn.Handshake即可
func (t *rlpxTransport) doEncHandshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	t.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	return t.conn.Handshake(prv)
}

// 执行协议握手,交换双方的协议版本等信息
func (t *rlpxTransport) doProtoHandshake(our *protoHandshake) (their *protoHandshake, err error) {
	// Writing our handshake happens concurrently, we prefer
	// returning the handshake read error. If the remote side
	// disconnects us early with a valid reason, we should return it
	// as the error so it can be tracked elsewhere.
	werr := make(chan error, 1)
	// 首先本地向远端发送本地的协议相关信息
	go func() { werr <- Send(t, handshakeMsg, our) }()
	// 接收远端返回的协议信息
	if their, err = readProtocolHandshake(t); err != nil {
		<-werr // make sure the write terminates too
		return nil, err
	}
	if err := <-werr; err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}
	// If the protocol version supports Snappy encoding, upgrade immediately
	t.conn.SetSnappy(their.Version >= snappyProtocolVersion)

	return their, nil
}

// 读取一个消息并解析为protoHandshake对象
func readProtocolHandshake(rw MsgReader) (*protoHandshake, error) {
	msg, err := rw.ReadMsg()
	if err != nil {
		return nil, err
	}
	// 协议握手的数据包不能太大
	if msg.Size > baseProtocolMaxMsgSize {
		return nil, fmt.Errorf("message too big")
	}
	// 如果接收到了断开连接的通知包，解析出来断开原因并返回
	if msg.Code == discMsg {
		// Disconnect before protocol handshake is valid according to the
		// spec and we send it ourself if the post-handshake checks fail.
		// We can't return the reason directly, though, because it is echoed
		// back otherwise. Wrap it in a string instead.
		var reason [1]DiscReason
		// 将接收到的错误信息解码到reason中
		rlp.Decode(msg.Payload, &reason)
		return nil, reason[0]
	}
	// 需要接收到一个Code是handshakeMsg的消息
	if msg.Code != handshakeMsg {
		return nil, fmt.Errorf("expected handshake, got %x", msg.Code)
	}
	var hs protoHandshake
	// 将接收到的消息解码到protoHandshake对象中
	if err := msg.Decode(&hs); err != nil {
		return nil, err
	}
	// ID必须长度是64字节,还不能全零
	if len(hs.ID) != 64 || !bitutil.TestBytes(hs.ID) {
		return nil, DiscInvalidIdentity
	}
	return &hs, nil
}
