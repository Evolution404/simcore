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

// Contains the meters and timers used by the networking layer.

package p2p

import (
	"net"

	"github.com/Evolution404/simcore/metrics"
)

const (
	// ingressMeterName is the prefix of the per-packet inbound metrics.
	ingressMeterName = "p2p/ingress"

	// egressMeterName is the prefix of the per-packet outbound metrics.
	egressMeterName = "p2p/egress"

	// HandleHistName is the prefix of the per-packet serving time histograms.
	HandleHistName = "p2p/handle"
)

var (
	// 外部向本地发起的连接个数
	ingressConnectMeter = metrics.NewRegisteredMeter("p2p/serves", nil)
	// 从网络中接收到的字节数,在Read中读取到的字节数
	ingressTrafficMeter = metrics.NewRegisteredMeter(ingressMeterName, nil)
	// 本地主动发起的连接个数
	egressConnectMeter  = metrics.NewRegisteredMeter("p2p/dials", nil)
	// 往网络中发送的字节数,在Write中发送的字节数
	egressTrafficMeter  = metrics.NewRegisteredMeter(egressMeterName, nil)
	// 记录当前建立连接的节点个数
	activePeerGauge     = metrics.NewRegisteredGauge("p2p/peers", nil)
)

// meteredConn is a wrapper around a net.Conn that meters both the
// inbound and outbound network traffic.
type meteredConn struct {
	net.Conn
}

// newMeteredConn creates a new metered connection, bumps the ingress or egress
// connection meter and also increases the metered peer count. If the metrics
// system is disabled, function returns the original connection.
// ingress为true代表从外部接收到的连接
// ingress为false代表从本地向外部发送的连接
func newMeteredConn(conn net.Conn, ingress bool, addr *net.TCPAddr) net.Conn {
	// Short circuit if metrics are disabled
	if !metrics.Enabled {
		return conn
	}
	// Bump the connection counters and wrap the connection
	if ingress {
		ingressConnectMeter.Mark(1)
	} else {
		egressConnectMeter.Mark(1)
	}
	activePeerGauge.Inc(1)
	return &meteredConn{Conn: conn}
}

// Read delegates a network read to the underlying connection, bumping the common
// and the peer ingress traffic meters along the way.
// 读取数据的时候记录读取了多少字节
func (c *meteredConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	ingressTrafficMeter.Mark(int64(n))
	return n, err
}

// Write delegates a network write to the underlying connection, bumping the common
// and the peer egress traffic meters along the way.
// 发送数据的时候记录发送了多少字节
func (c *meteredConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	egressTrafficMeter.Mark(int64(n))
	return n, err
}

// Close delegates a close operation to the underlying connection, unregisters
// the peer from the traffic registries and emits close event.
// 关闭连接后让记录连接个数的计数器减一
func (c *meteredConn) Close() error {
	err := c.Conn.Close()
	if err == nil {
		activePeerGauge.Dec(1)
	}
	return err
}
