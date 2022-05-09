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

package netutil

import (
	"time"

	"github.com/Evolution404/simcore/common/mclock"
)

// statements 代表外部节点认为的本地的ip和端口
// contacts 代表本地向哪个外部ip和端口建立了连接

// IPTracker predicts the external endpoint, i.e. IP address and port, of the local host
// based on statements made by other hosts.
// IPTracker用来预测本地节点的外部ip和端口
// 预测是根据其他节点认为的本地ip和端口
type IPTracker struct {
	// 代表一条statement记录的超时时间,超过该时间在gcStatements中会被回收
	window time.Duration
	// 代表一条contact记录的超时时间,超过该时间在gcContact中会被回收
	contactWindow time.Duration
	// 必须有超过minStatements个数的节点认为本地的ip是某个ip,才会在PredictEndpoint返回这个ip
	minStatements int
	clock         mclock.Clock
	// statements和contact都是ip到时间的映射

	// statements保存 外部主机ip=>它以为的本地ip 的映射
	statements map[string]ipStatement
	// contact记录本地已经发送了其他节点的ip和端口信息到指定的ip
	// 其他节点的ip和端口=>发送时间 的映射
	// contact的目的是为了预测nat的类型,便于判断有没有从外部主动建立的连接
	contact         map[string]mclock.AbsTime
	lastStatementGC mclock.AbsTime
	lastContactGC   mclock.AbsTime
}

type ipStatement struct {
	endpoint string
	time     mclock.AbsTime
}

// NewIPTracker creates an IP tracker.
//
// The window parameters configure the amount of past network events which are kept. The
// minStatements parameter enforces a minimum number of statements which must be recorded
// before any prediction is made. Higher values for these parameters decrease 'flapping' of
// predictions as network conditions change. Window duration values should typically be in
// the range of minutes.
func NewIPTracker(window, contactWindow time.Duration, minStatements int) *IPTracker {
	return &IPTracker{
		window:        window,
		contactWindow: contactWindow,
		statements:    make(map[string]ipStatement),
		minStatements: minStatements,
		contact:       make(map[string]mclock.AbsTime),
		clock:         mclock.System{},
	}
}

// PredictFullConeNAT checks whether the local host is behind full cone NAT. It predicts by
// checking whether any statement has been received from a node we didn't contact before
// the statement was made.
// 判断是不是Full Cone类型的NAT
// 检测方法是判断有没有从外部主动建立的连接
func (it *IPTracker) PredictFullConeNAT() bool {
	now := it.clock.Now()
	it.gcContact(now)
	it.gcStatements(now)
	for host, st := range it.statements {
		// 如果有从外部主动建立的连接就可以判断是完全锥型
		// 遍历statements,如果statements里面有contact里面没有的host,就说明是Full Cone
		// 或者如果有statement的生成时间比contact早,也说明是Full Cone
		if c, ok := it.contact[host]; !ok || c > st.time {
			return true
		}
	}
	return false
}

// PredictEndpoint returns the current prediction of the external endpoint.
// 预测本地节点在其他节点眼里以为的ip
// 就是计算statements里面保存的哪个endpoint最多
func (it *IPTracker) PredictEndpoint() string {
	// The current strategy is simple: find the endpoint with most statements.
	counts := make(map[string]int)
	// 循环遍历计算记录次数最多的ip
	maxcount, max := 0, ""
	for _, s := range it.statements {
		c := counts[s.endpoint] + 1
		counts[s.endpoint] = c
		if c > maxcount && c >= it.minStatements {
			maxcount, max = c, s.endpoint
		}
	}
	return max
}

// AddStatement records that a certain host thinks our external endpoint is the one given.
// 添加外部节点认为的本地ip的记录
// host是外部的地址,endpoint是外部认为的本地地址
func (it *IPTracker) AddStatement(host, endpoint string) {
	now := it.clock.Now()
	it.statements[host] = ipStatement{endpoint, now}
	if time.Duration(now-it.lastStatementGC) >= it.window {
		it.gcStatements(now)
	}
}

// AddContact records that a packet containing our endpoint information has been sent to a
// certain host.
// 本地主动向外部发起连接通过AddContact添加
func (it *IPTracker) AddContact(host string) {
	now := it.clock.Now()
	it.contact[host] = now
	if time.Duration(now-it.lastContactGC) >= it.contactWindow {
		it.gcContact(now)
	}
}

// 回收it.statements中所有超过window时间的记录
func (it *IPTracker) gcStatements(now mclock.AbsTime) {
	it.lastStatementGC = now
	cutoff := now.Add(-it.window)
	for host, s := range it.statements {
		if s.time < cutoff {
			delete(it.statements, host)
		}
	}
}

// 回收it.contact中所有超过contactWindow时间的记录
func (it *IPTracker) gcContact(now mclock.AbsTime) {
	it.lastContactGC = now
	cutoff := now.Add(-it.contactWindow)
	for host, ct := range it.contact {
		if ct < cutoff {
			delete(it.contact, host)
		}
	}
}
