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

package enode

import (
	"sync"
	"time"
)

// Iterator represents a sequence of nodes. The Next method moves to the next node in the
// sequence. It returns false when the sequence has ended or the iterator is closed. Close
// may be called concurrently with Next and Node, and interrupts Next if it is blocked.
// 节点的迭代器对象,包含Next,Node,Close方法
// 这个文件实现了sliceIter,filterIter,FairMix
type Iterator interface {
	Next() bool  // moves to next node
	Node() *Node // returns current node
	Close()      // ends the iterator
}

// ReadNodes reads at most n nodes from the given iterator. The return value contains no
// duplicates and no nil values. To prevent looping indefinitely for small repeating node
// sequences, this function calls Next at most n times.
// 从迭代器中读取n个节点,并对结果进行去重,读取过程中迭代器到底直接返回
func ReadNodes(it Iterator, n int) []*Node {
	// seen记录所有遍历到的节点
	// 节点id=>节点对象的映射,使用节点id来去重
	seen := make(map[ID]*Node, n)
	// 依次迭代节点,并对结果去重
	for i := 0; i < n && it.Next(); i++ {
		// Remove duplicates, keeping the node with higher seq.
		node := it.Node()
		// 如果有重复的节点,以Seq高者为准
		prevNode, ok := seen[node.ID()]
		if ok && prevNode.Seq() > node.Seq() {
			continue
		}
		seen[node.ID()] = node
	}
	// 将map转换成数组返回
	result := make([]*Node, 0, len(seen))
	for _, node := range seen {
		result = append(result, node)
	}
	return result
}

// IterNodes makes an iterator which runs through the given nodes once.
// 生成一个在输入的这些节点中遍历的迭代器,迭代到结尾就结束
func IterNodes(nodes []*Node) Iterator {
	return &sliceIter{nodes: nodes, index: -1}
}

// CycleNodes makes an iterator which cycles through the given nodes indefinitely.
// 生成一个在输入的这些节点中遍历的迭代器,迭代到结尾就重新从头开始,可以无限迭代
func CycleNodes(nodes []*Node) Iterator {
	return &sliceIter{nodes: nodes, index: -1, cycle: true}
}

type sliceIter struct {
	mu    sync.Mutex
	nodes []*Node
	index int
	// 控制是否循环遍历,到达末尾是否回到开头
	cycle bool
}

// 挨个遍历,如果cycle为true就到末尾后回到开头
// 返回值代表是否读取成功下一个值
func (it *sliceIter) Next() bool {
	it.mu.Lock()
	defer it.mu.Unlock()

	if len(it.nodes) == 0 {
		return false
	}
	it.index++
	if it.index == len(it.nodes) {
		if it.cycle {
			it.index = 0
		} else {
			it.nodes = nil
			return false
		}
	}
	return true
}

// 返回迭代器当前的节点
func (it *sliceIter) Node() *Node {
	it.mu.Lock()
	defer it.mu.Unlock()
	if len(it.nodes) == 0 {
		return nil
	}
	return it.nodes[it.index]
}

func (it *sliceIter) Close() {
	it.mu.Lock()
	defer it.mu.Unlock()

	it.nodes = nil
}

// Filter wraps an iterator such that Next only returns nodes for which
// the 'check' function returns true.
// 对已有的迭代器进行封装,只迭代满足check函数的节点
func Filter(it Iterator, check func(*Node) bool) Iterator {
	return &filterIter{it, check}
}

type filterIter struct {
	Iterator
	check func(*Node) bool
}

func (f *filterIter) Next() bool {
	for f.Iterator.Next() {
		if f.check(f.Node()) {
			return true
		}
	}
	return false
}

// FairMix aggregates multiple node iterators. The mixer itself is an iterator which ends
// only when Close is called. Source iterators added via AddSource are removed from the
// mix when they end.
//
// The distribution of nodes returned by Next is approximately fair, i.e. FairMix
// attempts to draw from all sources equally often. However, if a certain source is slow
// and doesn't return a node within the configured timeout, a node from any other source
// will be returned.
//
// It's safe to call AddSource and Close concurrently with Next.
// 可以以公平的方式从多个来源迭代节点
type FairMix struct {
	wg      sync.WaitGroup
	fromAny chan *Node
	// timeout指最多等待某个来源的时间,使用负数将禁用超时
	timeout time.Duration
	// 保存当前的Node
	cur *Node

	mu     sync.Mutex
	closed chan struct{}
	// 保存迭代节点的所有来源
	sources []*mixSource
	// 记录当前选取的sources中的位置
	last int
}

// 代表FairMix对象内部的一个节点来源
// 每个来源读取到的节点就会写入到自己的next管道中
// 当使用pickSource选中这个来源后就会被FairMix.Next方法读取
type mixSource struct {
	it      Iterator
	next    chan *Node
	timeout time.Duration
}

// NewFairMix creates a mixer.
//
// The timeout specifies how long the mixer will wait for the next fairly-chosen source
// before giving up and taking a node from any other source. A good way to set the timeout
// is deciding how long you'd want to wait for a node on average. Passing a negative
// timeout makes the mixer completely fair.
// 创建一个FairMix迭代器,用来从多个来源平均的迭代节点
// 输入的时间表示等待一个来源返回节点的超时时间
func NewFairMix(timeout time.Duration) *FairMix {
	m := &FairMix{
		fromAny: make(chan *Node),
		closed:  make(chan struct{}),
		timeout: timeout,
	}
	return m
}

// AddSource adds a source of nodes.
// AddSource就是在FairMix.sources数组中添加一项,并且启动这个来源的协程
func (m *FairMix) AddSource(it Iterator) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed == nil {
		return
	}
	m.wg.Add(1)
	// 在迭代器中添加一项来源
	source := &mixSource{it, make(chan *Node), m.timeout}
	m.sources = append(m.sources, source)
	// 启动这个来源开始迭代节点
	go m.runSource(m.closed, source)
}

// Close shuts down the mixer and all current sources.
// Calling this is required to release resources associated with the mixer.
func (m *FairMix) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed == nil {
		return
	}
	// 关闭所有内部的迭代器
	for _, s := range m.sources {
		s.it.Close()
	}
	// 关闭closed管道通知runSource协程结束
	close(m.closed)
	// 等待所有runSource协程结束
	m.wg.Wait()
	close(m.fromAny)
	m.sources = nil
	m.closed = nil
}

// Next returns a node from a random source.
// 迭代下一个节点
// 默认从下一个来源中读取节点,如果下一个来源等待时间超时那么就从所有来源中读取一个
func (m *FairMix) Next() bool {
	m.cur = nil

	var timeout <-chan time.Time
	if m.timeout >= 0 {
		timer := time.NewTimer(m.timeout)
		timeout = timer.C
		defer timer.Stop()
	}
	for {
		source := m.pickSource()
		if source == nil {
			return m.nextFromAny()
		}
		select {
		case n, ok := <-source.next:
			if ok {
				m.cur = n
				// 一个来源成功读取节点的话,就恢复他的超时时间为默认时间
				// 避免之前超时时间被减半了
				source.timeout = m.timeout
				return true
			}
			// This source has ended.
			m.deleteSource(source)
		// 当前来源超时,那么降低他的信任度,让超时时间减半
		case <-timeout:
			source.timeout /= 2
			// 超时的话,从任意一个来源获取一个节点信息
			return m.nextFromAny()
		}
	}
}

// Node returns the current node.
func (m *FairMix) Node() *Node {
	return m.cur
}

// nextFromAny is used when there are no sources or when the 'fair' choice
// doesn't turn up a node quickly enough.
// 从任意一个已经读取完成的来源中获取一个节点
func (m *FairMix) nextFromAny() bool {
	n, ok := <-m.fromAny
	if ok {
		m.cur = n
	}
	return ok
}

// pickSource chooses the next source to read from, cycling through them in order.
// 从m.sources中选取下一个
func (m *FairMix) pickSource() *mixSource {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sources) == 0 {
		return nil
	}
	m.last = (m.last + 1) % len(m.sources)
	return m.sources[m.last]
}

// deleteSource deletes a source.
// 从m.sources中移除指定的mixSource
func (m *FairMix) deleteSource(s *mixSource) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.sources {
		if m.sources[i] == s {
			copy(m.sources[i:], m.sources[i+1:])
			m.sources[len(m.sources)-1] = nil
			m.sources = m.sources[:len(m.sources)-1]
			break
		}
	}
}

// runSource reads a single source in a loop.
// 不断循环从输入的来源中读取下一个节点,写入到next或者fromAny管道中
// closed用来通知关闭
func (m *FairMix) runSource(closed chan struct{}, s *mixSource) {
	// AddSource调用了wg.Add
	defer m.wg.Done()
	// runSource函数结束,也就是这个来源的迭代器耗尽的时候关闭这个来源的next管道
	defer close(s.next)
	for s.it.Next() {
		n := s.it.Node()
		select {
		case s.next <- n:
		case m.fromAny <- n:
		case <-closed:
			return
		}
	}
}
