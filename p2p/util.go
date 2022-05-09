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

package p2p

import (
	"container/heap"

	"github.com/Evolution404/simcore/common/mclock"
)

// expHeap tracks strings and their expiry time.
// expHeap 用来记录字符串类型的数据,每个字符串可以带有一个过期时间
// expHeap.add(item,exp)添加一个字符串和对应的过期时间
// expHeap.expiry(now,onExp)删除所有过期时间在now前的字符串,被删除的字符串会调用onExp回调函数
// expHeap.contains(item)判断指定字符串是否被保存
// expHeap.nextExpiry()返回下一个元素的过期时间
type expHeap []expItem

// expItem is an entry in addrHistory.
type expItem struct {
	item string
	exp  mclock.AbsTime
}

// nextExpiry returns the next expiry time.
// 获得过期时间距离现在最近的元素
func (h *expHeap) nextExpiry() mclock.AbsTime {
	return (*h)[0].exp
}

// add adds an item and sets its expiry time.
// 元素类型是字符串,添加一个字符串到记录中,指定过期时间
func (h *expHeap) add(item string, exp mclock.AbsTime) {
	heap.Push(h, expItem{item, exp})
}

// contains checks whether an item is present.
// 判断指定的字符串是否被保存了
func (h expHeap) contains(item string) bool {
	for _, v := range h {
		if v.item == item {
			return true
		}
	}
	return false
}

// expire removes items with expiry time before 'now'.
// 输入一个时间,将过期时间在指定时间之前的元素都删除
// 当一个保存的字符串被删除的时候会调用传入的回调函数onExp
func (h *expHeap) expire(now mclock.AbsTime, onExp func(string)) {
	for h.Len() > 0 && h.nextExpiry() < now {
		item := heap.Pop(h)
		if onExp != nil {
			onExp(item.(expItem).item)
		}
	}
}

// heap.Interface boilerplate
func (h expHeap) Len() int            { return len(h) }
func (h expHeap) Less(i, j int) bool  { return h[i].exp < h[j].exp }
func (h expHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *expHeap) Push(x interface{}) { *h = append(*h, x.(expItem)) }
func (h *expHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
