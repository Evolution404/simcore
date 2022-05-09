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

package discover

import (
	"context"
	"time"

	"github.com/Evolution404/simcore/p2p/enode"
)

// lookup performs a network search for nodes close to the given target. It approaches the
// target by querying nodes that are closer to it on each iteration. The given target does
// not need to be an actual node identifier.
// 输入节点表、目标公钥、网络查询方法
// 内部封装节点搜索算法,通过run方法启动节点搜索过程
// 返回距离目标最近的16个节点
type lookup struct {
	tab       *Table
	queryfunc func(*node) ([]*node, error)
	// 发送查询到的结果
	replyCh  chan []*node
	cancelCh <-chan struct{}
	// asked标记一个节点是否被查询过
	// seen用来判断一个节点是否曾经添加到result中过
	asked, seen map[enode.ID]bool
	// 结果集：一个长度为16的列表，始终按照距离保存最近的16个节点
	// 初始状态从节点表中查询16个距离目标最近的节点
	// 每次收到查询结果都会更新此列表，当列表中所有节点都被查询过后搜索过程结束
	result      nodesByDistance
	replyBuffer []*node
	// 记录当前正在查询的进程数,还没有进行过查询用-1标记
	queries int
}

type queryFunc func(*node) ([]*node, error)

func newLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	it := &lookup{
		tab:       tab,
		queryfunc: q,
		asked:     make(map[enode.ID]bool),
		seen:      make(map[enode.ID]bool),
		result:    nodesByDistance{target: target},
		replyCh:   make(chan []*node, alpha),
		cancelCh:  ctx.Done(),
		// 初始一次查询都没进行过标记为-1
		// 这时候需要从节点表中加载初始的结果集
		queries: -1,
	}
	// Don't query further if we hit ourself.
	// Unlikely to happen often in practice.
	// 避免向自己查询
	it.asked[tab.self().ID()] = true
	return it
}

// run runs the lookup to completion and returns the closest nodes found.
// 持续向外查询,查询结束后返回最近的16(bucketSize)个节点
func (it *lookup) run() []*enode.Node {
	for it.advance() {
	}
	return unwrapNodes(it.result.entries)
}

// advance advances the lookup until any new nodes have been found.
// It returns false when the lookup has ended.
// 向节点发送请求,查询到结果该函数执行结束
// 查询的结果保存在it.replyBuffer中
func (it *lookup) advance() bool {
	// 向外部发送查询
	//   有可能查询结果都是见过的节点,所以需要for循环不断查询
	//   有可能没有可以查询的节点了,所以for循环结束
	for it.startQueries() {
		select {
		// 接收到了查询的结果,返回了多个节点信息
		case nodes := <-it.replyCh:
			it.replyBuffer = it.replyBuffer[:0]
			// 遍历查询结果,过滤掉空节点和之前见过的节点
			for _, n := range nodes {
				if n != nil && !it.seen[n.ID()] {
					it.seen[n.ID()] = true
					// 保存查询到的节点到结果集中
					it.result.push(n, bucketSize)
					it.replyBuffer = append(it.replyBuffer, n)
				}
			}
			// 接收到结果queries对应减一
			it.queries--
			// 接收到了查询结果就返回
			if len(it.replyBuffer) > 0 {
				return true
			}
		// 外部调用了ctx的cancel函数就结束
		case <-it.cancelCh:
			it.shutdown()
		}
	}
	return false
}

func (it *lookup) shutdown() {
	for it.queries > 0 {
		<-it.replyCh
		it.queries--
	}
	it.queryfunc = nil
	it.replyBuffer = nil
}

// 向最近的几个节点发送查询请求,返回是否有正在进行的查询
func (it *lookup) startQueries() bool {
	if it.queryfunc == nil {
		return false
	}

	// The first query returns nodes from the local table.
	// 第一次查询,表中查询
	if it.queries == -1 {
		// 找到初始表中与目标最近的几个节点
		closest := it.tab.findnodeByID(it.result.target, bucketSize, false)
		// Avoid finishing the lookup too quickly if table is empty. It'd be better to wait
		// for the table to fill in this case, but there is no good mechanism for that
		// yet.
		// 没查找到节点,稍等一会让table中填充一下
		if len(closest.entries) == 0 {
			it.slowdown()
		}
		it.queries = 1
		it.replyCh <- closest.entries
		return true
	}

	// Ask the closest nodes that we haven't asked yet.
	// 最多查询的并发不能超过3
	// 从最近的节点开始查询节点,向它们发送请求
	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i]
		// 这个节点的asked为false
		if !it.asked[n.ID()] {
			it.asked[n.ID()] = true
			it.queries++
			go it.query(n, it.replyCh)
		}
	}
	// The lookup ends when no more nodes can be asked.
	// 返回当前是否有正在进行的查询
	return it.queries > 0
}

// 阻塞一秒钟
func (it *lookup) slowdown() {
	sleep := time.NewTimer(1 * time.Second)
	defer sleep.Stop()
	select {
	case <-sleep.C:
	case <-it.tab.closeReq:
	}
}

// 向输入的节点发送查询请求,查询到的节点保存到it.tab中且会输入到管道reply中
func (it *lookup) query(n *node, reply chan<- []*node) {
	fails := it.tab.db.FindFails(n.ID(), n.IP())
	// 执行实际的查询
	r, err := it.queryfunc(n)
	// 更新失败次数
	//   socket closed不记录入错误
	//   没有查询到记录错误次数加一
	//   成功查询到记录让错误次数归零
	if err == errClosed {
		// Avoid recording failures on shutdown.
		reply <- nil
		return
	} else if len(r) == 0 {
		// 更新错误次数
		fails++
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), fails)
		// Remove the node from the local table if it fails to return anything useful too
		// many times, but only if there are enough other nodes in the bucket.
		// 用于日志中打印查询失败后是否删除了失败的节点
		dropped := false
		// 失败次数过多而且桶内剩余的节点还挺多,就把这个节点从桶里面删除
		if fails >= maxFindnodeFailures && it.tab.bucketLen(n.ID()) >= bucketSize/2 {
			dropped = true
			it.tab.delete(n)
		}
		it.tab.log.Trace("FINDNODE failed", "id", n.ID(), "failcount", fails, "dropped", dropped, "err", err)
		// 这次成功查询了,数据库里记录的错误次数归零
	} else if fails > 0 {
		// Reset failure counter because it counts _consecutive_ failures.
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), 0)
	}

	// Grab as many nodes as possible. Some of them might not be alive anymore, but we'll
	// just remove those again during revalidation.
	// 将查询到的结果都保存到表中
	for _, n := range r {
		it.tab.addSeenNode(n)
	}
	// 将查询结果发送到管道
	reply <- r
}

// lookupIterator performs lookup operations and iterates over all seen nodes.
// When a lookup finishes, a new one is created through nextLookup.
type lookupIterator struct {
	buffer []*node
	// 当一个lookup对象耗尽了,用于创建新的lookup对象
	nextLookup lookupFunc
	ctx        context.Context
	cancel     func()
	lookup     *lookup
}

// 每调用一次返回一个新的lookup对象
type lookupFunc func(ctx context.Context) *lookup

func newLookupIterator(ctx context.Context, next lookupFunc) *lookupIterator {
	ctx, cancel := context.WithCancel(ctx)
	return &lookupIterator{ctx: ctx, cancel: cancel, nextLookup: next}
}

// Node returns the current node.
// 有节点返回buffer[0],没有节点返回nil
func (it *lookupIterator) Node() *enode.Node {
	if len(it.buffer) == 0 {
		return nil
	}
	return unwrapNode(it.buffer[0])
}

// Next moves to the next node.
// 迭代到下一个节点,返回值代表接下来还有没有
func (it *lookupIterator) Next() bool {
	// Consume next node in buffer.
	// 移除buffer第一个元素
	if len(it.buffer) > 0 {
		it.buffer = it.buffer[1:]
	}
	// Advance the lookup to refill the buffer.
	// buffer空了,就让lookup对象查询一组回来保存到buffer中
	for len(it.buffer) == 0 {
		if it.ctx.Err() != nil {
			it.lookup = nil
			it.buffer = nil
			return false
		}
		if it.lookup == nil {
			it.lookup = it.nextLookup(it.ctx)
			continue
		}
		if !it.lookup.advance() {
			it.lookup = nil
			continue
		}
		it.buffer = it.lookup.replyBuffer
	}
	return true
}

// Close ends the iterator.
func (it *lookupIterator) Close() {
	it.cancel()
}
