// Copyright 2017 The go-ethereum Authors
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

package bloombits

import (
	"sync"
)

// request represents a bloom retrieval task to prioritize and pull from the local
// database or remotely from the network.
// 描述针对一个区块段的布隆过滤器的查询信息
type request struct {
	// 要查询的区块段号，用于定位是哪个布隆过滤器
	section uint64 // Section index to retrieve the a bit-vector from
	// 要查询的布隆过滤器的比特位
	bit     uint   // Bit index within the section to retrieve the vector of
}

// response represents the state of a requested bit-vector through a scheduler.
// 描述请求的响应，请求对象与响应对象一一对应
type response struct {
	// 代表查询的结果，是一个长度4096位的位集
	// 将结果保存下来，重复的请求直接返回
	cached []byte        // Cached bits to dedup multiple requests
	// 响应到达关闭done管道，通知外部数据到达
	done   chan struct{} // Channel to allow waiting for completion
}

// scheduler handles the scheduling of bloom-filter retrieval operations for
// entire section-batches belonging to a single bloom bit. Beside scheduling the
// retrieval operations, this struct also deduplicates the requests and caches
// the results to minimize network/database overhead even in complex filtering
// scenarios.
// 一个scheduler对象用于调度针对布隆过滤器的某一个比特位的所有查询
type scheduler struct {
	// 当前scheduler对象负责处理的布隆过滤器的比特位
	bit       uint                 // Index of the bit in the bloom filter this scheduler is responsible for
	// 区块段号=>响应，保存各个区块段的查询的结果
	responses map[uint64]*response // Currently pending retrieval requests or already cached responses
	// 用于保护responses变量的锁
	lock      sync.Mutex           // Lock protecting the responses from concurrent access
}

// newScheduler creates a new bloom-filter retrieval scheduler for a specific
// bit index.
// 创建调度器对象，需要传入这个调度器对象需要负责的布隆过滤器比特位
func newScheduler(idx uint) *scheduler {
	return &scheduler{
		bit:       idx,
		responses: make(map[uint64]*response),
	}
}

// run creates a retrieval pipeline, receiving section indexes from sections and
// returning the results in the same order through the done channel. Concurrent
// runs of the same scheduler are allowed, leading to retrieval task deduplication.
// 调度器的启动函数
// 内部启动两个协程分别用于处理客户端和服务端
// 1.从sections管道接收各个要被查询的区块段号
// 2.对请求去重且没有缓存结果，构造request对象发送到dist管道，服务端接收到request对象执行真正的查询
// 3.服务端查询完成，将查询到的位集发送到done管道
func (s *scheduler) run(sections chan uint64, dist chan *request, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Create a forwarder channel between requests and responses of the same size as
	// the distribution channel (since that will block the pipeline anyway).
	// 保存已经发送给服务端还没返回结果的查询的区块段号
	pend := make(chan uint64, cap(dist))

	// Start the pipeline schedulers to forward between user -> distributor -> user
	// 增加等待两个协程
	// 以下两个方法内部都将调用wg.Done()
	wg.Add(2)
	go s.scheduleRequests(sections, dist, pend, quit, wg)
	go s.scheduleDeliveries(pend, done, quit, wg)
}

// reset cleans up any leftovers from previous runs. This is required before a
// restart to ensure the no previously requested but never delivered state will
// cause a lockup.
// 重置调度器
func (s *scheduler) reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for section, res := range s.responses {
		if res.cached == nil {
			delete(s.responses, section)
		}
	}
}

// scheduleRequests reads section retrieval requests from the input channel,
// deduplicates the stream and pushes unique retrieval tasks into the distribution
// channel for a database or network layer to honour.
// 调度客户端发送的查询请求
// reqs管道是客户端发送的各个要查询的区块段号
// dist是要发送给服务端的真正要执行的查询请求
// 从reqs管道接收请求,对请求去重后发送到dist中
func (s *scheduler) scheduleRequests(reqs chan uint64, dist chan *request, pend chan uint64, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(pend)

	// Keep reading and scheduling section requests
	for {
		select {
		case <-quit:
			return

		// 读取客户端要查询的区块段号
		case section, ok := <-reqs:
			// New section retrieval requested
			// 客户端关闭了发送管道，直接结束函数
			if !ok {
				return
			}
			// Deduplicate retrieval requests
			// 用于标识是否是新的请求
			unique := false

			s.lock.Lock()
			// 第一次查询这个区块段，构造reponse对象等待服务端返回
			if s.responses[section] == nil {
				// 第一次查询,在scheduler里面初始化一个response
				s.responses[section] = &response{
					done: make(chan struct{}),
				}
				unique = true
			}
			s.lock.Unlock()

			// Schedule the section for retrieval and notify the deliverer to expect this section
			// 处理向dist和pend管道发送的数据

			// 只有首次查询的数据，才发送到dist管道，让服务端查询
			if unique {
				select {
				case <-quit:
					return
				case dist <- &request{bit: s.bit, section: section}:
				}
			}
			// 所有的客户端请求都转发给scheduleDeliveries，让他内部来判断是返回缓存还是等待查询结果
			select {
			case <-quit:
				return
			case pend <- section:
			}
		}
	}
}

// scheduleDeliveries reads section acceptance notifications and waits for them
// to be delivered, pushing them into the output data buffer.
// 调度服务端提交的查询结果
// pend管道代表发送给服务端还没有返回的查询任务,等待查询任务结束向done管道发送查询结果
func (s *scheduler) scheduleDeliveries(pend chan uint64, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	defer wg.Done()
	defer close(done)

	// Keep reading notifications and scheduling deliveries
	for {
		select {
		case <-quit:
			return

		// 从pend中读取一个正在查询的区块段号，等待此查询完成将结果发送给客户端
		case idx, ok := <-pend:
			// New section retrieval pending
			if !ok {
				return
			}
			// Wait until the request is honoured
			s.lock.Lock()
			res := s.responses[idx]
			s.lock.Unlock()
			// 服务端调用deliver提交数据后对应response对象的done管道就会关闭
			// 如果服务端正在查询，这里就相当于等待查询完成
			// 如果是之前查询过的数据，由于done管道已经关闭将会立刻通过，相当于命中缓存直接返回
			select {
			case <-quit:
				return
			case <-res.done:
			}
			// Deliver the result
			// 将查询数据done管道发送给客户端
			select {
			case <-quit:
				return
			case done <- res.cached:
			}
		}
	}
}

// deliver is called by the request distributor when a reply to a request arrives.
// 服务器调用deliver来提交查询结果，一次调用可以提交多个区块段的数据
// sections[i]代表区块段号，data[i]代表区块段sections[i]得数据
func (s *scheduler) deliver(sections []uint64, data [][]byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// 遍历所有区块段号保存他们的查询结果
	for i, section := range sections {
		if res := s.responses[section]; res != nil && res.cached == nil { // Avoid non-requests and double deliveries
			// 将数据保存下来
			res.cached = data[i]
			// 通知scheduleDeliveries数据已经到达
			close(res.done)
		}
	}
}
