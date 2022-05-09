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
	"bytes"
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Evolution404/simcore/common/bitutil"
	"github.com/Evolution404/simcore/crypto"
)

// bloomIndexes represents the bit indexes inside the bloom filter that belong
// to some key.
// 用来描述一个元素在布隆过滤器中标记为1的三个比特位的下标
type bloomIndexes [3]uint

// calcBloomIndexes returns the bloom filter bit indexes belonging to the given key.
// 计算输入数据的标记位
func calcBloomIndexes(b []byte) bloomIndexes {
	b = crypto.Keccak256(b)

	var idxs bloomIndexes
	// 循环三次,每组两字节,每个循环取每组的最后11位
	for i := 0; i < len(idxs); i++ {
		// (uint(b[2*i])<<8)&2047 最大1792
		// uint(b[2*i+1]) 最大255
		// 所以相加最大2047,正好在[0-2047]比特位之间
		// 比特位置就是 b[0]的后三位和b[1]的八位拼在一起
		idxs[i] = (uint(b[2*i])<<8)&2047 + uint(b[2*i+1])
	}
	return idxs
}

// partialMatches with a non-nil vector represents a section in which some sub-
// matchers have already found potential matches. Subsequent sub-matchers will
// binary AND their matches with this vector. If vector is nil, it represents a
// section to be processed by the first sub-matcher.
// 描述一个区块段中所有区块经过若干个过滤器后的匹配状态
type partialMatches struct {
	// 当前的区块段号
	section uint64
	// 每一位代表该区块段的一个区块的匹配状态
	// 初始化的时候所有比特位被设置为1（4096个1）
	// 随着不断经过各个过滤器，被设置为1的比特位越来越少
	// 经过最后一个过滤器后，最终还是1的比特位就对应了通过了过滤器组的区块
	bitset []byte
}

// Retrieval represents a request for retrieval task assignments for a given
// bit with the given number of fetch elements, or a response for such a request.
// It can also have the actual results set to be used as a delivery data struct.
//
// The contest and error fields are used by the light client to terminate matching
// early if an error is encountered on some path of the pipeline.
// 代表需要服务端执行的一次查询任务
type Retrieval struct {
	// 要查询区块段中区块的布隆过滤器的哪个比特位
	Bit uint
	// 要查询哪些区块段
	Sections []uint64
	// 服务端查询完成后将多个位集结果保存在这里
	Bitsets [][]byte

	Context context.Context
	Error   error
}

// Matcher is a pipelined system of schedulers and logic matchers which perform
// binary AND/OR operations on the bit-streams, creating a stream of potential
// blocks to inspect for data content.
type Matcher struct {
	sectionSize uint64 // Size of the data batches to filter on

	// 保存匹配器的过滤器组
	filters [][]bloomIndexes // Filter the system is matching for
	// 调度器负责的比特位=>调度器 的映射，保存匹配器内部使用的调度器
	schedulers map[uint]*scheduler // Retrieval schedulers for loading bloom bits

	retrievers chan chan uint       // Retriever processes waiting for bit allocations
	counters   chan chan uint       // Retriever processes waiting for task count reports
	retrievals chan chan *Retrieval // Retriever processes waiting for task allocations
	deliveries chan *Retrieval      // Retriever processes waiting for task response deliveries

	// 标记当前的匹配器是否正调用Start函数
	running uint32 // Atomic flag whether a session is live or not
}

// NewMatcher creates a new pipeline for retrieving bloom bit streams and doing
// address and topic filtering on them. Setting a filter component to `nil` is
// allowed and will result in that filter rule being skipped (OR 0x11...1).
// 设地址为ax,topic为tx, filters[i]称为filter
// filters的格式为 [ [a1,a2,a3], [t11,t12], [t21,t22,t23]]
// 只有filters[0]保存了地址列表,后面都是topic列表
// 满足filters的条件是每个filter中的值都至少被找到一个
// 输入filters生成一个Matcher
//   1. 将原始filters转换成三数字类型的filters
//   2. filters可以得到需要查询的比特位,每个比特位生成一个scheduler
func NewMatcher(sectionSize uint64, filters [][][]byte) *Matcher {
	// Create the matcher instance
	m := &Matcher{
		sectionSize: sectionSize,
		schedulers:  make(map[uint]*scheduler),
		retrievers:  make(chan chan uint),
		counters:    make(chan chan uint),
		retrievals:  make(chan chan *Retrieval),
		deliveries:  make(chan *Retrieval),
	}
	// Calculate the bloom bit indexes for the groups we're interested in
	// 接下来要将用户输入的原始过滤器组转化为过滤器组
	m.filters = nil

	// 遍历原始过滤器组中的各条原始过滤器
	for _, filter := range filters {
		// Gather the bit indexes of the filter rule, special casing the nil filter
		// 原始过滤器中没有要查询的数据，直接跳过
		if len(filter) == 0 {
			continue
		}
		// 用来保存原始过滤器转化后的真实过滤器，每个条件被转化为一个位置标记组
		bloomBits := make([]bloomIndexes, len(filter))
		// 遍历原始过滤器中的各条数据，clause就是每条数据
		for i, clause := range filter {
			if clause == nil {
				bloomBits = nil
				break
			}
			// 将查询数据转化为位置标记组
			bloomBits[i] = calcBloomIndexes(clause)
		}
		// Accumulate the filter rules if no nil rule was within
		// 加入到Matcher.filters里面
		if bloomBits != nil {
			m.filters = append(m.filters, bloomBits)
		}
	}
	// For every bit, create a scheduler to load/download the bit vectors
	// 将过滤器组拆分为位集查询任务
	for _, bloomIndexLists := range m.filters {
		//     三数字
		for _, bloomIndexList := range bloomIndexLists {
			//     单个数字
			for _, bloomIndex := range bloomIndexList {
				m.addScheduler(bloomIndex)
			}
		}
	}
	return m
}

// addScheduler adds a bit stream retrieval scheduler for the given bit index if
// it has not existed before. If the bit is already selected for filtering, the
// existing scheduler can be used.
// idx是布隆过滤器的比特位
// 创建新的查询idx位置的scheduler
func (m *Matcher) addScheduler(idx uint) {
	if _, ok := m.schedulers[idx]; ok {
		return
	}
	m.schedulers[idx] = newScheduler(idx)
}

// Start starts the matching process and returns a stream of bloom matches in
// a given range of blocks. If there are no more matches in the range, the result
// channel is closed.
// 客户端启动一个查询过程，指定了开始和结束的区块号，从results中接收查询结果
func (m *Matcher) Start(ctx context.Context, begin, end uint64, results chan uint64) (*MatcherSession, error) {
	// Make sure we're not creating concurrent sessions
	// Start函数不能并发调用
	if atomic.SwapUint32(&m.running, 1) == 1 {
		return nil, errors.New("matcher already running")
	}
	defer atomic.StoreUint32(&m.running, 0)

	// Initiate a new matching round
	// 生成MatcherSession对象
	session := &MatcherSession{
		matcher: m,
		quit:    make(chan struct{}),
		ctx:     ctx,
	}
	// 重置所有调度器
	for _, scheduler := range m.schedulers {
		scheduler.reset()
	}
	// results管道有多少容量,就给查询管道开多少容量
	// sink管道接收流水线的最终结果
	sink := m.run(begin, end, cap(results), session)

	// Read the output from the result sink and deliver to the user
	// 等待下面的协程执行完毕
	session.pend.Add(1)
	go func() {
		defer session.pend.Done()
		defer close(results)
		// 不断从sink管道中读取经过所有过滤器的中间状态，将中间状态中为1的比特位转换成区块号发送给客户端
		for {
			select {
			case <-session.quit:
				return

			// 获取一个区块段的查询结果
			// 找到这个区块段所有在用户查询范围内被设置为1的位置，发送到results管道
			case res, ok := <-sink:
				// New match result found
				if !ok {
					return
				}
				// Calculate the first and last blocks of the section
				// 返回结果的区块段的开始位置
				sectionStart := res.section * m.sectionSize

				// 用户真正查询的开始位置
				first := sectionStart
				if begin > first {
					first = begin
				}
				// 用户真正查询的结束位置
				last := sectionStart + m.sectionSize - 1
				if end < last {
					last = end
				}
				// Iterate over all the blocks in the section and return the matching ones
				for i := first; i <= last; i++ {
					// Skip the entire byte if no matches are found inside (and we're processing an entire byte!)
					next := res.bitset[(i-sectionStart)/8]
					// 如果一整个字节都是0，跳过继续查询这个字节
					if next == 0 {
						if i%8 == 0 {
							// 这里本来应该i+=8，但是for循环自身还会i++，所以是i+=7
							i += 7
						}
						continue
					}
					// Some bit it set, do the actual submatching
					// 这个字节内部有一些位是1，判断i对应的位置是不是1
					// bit变量代表i位置在它的字节里面后面有几个0
					// next&(1<<bit)也就是取到i位置，判断如果i位置不是0发送到results管道
					if bit := 7 - i%8; next&(1<<bit) != 0 {
						select {
						case <-session.quit:
							return
						// 第i位是1,发送块号到results中
						case results <- i:
						}
					}
				}
			}
		}
	}()
	return session, nil
}

// run creates a daisy-chain of sub-matchers, one for the address set and one
// for each topic set, each sub-matcher receiving a section only if the previous
// ones have all found a potential match in one of the blocks of the section,
// then binary AND-ing its own matches and forwarding the result to the next one.
//
// The method starts feeding the section indexes into the first sub-matcher on a
// new goroutine and returns a sink channel receiving the results.
// buffer代表查询管道的缓存
func (m *Matcher) run(begin, end uint64, buffer int, session *MatcherSession) chan *partialMatches {
	// Create the source channel and feed section indexes into
	source := make(chan *partialMatches, buffer)

	session.pend.Add(1)
	// 为每个区块段创建中间状态
	go func() {
		defer session.pend.Done()
		defer close(source)

		// 为每个区块段生成一个partialMatches对象，发送到source管道中
		for i := begin / m.sectionSize; i <= end/m.sectionSize; i++ {
			select {
			case <-session.quit:
				return
			// 没经过任何过滤器默认所有区块都通过，所以partialMatches对象的bitset字段初始化为全1
			case source <- &partialMatches{i, bytes.Repeat([]byte{0xff}, int(m.sectionSize/8))}:
			}
		}
	}()
	// Assemble the daisy-chained filtering pipeline
	next := source
	// 用于调度器的服务端接收查询请求，在distributor函数中接收请求
	dist := make(chan *request, buffer)

	// 针对每个过滤器启动一个subMatch
	// 这些subMatch两两相接，前一个subMatch生成一个管道来与下一个subMatch通信中间状态
	for _, bloom := range m.filters {
		// 每次处理一个filter
		next = m.subMatch(next, dist, bloom, session)
	}
	// Start the request distribution
	session.pend.Add(1)
	go m.distributor(dist, session)

	// 返回的是subMatch链最后一个输出管道，从中可以读取满足了整个过滤器组的区块
	return next
}

// subMatch creates a sub-matcher that filters for a set of addresses or topics, binary OR-s those matches, then
// binary AND-s the result to the daisy-chain input (source) and forwards it to the daisy-chain output.
// The matches of each address/topic are calculated by fetching the given sections of the three bloom bit indexes belonging to
// that address/topic, and binary AND-ing those vectors together.
// subMatch函数与过滤器一一对应，bloom就是对应的过滤器
// 从source中接收经过了前一个过滤器后的中间状态
// dist是调度器服务端接受请求的管道，过滤器中要执行的查询由调度器去重、缓存后都发送到dist中
// bloom就代表这个subMatch对应的过滤器
func (m *Matcher) subMatch(source chan *partialMatches, dist chan *request, bloom []bloomIndexes, session *MatcherSession) chan *partialMatches {
	// Start the concurrent schedulers for each bit required by the bloom filter
	// 调度器需要客户端准备好发送请求和接收数据的两个管道
	// 过滤器里的每一个比特位对应一个客户端

	// 客户端发送请求的管道，发送的是区块段号
	sectionSources := make([][3]chan uint64, len(bloom))
	// 客户端接收查询结果的管道，接收的是位集
	sectionSinks := make([][3]chan []byte, len(bloom))
	// 找到各个客户端对应的管道，调用run函数让调度器调度他们的请求
	// 这里可能针对一个调度器重复调用run函数，调度器支持调度多个客户端，所以没有问题
	for i, bits := range bloom {
		for j, bit := range bits {
			sectionSources[i][j] = make(chan uint64, cap(source))
			sectionSinks[i][j] = make(chan []byte, cap(source))

			m.schedulers[bit].run(sectionSources[i][j], dist, sectionSinks[i][j], session.quit, &session.pend)
		}
	}

	// 下面有两个协程要接收source中的中间状态，第一个协程将数据转发到process中供第二个协程接收
	process := make(chan *partialMatches, cap(source)) // entries from source are forwarded here after fetches have been initiated
	// 从process读取后最终再写入results,写入这个管道里的流水线进入下一个filter
	results := make(chan *partialMatches, cap(source))

	// 下面有两个协程
	session.pend.Add(2)
	// 下面启动两个协程，一个用来向调度器发送请求，另一个接收调度器返回的数据
	// 由于两个协程都需要读取中间状态，所以前一个协程利用process管道向第二个协程转发中间状态

	// 向调度器发送请求的协程
	go func() {
		// Tear down the goroutine and terminate all source channels
		defer session.pend.Done()
		defer close(process)

		defer func() {
			// 函数结束时，客户端关闭所有发送请求的管道
			for _, bloomSources := range sectionSources {
				for _, bitSource := range bloomSources {
					close(bitSource)
				}
			}
		}()
		// Read sections from the source channel and multiplex into all bit-schedulers
		// 从source中读取一个中间状态，让他通过当前的过滤器
		for {
			select {
			case <-session.quit:
				return

			// 读取到中间状态
			case subres, ok := <-source:
				// New subresult from previous link
				if !ok {
					return
				}
				// Multiplex the section index to all bit-schedulers
				// 作为调度器的客户端向调度器发送请求
				for _, bloomSources := range sectionSources {
					for _, bitSource := range bloomSources {
						select {
						case <-session.quit:
							return
						// 写入section后会驱动schedulers.run运行
						case bitSource <- subres.section:
						}
					}
				}
				// Notify the processor that this section will become available
				// 转发给第二个协程
				select {
				case <-session.quit:
					return
				case process <- subres:
				}
			}
		}
	}()

	// 接收调度器返回数据的协程
	go func() {
		// Tear down the goroutine and terminate the final sink channel
		defer session.pend.Done()
		defer close(results)

		// Read the source notifications and collect the delivered results
		for {
			select {
			case <-session.quit:
				return

			// 接收中间状态，由前一个协程转发过来
			case subres, ok := <-process:
				// Notified of a section being retrieved
				if !ok {
					return
				}
				// Gather all the sub-results and merge them together
				// 循环结束后为1的比特位，代表对应的区块保存了过滤器中的任意一条数据
				var orVector []byte
				// 遍历各个接收管道来接收数据
				// 一层循环进入各个条件的三个接收管道
				for _, bloomSinks := range sectionSinks {
					// 二层循环获得真正的调度器客户端，三个比特位都是1才能说明数据存在，所以这里是与关系

					// 循环结束后还为1的比特位，代表位置标记组三个比特位都是1
					var andVector []byte
					// 内部的for循环将每个条件查询的三个比特位进行与运算
					for _, bitSink := range bloomSinks {
						var data []byte
						select {
						case <-session.quit:
							return
						// 实际接收数据的位置
						case data = <-bitSink:
						}
						// 如果是在判断位置标记组的第一个比特位，直接将查询结果拷贝过来
						if andVector == nil {
							andVector = make([]byte, int(m.sectionSize/8))
							copy(andVector, data)
							// 如果是第二个或者第三个比特位，直接与计算，最终得到3个比特位都是1的位置
						} else {
							bitutil.ANDBytes(andVector, andVector, data)
						}
					}
					// 如果是查询完了第一个位置标记组，满足条件的就是andVector里面的
					if orVector == nil {
						orVector = andVector
						// 查询之后的位置标记组都与之前的结果取或
					} else {
						bitutil.ORBytes(orVector, orVector, andVector)
					}
				}
				// 当前filter没有条件,默认所有块都不通过
				if orVector == nil {
					orVector = make([]byte, int(m.sectionSize/8))
				}
				// 已经找到了能够通过当前过滤器的区块，与通过之前过滤器的结果相与得到通过新增过滤器的区块
				if subres.bitset != nil {
					bitutil.ANDBytes(orVector, orVector, subres.bitset)
				}
				// 如果经过这个过滤器后还有存活的区块，继续发送中间状态由下一个过滤器处理
				// 如果经过这个过滤器没有存活的区块了，这里不会发送，中间状态在subMatch链上的传递中断在此处
				if bitutil.TestBytes(orVector) {
					select {
					case <-session.quit:
						return
					case results <- &partialMatches{subres.section, orVector}:
					}
				}
			}
		}
	}()
	return results
}

// distributor receives requests from the schedulers and queues them into a set
// of pending requests, which are assigned to retrievers wanting to fulfil them.
// 从dist管道接收调度器发出来的最终需要执行的查询请求，distributor用来处理多个服务端查询请求的分发
func (m *Matcher) distributor(dist chan *request, session *MatcherSession) {
	defer session.pend.Done()

	var (
		// 比特位=>区块段号数组，保存了各个比特位对应的请求队列，每个请求队列按照区块段号的大小排序
		requests = make(map[uint][]uint64) // Per-bit list of section requests, ordered by section number
		// 保存未被分配的比特位，使用map是便于删除元素
		unallocs = make(map[uint]struct{}) // Bits with pending requests but not allocated to any retriever
		// 用于与allocateRetrieval沟通，allocateRetrieval发送fetcher，本函数再向fetcher发送分配的比特位
		retrievers chan chan uint // Waiting retrievers (toggled to nil if unallocs is empty)
		// 记录已经分配了多少个比特位，用于退出过程
		allocs     int            // Number of active allocations to handle graceful shutdown requests
		shutdown   = session.quit // Shutdown request channel, will gracefully wait for pending requests
	)

	// assign is a helper method fo try to assign a pending bit an actively
	// listening servicer, or schedule it up for later when one arrives.
	// 用来分配一个比特位，分配过程有两种可能
	//   retrievers管道正好接收到了来自allocateRetrieval发送的分配请求，直接分配当前比特位
	//   没有分配请求的话将比特位加入到unallocs变量，等待以后的分配请求
	assign := func(bit uint) {
		// 如果有空闲的retrievers直接分配当前比特位任务
		select {
		case fetcher := <-m.retrievers:
			allocs++
			fetcher <- bit
		// 没有空闲的retriever,加入unallocs中,让下面的事件监听处理
		default:
			// No retrievers active, start listening for new ones
			// 下面retrievers分支可能会将这个管道置为nil，这里重新设置一下
			retrievers = m.retrievers
			unallocs[bit] = struct{}{}
		}
	}

	// 1. req:= <-dist
	//   所有请求首先从dist中读取,写入requests中
	//   所有任务在requests中根据查询的比特位不同,分为若干个比特位任务
	// 2. fetcher := <-retrievers
	//   每个retriever将会被分配一个比特位任务,向所有需要查询这个比特位的section进行查询操作
	//   调用allocateRetrieval就会从requests中派发一个比特位的任务
	// 3. fetcher := <-m.retrievals
	//   retriever只得到了被派发的比特位,通过这个管道可以获取指定长度的section列表进行查询
	for {
		select {
		case <-shutdown:
			// Shutdown requested. No more retrievers can be allocated,
			// but we still need to wait until all pending requests have returned.
			shutdown = nil
			if allocs == 0 {
				return
			}

		// 作为调度器的服务端，接收request对象，里面包括请求的区块段号以及请求的比特位
		case req := <-dist:
			// New retrieval request arrived to be distributed to some fetcher process
			// 将新请求的区块段号加入到请求列表中
			queue := requests[req.bit]
			// 将新的区块段号按照顺序插入到请求队列中
			index := sort.Search(len(queue), func(i int) bool { return queue[i] >= req.section })
			requests[req.bit] = append(queue[:index], append([]uint64{req.section}, queue[index:]...)...)

			// If it's a new bit and we have waiting fetchers, allocate to them
			// 如果这是一个新的比特位，它需要调用allocateRetrieval函数后分配
			if len(queue) == 0 {
				assign(req.bit)
			}

		// 以下四个情况retrievers,counters,retrievals,deliveries是处理来自MatcherSession的查询

		// 从未分配的比特位中派发一个给allocateRetrieval，派发的是比特位优先级最高的比特位
		case fetcher := <-retrievers:
			// New retriever arrived, find the lowest section-ed bit to assign
			// 派发一个比特位,选取的是第一个任务section最小的那个比特位
			bit, best := uint(0), uint64(math.MaxUint64)
			// 找到请求队列第一个请求的区块段号最小的那个比特位，也就是比特位优先级最高的比特位
			for idx := range unallocs {
				if requests[idx][0] < best {
					bit, best = idx, requests[idx][0]
				}
			}
			// Stop tracking this bit (and alloc notifications if no more work is available)
			// 从未分配比特位中删除
			delete(unallocs, bit)
			// 未分配比特位长度是0了就冻结这个分支
			// assign函数里面有可能会重新激活这个分支
			if len(unallocs) == 0 {
				// 设置为nil之后,这个retrievers分支就相当于被禁用
				retrievers = nil
			}
			// 自增已分配的比特位个数
			allocs++
			// 将比特位发送给allocateRetrieval
			fetcher <- bit

		// 为查询 请求队列长度(pendingSections) 提供服务
		case fetcher := <-m.counters:
			// New task count request arrives, return number of items
			// 先接收要查询的比特位，然后将请求队列长度发送过去
			fetcher <- uint(len(requests[<-fetcher]))

		// allocateSections函数要取得某个比特位的请求队列
		case fetcher := <-m.retrievals:
			// New fetcher waiting for tasks to retrieve, assign
			// 接收从allocateSections发送来的Retrieval对象
			task := <-fetcher
			// 要接收的请求个数大于实际队列中的，直接返回整个队列
			if want := len(task.Sections); want >= len(requests[task.Bit]) {
				// 填充返回的请求
				task.Sections = requests[task.Bit]
				// 所有请求都返回，清空请求队列
				delete(requests, task.Bit)
				// 要接收的请求个数小于实际队列中的，返回队列开头的部分
			} else {
				// 填充返回的请求
				task.Sections = append(task.Sections[:0], requests[task.Bit][:want]...)
				// 移除请求队列前面被返回的部分
				requests[task.Bit] = append(requests[task.Bit][:0], requests[task.Bit][want:]...)
			}
			// 将数据发送回allocateSections
			fetcher <- task

			// If anything was left unallocated, try to assign to someone else
			if len(requests[task.Bit]) > 0 {
				assign(task.Bit)
			}

		// 将服务端提交的数据，通过调度器的deliver方法，提交给调度器
		case result := <-m.deliveries:
			// New retrieval task response from fetcher, split out missing sections and
			// deliver complete ones
			var (
				// 保存服务端成功查询的区块段号
				sections = make([]uint64, 0, len(result.Sections))
				// 保存与sections里面保存的区块段号对应的位集
				bitsets = make([][]byte, 0, len(result.Bitsets))
				// 保存没有查询到数据的区块段号
				missing = make([]uint64, 0, len(result.Sections))
			)
			// 服务端提交的数据中有可能某些区块段是空数据
			// 过滤掉提交的空数据（bitset中长度为0的项），需要保证sections与bitsets一一对应
			for i, bitset := range result.Bitsets {
				// 位集长度是0，说明服务端在这个区块段上没有查询成功
				if len(bitset) == 0 {
					missing = append(missing, result.Sections[i])
					// 查询结果长度是0的不放到最终结果中
					continue
				}
				// sections与bitsets一一对应
				sections = append(sections, result.Sections[i])
				bitsets = append(bitsets, bitset)
			}
			// 向调度器提交过滤后的数据
			m.schedulers[result.Bit].deliver(sections, bitsets)
			allocs--

			// Reschedule missing sections and allocate bit if newly available
			if len(missing) > 0 {
				// 重新发送没有查询成功的请求
				queue := requests[result.Bit]
				// 将缺失数据的区块段重新加入到请求队列中
				for _, section := range missing {
					index := sort.Search(len(queue), func(i int) bool { return queue[i] >= section })
					// 在index位置向queue插入section
					queue = append(queue[:index], append([]uint64{section}, queue[index:]...)...)
				}
				requests[result.Bit] = queue

				// 如果是新建的请求队列需要被分配
				if len(queue) == len(missing) {
					assign(result.Bit)
				}
			}

			// End the session when all pending deliveries have arrived.
			if shutdown == nil && allocs == 0 {
				return
			}
		}
	}
}

// MatcherSession is returned by a started matcher to be used as a terminator
// for the actively running matching operation.
// 调用Matcher.Start后返回MatcherSession对象
// 可以使用MatcherSession.Close方法来终止查询过程
type MatcherSession struct {
	matcher *Matcher

	// sync.Once类型能保证closer.Do(f)内的函数f只被执行一次
	// closer和quit共同实现Close函数
	closer sync.Once     // Sync object to ensure we only ever close once
	quit   chan struct{} // Quit channel to request pipeline termination

	ctx     context.Context // Context used by the light client to abort filtering
	err     error           // Global error to track retrieval failures deep in the chain
	errLock sync.Mutex

	// 匹配器中每启动一个协程就加一
	// 用于关闭匹配器时等待协程执行完成
	pend sync.WaitGroup
}

// Close stops the matching process and waits for all subprocesses to terminate
// before returning. The timeout may be used for graceful shutdown, allowing the
// currently running retrievals to complete before this time.
// 关闭一个匹配器的匹配过程
func (s *MatcherSession) Close() {
	s.closer.Do(func() {
		// Signal termination and wait for all goroutines to tear down
		// 通知所有协程关闭
		close(s.quit)
		// 等待协程关闭完成
		s.pend.Wait()
	})
}

// Error returns any failure encountered during the matching session.
// 返回匹配会话中发生的错误
func (s *MatcherSession) Error() error {
	s.errLock.Lock()
	defer s.errLock.Unlock()

	return s.err
}

// 先调用allocateRetrieval
// 再调用allocateSections
// 中间过程会调用pendingSections来查询还剩余多少section

// allocateRetrieval assigns a bloom bit index to a client process that can either
// immediately request and fetch the section contents assigned to this bit or wait
// a little while for more sections to be requested.
// 获取一个还未被分配的比特位
func (s *MatcherSession) allocateRetrieval() (uint, bool) {
	fetcher := make(chan uint)

	select {
	case <-s.quit:
		return 0, false
		// 向retrievers写入fetcher
	case s.matcher.retrievers <- fetcher:
		bit, ok := <-fetcher
		return bit, ok
	}
}

// pendingSections returns the number of pending section retrievals belonging to
// the given bloom bit index.
// 查询指定比特位的请求队列有多长
func (s *MatcherSession) pendingSections(bit uint) int {
	fetcher := make(chan uint)

	select {
	case <-s.quit:
		return 0
	case s.matcher.counters <- fetcher:
		// 将要查询的比特位发送过去
		fetcher <- bit
		// distributor函数里的接收方读取比特位后再写入fetcher结果
		return int(<-fetcher)
	}
}

// allocateSections assigns all or part of an already allocated bit-task queue
// to the requesting process.
// 查询指定比特位的请求队列，取回队列的前count个请求
func (s *MatcherSession) allocateSections(bit uint, count int) []uint64 {
	fetcher := make(chan *Retrieval)

	select {
	case <-s.quit:
		return nil
	case s.matcher.retrievals <- fetcher:
		task := &Retrieval{
			Bit:      bit,
			Sections: make([]uint64, count),
		}
		fetcher <- task
		return (<-fetcher).Sections
	}
}

// deliverSections delivers a batch of section bit-vectors for a specific bloom
// bit index to be injected into the processing pipeline.
// 提交来自服务端的查询结果，bitsets[i]代表sections[i]这个区块段在bit这个比特位上的位集
func (s *MatcherSession) deliverSections(bit uint, sections []uint64, bitsets [][]byte) {
	s.matcher.deliveries <- &Retrieval{Bit: bit, Sections: sections, Bitsets: bitsets}
}

// Multiplex polls the matcher session for retrieval tasks and multiplexes it into
// the requested retrieval queue to be serviced together with other sessions.
//
// This method will block for the lifetime of the session. Even after termination
// of the session, any request in-flight need to be responded to! Empty responses
// are fine though in that case.
// batch代表一次发送请求的个数，wait代表如果个数不足batch等待的时间
func (s *MatcherSession) Multiplex(batch int, wait time.Duration, mux chan chan *Retrieval) {
	for {
		// allocateRetrieval与deliverSections调用是一一对应
		// Allocate a new bloom bit index to retrieve data for, stopping when done
		bit, ok := s.allocateRetrieval()
		if !ok {
			return
		}
		// Bit allocated, throttle a bit if we're below our batch limit
		// 如果还没有派发出去的请求没有达到batch的话，就等待用户设置的时间后再派发请求
		if s.pendingSections(bit) < batch {
			select {
			// 检测到退出
			case <-s.quit:
				// Session terminating, we can't meaningfully service, abort
				s.allocateSections(bit, 0)
				s.deliverSections(bit, []uint64{}, [][]byte{})
				return

			case <-time.After(wait):
				// Throttling up, fetch whatever's available
			}
		}
		// Allocate as much as we can handle and request servicing
		sections := s.allocateSections(bit, batch)
		// 向服务端发送的是一个管道，每次发送请求都要发送新的管道
		// 发送一个请求包括两步
		// 创建发送Retrieval对象的管道，向新建的管道发送Retrieval对象
		request := make(chan *Retrieval)

		select {
		case <-s.quit:
			// Session terminating, we can't meaningfully service, abort
			s.deliverSections(bit, sections, make([][]byte, len(sections)))
			return

		// 向外部发送真正的查询请求
		case mux <- request:
			// Retrieval accepted, something must arrive before we're aborting
			// 发送真正的请求内容
			request <- &Retrieval{Bit: bit, Sections: sections, Context: s.ctx}

			// 接收服务端返回的结果
			result := <-request
			if result.Error != nil {
				s.errLock.Lock()
				s.err = result.Error
				s.errLock.Unlock()
				s.Close()
			}
			// 提交服务端的查询结果
			s.deliverSections(result.Bit, result.Sections, result.Bitsets)
		}
	}
}
