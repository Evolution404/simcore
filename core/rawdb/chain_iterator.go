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

package rawdb

import (
	"runtime"
	"sync/atomic"
	"time"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/common/prque"
	"github.com/Evolution404/simcore/core/types"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/rlp"
)

// InitDatabaseFromFreezer reinitializes an empty database from a previous batch
// of frozen ancient blocks. The method iterates over all the frozen blocks and
// injects into the database the block hash->number mappings.
// 从freezer中新建一个数据库对象
// 读取freezer里保存的区块哈希,恢复到数据库的hash->number映射里
// 恢复headHeaderHash和headFastBlockHash
func InitDatabaseFromFreezer(db ethdb.Database) {
	// If we can't access the freezer or it's empty, abort
	frozen, err := db.Ancients()
	if err != nil || frozen == 0 {
		return
	}
	var (
		batch  = db.NewBatch()
		start  = time.Now()
		// 记录上次打印日志的时间，每8秒打印一次时间
		logged = start.Add(-7 * time.Second) // Unindex during import is fast, don't double log
		hash   common.Hash
	)
	for i := uint64(0); i < frozen; {
		// We read 100K hashes at a time, for a total of 3.2M
		count := uint64(100_000)
		if i+count > frozen {
			count = frozen - i
		}
		data, err := db.AncientRange(freezerHashTable, i, count, 32*count)
		if err != nil {
			log.Crit("Failed to init database from freezer", "err", err)
		}
		for j, h := range data {
			number := i + uint64(j)
			hash = common.BytesToHash(h)
			WriteHeaderNumber(batch, hash, number)
			// If enough data was accumulated in memory or we're at the last block, dump to disk
			if batch.ValueSize() > ethdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					log.Crit("Failed to write data to db", "err", err)
				}
				batch.Reset()
			}
		}
		i += uint64(len(data))
		// If we've spent too much time already, notify the user of what we're doing
		if time.Since(logged) > 8*time.Second {
			log.Info("Initializing database from freezer", "total", frozen, "number", i, "hash", hash, "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write data to db", "err", err)
	}
	batch.Reset()

	WriteHeadHeaderHash(db, hash)
	WriteHeadFastBlockHash(db, hash)
	log.Info("Initialized database from freezer", "blocks", frozen, "elapsed", common.PrettyDuration(time.Since(start)))
}

type blockTxHashes struct {
	number uint64
	hashes []common.Hash
}

// iterateTransactions iterates over all transactions in the (canon) block
// number(s) given, and yields the hashes on a channel. If there is a signal
// received from interrupt channel, the iteration will be aborted and result
// channel will be closed.
// 查询从from区块到to区块的交易哈希
// 返回的管道一次接收一个区块内的所有交易哈希
// 默认从from到to查询,reverse为true那么从to到from查询
func iterateTransactions(db ethdb.Database, from uint64, to uint64, reverse bool, interrupt chan struct{}) chan *blockTxHashes {
	// One thread sequentially reads data from db
	type numberRlp struct {
		number uint64
		rlp    rlp.RawValue
	}
	if to == from {
		return nil
	}
	// 计算启动的线程数：min(遍历的区块数, cpu的核数)
	threads := to - from
	if cpus := runtime.NumCPU(); threads > uint64(cpus) {
		threads = uint64(cpus)
	}
	var (
		rlpCh    = make(chan *numberRlp, threads*2)     // we send raw rlp over this channel
		hashesCh = make(chan *blockTxHashes, threads*2) // send hashes over hashesCh
	)
	// lookup runs in one instance
	lookup := func() {
		// 没有reverse查询顺序 from,from+1,...,to-1
		// 有了reverse查询顺序 to-1,to-2,...,from
		n, end := from, to
		if reverse {
			n, end = to-1, from-1
		}
		defer close(rlpCh)
		for n != end {
			data := ReadCanonicalBodyRLP(db, n)
			// Feed the block to the aggregator, or abort on interrupt
			select {
			// 将查询结果写入rlpCh
			case rlpCh <- &numberRlp{n, data}:
			case <-interrupt:
				return
			}
			if reverse {
				n--
			} else {
				n++
			}
		}
	}
	// process runs in parallel
	nThreadsAlive := int32(threads)
	// 每个子线程接收rlp编码进行解码操作,写入输出管道
	// 可能是rlp解码工作耗费性能,进行并行操作
	process := func() {
		defer func() {
			// Last processor closes the result channel
			// 每个线程结束让计数器减一,计数器为0关闭输出管道
			if atomic.AddInt32(&nThreadsAlive, -1) == 0 {
				close(hashesCh)
			}
		}()
		// 接收rlp编码进行解码
		for data := range rlpCh {
			var body types.Body
			if err := rlp.DecodeBytes(data.rlp, &body); err != nil {
				log.Warn("Failed to decode block body", "block", data.number, "error", err)
				return
			}
			var hashes []common.Hash
			for _, tx := range body.Transactions {
				hashes = append(hashes, tx.Hash())
			}
			result := &blockTxHashes{
				hashes: hashes,
				number: data.number,
			}
			// Feed the block to the aggregator, or abort on interrupt
			select {
			case hashesCh <- result:
			case <-interrupt:
				return
			}
		}
	}
	// 读写操作并行进行
	// 读入数据写入管道,然后由并行的解码线程进行接收处理
	go lookup() // start the sequential db accessor
	for i := 0; i < int(threads); i++ {
		go process()
	}
	return hashesCh
}

// indexTransactions creates txlookup indices of the specified block range.
//
// This function iterates canonical chain in reverse order, it has one main advantage:
// We can write tx index tail flag periodically even without the whole indexing
// procedure is finished. So that we can resume indexing procedure next time quickly.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// 对交易进行索引,也就是从旧数据中读取交易信息,将 交易哈希->所在区块号 映射保存到数据库
func indexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	// short circuit for invalid range
	if from >= to {
		return
	}
	var (
		// 在协程内遍历区块中的交易,返回一个管道用于接收查询结果
		hashesCh = iterateTransactions(db, from, to, true, interrupt)
		batch    = db.NewBatch()
		start    = time.Now()
		logged   = start.Add(-7 * time.Second)
		// Since we iterate in reverse, we expect the first number to come
		// in to be [to-1]. Therefore, setting lastNum to means that the
		// prqueue gap-evaluation will work correctly
		lastNum = to
		// 使用优先队列保存交易,每个元素是一个区块内的所有哈希,优先级是块号
		queue   = prque.New(nil)
		// for stats reporting
		// 分别记录已经写入了几个区块,多少条交易
		blocks, txs = 0, 0
	)
	// 遍历接收协程查询的结果
	// 管道返回的区块并不一定是按照倒序发送的，但是这里要求从最高的区块开始索引，所以使用了优先队列来保证顺序
	for chanDelivery := range hashesCh {
		// Push the delivery into the queue and process contiguous ranges.
		// Since we iterate in reverse, so lower numbers have lower prio, and
		// we can use the number directly as prio marker
		// 需要保证最高的区块最先被索引，所以使用块号作为优先级
		queue.Push(chanDelivery, int64(chanDelivery.number))
		for !queue.Empty() {
			// If the next available item is gapped, return
			// 一直在判断优先队列中优先级最高的元素的区块高度是否是最后一个区块,也就是保证按照倒序来进行索引
			if _, priority := queue.Peek(); priority != int64(lastNum-1) {
				break
			}
			// For testing
			if hook != nil && !hook(lastNum-1) {
				break
			}
			// Next block available, pop it off and index it
			// 读取最后一个区块
			delivery := queue.PopItem().(*blockTxHashes)
			// 让lastNum向前移动一位
			lastNum = delivery.number
			// 写入这一批交易信息到数据库中
			WriteTxLookupEntries(batch, delivery.number, delivery.hashes)
			// 这个区块的索引已经完成,区块数量加一,交易数加上这个区块内的交易
			blocks++
			txs += len(delivery.hashes)
			// If enough data was accumulated in memory or we're at the last block, dump to disk
			if batch.ValueSize() > ethdb.IdealBatchSize {
				// 记录数据库中索引位置
				WriteTxIndexTail(batch, lastNum) // Also write the tail here
				if err := batch.Write(); err != nil {
					log.Crit("Failed writing batch to db", "error", err)
					return
				}
				batch.Reset()
			}
			// If we've spent too much time already, notify the user of what we're doing
			if time.Since(logged) > 8*time.Second {
				log.Info("Indexing transactions", "blocks", blocks, "txs", txs, "tail", lastNum, "total", to-from, "elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
		}
	}
	// Flush the new indexing tail and the last committed data. It can also happen
	// that the last batch is empty because nothing to index, but the tail has to
	// be flushed anyway.
	WriteTxIndexTail(batch, lastNum)
	if err := batch.Write(); err != nil {
		log.Crit("Failed writing batch to db", "error", err)
		return
	}
	select {
	case <-interrupt:
		log.Debug("Transaction indexing interrupted", "blocks", blocks, "txs", txs, "tail", lastNum, "elapsed", common.PrettyDuration(time.Since(start)))
	default:
		log.Info("Indexed transactions", "blocks", blocks, "txs", txs, "tail", lastNum, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

// IndexTransactions creates txlookup indices of the specified block range. The from
// is included while to is excluded.
//
// This function iterates canonical chain in reverse order, it has one main advantage:
// We can write tx index tail flag periodically even without the whole indexing
// procedure is finished. So that we can resume indexing procedure next time quickly.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// 对范围[from,to)的区块内交易进行索引
// 索引指向数据库内保存 交易哈希->交易所在区块 映射
// 索引过程从to-1区块一直到from区块,倒序
func IndexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}) {
	indexTransactions(db, from, to, interrupt, nil)
}

// indexTransactionsForTesting is the internal debug version with an additional hook.
func indexTransactionsForTesting(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	indexTransactions(db, from, to, interrupt, hook)
}

// unindexTransactions removes txlookup indices of the specified block range.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// 删除从from到to区块内交易的索引
// 删除过程从from到to-1,正序
func unindexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	// short circuit for invalid range
	if from >= to {
		return
	}
	var (
		hashesCh = iterateTransactions(db, from, to, false, interrupt)
		batch    = db.NewBatch()
		start    = time.Now()
		logged   = start.Add(-7 * time.Second)
		// we expect the first number to come in to be [from]. Therefore, setting
		// nextNum to from means that the prqueue gap-evaluation will work correctly
		nextNum = from
		queue   = prque.New(nil)
		// for stats reporting
		blocks, txs = 0, 0
	)
	// Otherwise spin up the concurrent iterator and unindexer
	for delivery := range hashesCh {
		// Push the delivery into the queue and process contiguous ranges.
		// 这里加上负号使得区块号越小的优先级越大,先从区块号小的删除
		queue.Push(delivery, -int64(delivery.number))
		for !queue.Empty() {
			// If the next available item is gapped, return
			if _, priority := queue.Peek(); -priority != int64(nextNum) {
				break
			}
			// For testing
			if hook != nil && !hook(nextNum) {
				break
			}
			delivery := queue.PopItem().(*blockTxHashes)
			nextNum = delivery.number + 1
			// 删除一个区块内交易的索引
			DeleteTxLookupEntries(batch, delivery.hashes)
			txs += len(delivery.hashes)
			blocks++

			// If enough data was accumulated in memory or we're at the last block, dump to disk
			// A batch counts the size of deletion as '1', so we need to flush more
			// often than that.
			if blocks%1000 == 0 {
				WriteTxIndexTail(batch, nextNum)
				if err := batch.Write(); err != nil {
					log.Crit("Failed writing batch to db", "error", err)
					return
				}
				batch.Reset()
			}
			// If we've spent too much time already, notify the user of what we're doing
			if time.Since(logged) > 8*time.Second {
				log.Info("Unindexing transactions", "blocks", blocks, "txs", txs, "total", to-from, "elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
		}
	}
	// Flush the new indexing tail and the last committed data. It can also happen
	// that the last batch is empty because nothing to unindex, but the tail has to
	// be flushed anyway.
	WriteTxIndexTail(batch, nextNum)
	if err := batch.Write(); err != nil {
		log.Crit("Failed writing batch to db", "error", err)
		return
	}
	select {
	case <-interrupt:
		log.Debug("Transaction unindexing interrupted", "blocks", blocks, "txs", txs, "tail", to, "elapsed", common.PrettyDuration(time.Since(start)))
	default:
		log.Info("Unindexed transactions", "blocks", blocks, "txs", txs, "tail", to, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

// UnindexTransactions removes txlookup indices of the specified block range.
// The from is included while to is excluded.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// 删除[from,to)区块内交易的索引
// 按照从from到to-1的顺序,正序删除
func UnindexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}) {
	unindexTransactions(db, from, to, interrupt, nil)
}

// unindexTransactionsForTesting is the internal debug version with an additional hook.
func unindexTransactionsForTesting(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	unindexTransactions(db, from, to, interrupt, hook)
}
