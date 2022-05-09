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

package dnsdisc

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Client discovers nodes by querying DNS servers.
// Client对象用于执行DNS查询
// 查询时先查询缓存entries,缓存中没有则使用cfg.Resolver执行DNS查询
type Client struct {
	cfg          Config
	clock        mclock.Clock
	entries      *lru.Cache
	ratelimit    *rate.Limiter
	singleflight singleflight.Group
}

// Config holds configuration options for the client.
type Config struct {
	Timeout time.Duration // timeout used for DNS lookups (default 5s)
	// 每三十分钟重新查询一次域名的根记录
	RecheckInterval time.Duration      // time between tree root update checks (default 30min)
	CacheLimit      int                // maximum number of cached records (default 1000)
	RateLimit       float64            // maximum DNS requests / second (default 3)
	ValidSchemes    enr.IdentityScheme // acceptable ENR identity schemes (default enode.ValidSchemes)
	Resolver        Resolver           // the DNS resolver to use (defaults to system DNS)
	Logger          log.Logger         // destination of client log messages (defaults to root logger)
}

// Resolver is a DNS resolver that can query TXT records.
// 用来查询DNS请求的对象
type Resolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// 设置默认选项
func (cfg Config) withDefaults() Config {
	const (
		defaultTimeout   = 5 * time.Second
		defaultRecheck   = 30 * time.Minute
		defaultRateLimit = 3
		defaultCache     = 1000
	)
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.RecheckInterval == 0 {
		cfg.RecheckInterval = defaultRecheck
	}
	if cfg.CacheLimit == 0 {
		cfg.CacheLimit = defaultCache
	}
	// 默认每秒最多发起三个dns请求
	if cfg.RateLimit == 0 {
		cfg.RateLimit = defaultRateLimit
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Resolver == nil {
		cfg.Resolver = new(net.Resolver)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Root()
	}
	return cfg
}

// NewClient creates a client.
// 创建Client对象,用来从某一个链接同步节点数据
func NewClient(cfg Config) *Client {
	// 为输入的配置每设置的项设置默认值
	cfg = cfg.withDefaults()
	cache, err := lru.New(cfg.CacheLimit)
	if err != nil {
		panic(err)
	}
	// 创建限流器
	rlimit := rate.NewLimiter(rate.Limit(cfg.RateLimit), 10)
	return &Client{
		cfg:       cfg,
		entries:   cache,
		clock:     mclock.System{},
		ratelimit: rlimit,
	}
}

// SyncTree downloads the entire node tree at the given URL.
// 从指定的链接开始同步节点信息的梅克尔树
func (c *Client) SyncTree(url string) (*Tree, error) {
	le, err := parseLink(url)
	if err != nil {
		return nil, fmt.Errorf("invalid enrtree URL: %v", err)
	}
	ct := newClientTree(c, new(linkCache), le)
	t := &Tree{entries: make(map[string]entry)}
	if err := ct.syncAll(t.entries); err != nil {
		return nil, err
	}
	t.root = ct.root
	return t, nil
}

// NewIterator creates an iterator that visits all nodes at the
// given tree URLs.
// 传入多个链接,生成一个节点的迭代器,在传入的这些链接间迭代节点
func (c *Client) NewIterator(urls ...string) (enode.Iterator, error) {
	it := c.newRandomIterator()
	// 将传入的链接都加入到linkCache中
	for _, url := range urls {
		if err := it.addTree(url); err != nil {
			return nil, err
		}
	}
	return it, nil
}

// resolveRoot retrieves a root entry via DNS.
// 向loc.domain查询根节点的记录,返回rootEntry对象
func (c *Client) resolveRoot(ctx context.Context, loc *linkEntry) (rootEntry, error) {
	// 使用singleflight的目的是如果多次查询同样的loc.str只会执行一次里面定义的回调函数
	e, err, _ := c.singleflight.Do(loc.str, func() (interface{}, error) {
		txts, err := c.cfg.Resolver.LookupTXT(ctx, loc.domain)
		c.cfg.Logger.Trace("Updating DNS discovery root", "tree", loc.domain, "err", err)
		if err != nil {
			return rootEntry{}, err
		}
		// 遍历查询到的记录,有没有以"enrtree-root:v1"开头的
		// 找到后验证内部保存的签名是否正确
		for _, txt := range txts {
			if strings.HasPrefix(txt, rootPrefix) {
				return parseAndVerifyRoot(txt, loc)
			}
		}
		return rootEntry{}, nameError{loc.domain, errNoRoot}
	})
	return e.(rootEntry), err
}

// 判断txt里面保存的根节点的签名是否正确,是否是使用loc.pubkey进行的签名
func parseAndVerifyRoot(txt string, loc *linkEntry) (rootEntry, error) {
	e, err := parseRoot(txt)
	if err != nil {
		return e, err
	}
	if !e.verifySignature(loc.pubkey) {
		return e, entryError{typ: "root", err: errInvalidSig}
	}
	return e, nil
}

// resolveEntry retrieves an entry from the cache or fetches it from the network
// if it isn't cached.
// 解析 hash.domain 域名对应的txt记录并解析成entry对象
// 首先从缓存中查询,没有的话再从网络上查询
func (c *Client) resolveEntry(ctx context.Context, domain, hash string) (entry, error) {
	// The rate limit always applies, even when the result might be cached. This is
	// important because it avoids hot-spinning in consumers of node iterators created on
	// this client.
	// 用ratelimit来限制查询的速度
	if err := c.ratelimit.Wait(ctx); err != nil {
		return nil, err
	}
	// 先从缓存中查找
	cacheKey := truncateHash(hash)
	if e, ok := c.entries.Get(cacheKey); ok {
		return e.(entry), nil
	}

	// 缓存中每找到,执行dns查询
	ei, err, _ := c.singleflight.Do(cacheKey, func() (interface{}, error) {
		e, err := c.doResolveEntry(ctx, domain, hash)
		if err != nil {
			return nil, err
		}
		// 查询到的结果保存到缓存中
		c.entries.Add(cacheKey, e)
		return e, nil
	})
	e, _ := ei.(entry)
	return e, err
}

// doResolveEntry fetches an entry via DNS.
// 执行实际的DNS请求,并解析出来entry对象
func (c *Client) doResolveEntry(ctx context.Context, domain, hash string) (entry, error) {
	wantHash, err := b32format.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 hash")
	}
	name := hash + "." + domain
	txts, err := c.cfg.Resolver.LookupTXT(ctx, hash+"."+domain)
	c.cfg.Logger.Trace("DNS discovery lookup", "name", name, "err", err)
	if err != nil {
		return nil, err
	}
	for _, txt := range txts {
		e, err := parseEntry(txt, c.cfg.ValidSchemes)
		if err == errUnknownEntry {
			continue
		}
		// 校验域名里的hash是否与查询结果一致
		if !bytes.HasPrefix(crypto.Keccak256([]byte(txt)), wantHash) {
			err = nameError{name, errHashMismatch}
		} else if err != nil {
			err = nameError{name, err}
		}
		return e, err
	}
	return nil, nameError{name, errNoEntry}
}

// randomIterator traverses a set of trees and returns nodes found in them.
// 实现了enode.Iterator接口,用来遍历多个链接中保存的节点
type randomIterator struct {
	// 迭代器当前的节点
	cur      *enode.Node
	ctx      context.Context
	cancelFn context.CancelFunc
	c        *Client

	mu sync.Mutex
	// 保存遍历过程遇到的所有链接以及他们之间的引用关系
	lc    linkCache              // tracks tree dependencies
	trees map[string]*clientTree // all trees
	// buffers for syncableTrees
	syncableList []*clientTree
	disabledList []*clientTree
}

func (c *Client) newRandomIterator() *randomIterator {
	ctx, cancel := context.WithCancel(context.Background())
	return &randomIterator{
		c:        c,
		ctx:      ctx,
		cancelFn: cancel,
		trees:    make(map[string]*clientTree),
	}
}

// Node returns the current node.
func (it *randomIterator) Node() *enode.Node {
	return it.cur
}

// Close closes the iterator.
// 关闭迭代器
func (it *randomIterator) Close() {
	it.cancelFn()

	it.mu.Lock()
	defer it.mu.Unlock()
	it.trees = nil
}

// Next moves the iterator to the next node.
// 获取下一个节点
func (it *randomIterator) Next() bool {
	it.cur = it.nextNode()
	return it.cur != nil
}

// addTree adds an enrtree:// URL to the iterator.
// 传入的url是NewIterator的各个url
// 将链接加入到linkCache中,并且都设置他们被空字符串引用
// 保证都能在rebuildTrees中创建对应的clientTree对象
func (it *randomIterator) addTree(url string) error {
	le, err := parseLink(url)
	if err != nil {
		return fmt.Errorf("invalid enrtree URL: %v", err)
	}
	it.lc.addLink("", le.str)
	return nil
}

// nextNode syncs random tree entries until it finds a node.
// 迭代器中同步下一条enr记录
// 1. 随机确定要从哪条链接同步,也就是随机一个clientTree
// 2. 再调用这个clientTree的syncRandom
// 3. syncRandom可能同步到的是branchEntry返回nil
//    所以不断循环直到返回不是nil,得到真正的下一条enr记录,进行返回
func (it *randomIterator) nextNode() *enode.Node {
	for {
		ct := it.pickTree()
		if ct == nil {
			return nil
		}
		n, err := ct.syncRandom(it.ctx)
		if err != nil {
			if err == it.ctx.Err() {
				return nil // context canceled.
			}
			it.c.cfg.Logger.Debug("Error in DNS random node sync", "tree", ct.loc.domain, "err", err)
			continue
		}
		if n != nil {
			return n
		}
	}
}

// pickTree returns a random tree to sync from.
// 从it.trees中随机挑选一个可以进行同步的clientTree对象
func (it *randomIterator) pickTree() *clientTree {
	it.mu.Lock()
	defer it.mu.Unlock()

	// First check if iterator was closed.
	// Need to do this here to avoid nil map access in rebuildTrees.
	if it.trees == nil {
		return nil
	}

	// Rebuild the trees map if any links have changed.
	// 链接间的引用关系发生了变化,就重新创建clientTree对象们
	if it.lc.changed {
		it.rebuildTrees()
		it.lc.changed = false
	}

	// 一直循环直到canSync为true,除非it.ctx执行了取消
	for {
		canSync, trees := it.syncableTrees()
		switch {
		case canSync:
			// Pick a random tree.
			return trees[rand.Intn(len(trees))]
		// 不能同步,这时候返回的是disabledList
		case len(trees) > 0:
			// No sync action can be performed on any tree right now. The only meaningful
			// thing to do is waiting for any root record to get updated.
			// 如果等待过程中it.ctx结束了,那么直接返回
			// 如果等待到下一次树根更新重新执行一次for循环
			if !it.waitForRootUpdates(trees) {
				// Iterator was closed while waiting.
				return nil
			}
		default:
			// There are no trees left, the iterator was closed.
			return nil
		}
	}
}

// syncableTrees finds trees on which any meaningful sync action can be performed.
// 遍历it.trees,按照可不可以同步区分保存到it.syncableList和it.disabledList中
func (it *randomIterator) syncableTrees() (canSync bool, trees []*clientTree) {
	// Resize tree lists.
	it.syncableList = it.syncableList[:0]
	it.disabledList = it.disabledList[:0]

	// Partition them into the two lists.
	for _, ct := range it.trees {
		if ct.canSyncRandom() {
			it.syncableList = append(it.syncableList, ct)
		} else {
			it.disabledList = append(it.disabledList, ct)
		}
	}
	// 有可以同步的,返回syncableList
	if len(it.syncableList) > 0 {
		return true, it.syncableList
	}
	// 没有可以同步的,返回disabledList
	return false, it.disabledList
}

// waitForRootUpdates waits for the closest scheduled root check time on the given trees.
// 调用后会阻塞到下一次更新树根的时间
// 如果是更新树根的时间到了返回true,如果是it.ctx结束了返回false
func (it *randomIterator) waitForRootUpdates(trees []*clientTree) bool {
	// 找到下次更新时间最近的clientTree对象
	var minTree *clientTree
	var nextCheck mclock.AbsTime
	for _, ct := range trees {
		check := ct.nextScheduledRootCheck()
		if minTree == nil || check < nextCheck {
			minTree = ct
			nextCheck = check
		}
	}

	// 接下来阻塞到下一次树根更新
	sleep := nextCheck.Sub(it.c.clock.Now())
	it.c.cfg.Logger.Debug("DNS iterator waiting for root updates", "sleep", sleep, "tree", minTree.loc.domain)
	timeout := it.c.clock.NewTimer(sleep)
	defer timeout.Stop()
	select {
	case <-timeout.C():
		return true
	case <-it.ctx.Done():
		return false // Iterator was closed.
	}
}

// rebuildTrees rebuilds the 'trees' map.
// 将linkCache中所有被引用的链接构造成clientTree,保存到it.trees
func (it *randomIterator) rebuildTrees() {
	// Delete removed trees.
	// 判断各个树要同步的链接还有没有被引用,没有引用就删除这个树
	for loc := range it.trees {
		if !it.lc.isReferenced(loc) {
			delete(it.trees, loc)
		}
	}
	// Add new trees.
	// 将所有被引用的链接构造成clientTree
	for loc := range it.lc.backrefs {
		if it.trees[loc] == nil {
			link, _ := parseLink(linkPrefix + loc)
			it.trees[loc] = newClientTree(it.c, &it.lc, link)
		}
	}
}
