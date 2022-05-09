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

package dnsdisc

import (
	"context"
	"math/rand"
	"time"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/p2p/enode"
)

// This is the number of consecutive leaf requests that may fail before
// we consider re-resolving the tree root.
const rootRecheckFailCount = 5

// clientTree is a full tree being synced.
// clientTree对象与链接一一对应,用来同步内部保存的链接
// 比如链接: enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net
type clientTree struct {
	c   *Client
	loc *linkEntry // link to this tree

	// 记录上一次调用updateRoot的时间
	lastRootCheck mclock.AbsTime // last revalidation of root
	leafFailCount int
	rootFailCount int

	root  *rootEntry
	enrs  *subtreeSync
	links *subtreeSync

	lc *linkCache // tracks all links between all trees
	// 链接树里保存的其他域名保存在这里
	curLinks map[string]struct{} // links contained in this tree
	// 调用gcLinks后会更新这个的值为ct.root.lroot
	linkGCRoot string // root on which last link GC has run
}

func newClientTree(c *Client, lc *linkCache, loc *linkEntry) *clientTree {
	return &clientTree{c: c, lc: lc, loc: loc}
}

// syncAll retrieves all entries of the tree.
// 同步所有记录到dest中,包括links和enrs
// dest记录的键是base32字符串,域名的最开始部分
// 例如:"QEJND7PRRXHXW4CTT5IG2AXE2Y.all.mainnet.ethdisco.net",中的"QEJND7PRRXHXW4CTT5IG2AXE2Y"
// 这个保存的是dns的txt记录的keccak256的前16字节的base32编码
func (ct *clientTree) syncAll(dest map[string]entry) error {
	if err := ct.updateRoot(context.Background()); err != nil {
		return err
	}
	if err := ct.links.resolveAll(dest); err != nil {
		return err
	}
	if err := ct.enrs.resolveAll(dest); err != nil {
		return err
	}
	return nil
}

// syncRandom retrieves a single entry of the tree. The Node return value
// is non-nil if the entry was a node.
// 随机的查询树中的一个节点
// 查询到了新纪录返回enode.Node对象
// 如果查询到了branchEntry对象,那么返回nil
func (ct *clientTree) syncRandom(ctx context.Context) (n *enode.Node, err error) {
	// 判断是否需要更新树根
	if ct.rootUpdateDue() {
		if err := ct.updateRoot(ctx); err != nil {
			return nil, err
		}
	}

	// Update fail counter for leaf request errors.
	defer func() {
		if err != nil {
			ct.leafFailCount++
		}
	}()

	// Link tree sync has priority, run it to completion before syncing ENRs.
	if !ct.links.done() {
		err := ct.syncNextLink(ctx)
		return nil, err
	}
	ct.gcLinks()

	// Sync next random entry in ENR tree. Once every node has been visited, we simply
	// start over. This is fine because entries are cached internally by the client LRU
	// also by DNS resolvers.
	// enrs已经全部同步完了就重新开始
	if ct.enrs.done() {
		ct.enrs = newSubtreeSync(ct.c, ct.loc, ct.root.eroot, false)
	}
	// 同步下一条enr记录
	return ct.syncNextRandomENR(ctx)
}

// canSyncRandom checks if any meaningful action can be performed by syncRandom.
// 已经完全同步完成了但是在enrs树中没有发现任何一个叶子节点
// 这样的树是一个空树,不能再继续同步了
func (ct *clientTree) canSyncRandom() bool {
	// Note: the check for non-zero leaf count is very important here.
	// If we're done syncing all nodes, and no leaves were found, the tree
	// is empty and we can't use it for sync.
	return ct.rootUpdateDue() || !ct.links.done() || !ct.enrs.done() || ct.enrs.leaves != 0
}

// gcLinks removes outdated links from the global link cache. GC runs once
// when the link sync finishes.
// 如果根记录发生了变化,也就是链接树的树根发生了变化
// 需要将原来的引用关系删除
func (ct *clientTree) gcLinks() {
	if !ct.links.done() || ct.root.lroot == ct.linkGCRoot {
		return
	}
	ct.lc.resetLinks(ct.loc.str, ct.curLinks)
	ct.linkGCRoot = ct.root.lroot
}

// 同步一个链接树中的节点
// 如果同步到了叶子节点其中保存的是新的链接
//   调用addLink保存到多个clientTree共用的linkCache(ct.lc)中,记录链接间引用关系
//   对于clientTree自身,保存到curLinks中
func (ct *clientTree) syncNextLink(ctx context.Context) error {
	// 取missing[0]进行同步
	hash := ct.links.missing[0]
	e, err := ct.links.resolveNext(ctx, hash)
	if err != nil {
		return err
	}
	// 同步成功从missing中移除
	ct.links.missing = ct.links.missing[1:]

	if dest, ok := e.(*linkEntry); ok {
		// from是clientTree里保存的链接
		// to是新同步到的链接,from引用了to
		ct.lc.addLink(ct.loc.str, dest.str)
		// 将新同步到的链接保存下来
		ct.curLinks[dest.str] = struct{}{}
	}
	return nil
}

// 同步enrs.missing里的一个随机节点
// 如果同步到了新记录返回enode.Node对象
// 否则返回nil
func (ct *clientTree) syncNextRandomENR(ctx context.Context) (*enode.Node, error) {
	index := rand.Intn(len(ct.enrs.missing))
	hash := ct.enrs.missing[index]
	e, err := ct.enrs.resolveNext(ctx, hash)
	if err != nil {
		return nil, err
	}
	ct.enrs.missing = removeHash(ct.enrs.missing, index)
	// 同步到的是enrEntry直接返回记录
	// 否则如果是branchEntry返回nil
	if ee, ok := e.(*enrEntry); ok {
		return ee.node, nil
	}
	return nil, nil
}

func (ct *clientTree) String() string {
	return ct.loc.String()
}

// removeHash removes the element at index from h.
// 将h[index]从h中删除,然后返回删除元素后的h
func removeHash(h []string, index int) []string {
	// 只有一个元素,删除后就变成空
	if len(h) == 1 {
		return nil
	}
	// 删除并不是把后面的元素向前移动
	// 而是将最后一个元素移动到删除位置,这样删除后没有保证原来的顺序
	last := len(h) - 1
	if index < last {
		h[index] = h[last]
		h[last] = ""
	}
	return h[:last]
}

// updateRoot ensures that the given tree has an up-to-date root.
// 获取最新的根记录,并且初始化links和enrs两颗subtreeSync对象
func (ct *clientTree) updateRoot(ctx context.Context) error {
	if !ct.slowdownRootUpdate(ctx) {
		return ctx.Err()
	}

	ct.lastRootCheck = ct.c.clock.Now()
	ctx, cancel := context.WithTimeout(ctx, ct.c.cfg.Timeout)
	defer cancel()
	// 执行DNS查询,获取最新的rootEntry记录
	root, err := ct.c.resolveRoot(ctx, ct.loc)
	// 查询失败增加失败次数的记录,然后直接返回
	if err != nil {
		ct.rootFailCount++
		return err
	}
	ct.root = &root
	ct.rootFailCount = 0
	ct.leafFailCount = 0

	// Invalidate subtrees if changed.
	if ct.links == nil || root.lroot != ct.links.root {
		ct.links = newSubtreeSync(ct.c, ct.loc, root.lroot, true)
		ct.curLinks = make(map[string]struct{})
	}
	if ct.enrs == nil || root.eroot != ct.enrs.root {
		ct.enrs = newSubtreeSync(ct.c, ct.loc, root.eroot, false)
	}
	return nil
}

// rootUpdateDue returns true when a root update is needed.
// 判断是否需要重新查询根记录
// 超过30分钟,错误次数过多,root为nil都需要重新查询
func (ct *clientTree) rootUpdateDue() bool {
	tooManyFailures := ct.leafFailCount > rootRecheckFailCount
	scheduledCheck := ct.c.clock.Now() >= ct.nextScheduledRootCheck()
	return ct.root == nil || tooManyFailures || scheduledCheck
}

// 获取下次更新树根的时间
func (ct *clientTree) nextScheduledRootCheck() mclock.AbsTime {
	return ct.lastRootCheck.Add(ct.c.cfg.RecheckInterval)
}

// slowdownRootUpdate applies a delay to root resolution if is tried
// too frequently. This avoids busy polling when the client is offline.
// Returns true if the timeout passed, false if sync was canceled.
// rootFailCount次数过多的话这个函数会进行阻塞,避免解析root的流程过于频繁
func (ct *clientTree) slowdownRootUpdate(ctx context.Context) bool {
	var delay time.Duration
	switch {
	// 超过20次阻塞10秒
	case ct.rootFailCount > 20:
		delay = 10 * time.Second
	// 超过5次阻塞5秒
	case ct.rootFailCount > 5:
		delay = 5 * time.Second
	// 小于等于5次这个函数不阻塞直接返回
	default:
		return true
	}
	timeout := ct.c.clock.NewTimer(delay)
	defer timeout.Stop()
	// 等待上面设定的时间
	select {
	case <-timeout.C():
		return true
	case <-ctx.Done():
		return false
	}
}

// subtreeSync is the sync of an ENR or link subtree.
// 表示当前同步一颗树的状态,有链接树和节点树
type subtreeSync struct {
	c    *Client
	loc  *linkEntry
	root string
	// 已知的缺失的节点的哈希
	missing []string // missing tree node hashes
	// 用于标记在同步链接树
	link bool // true if this sync is for the link tree
	// 记录已经同步的节点个数
	leaves int // counter of synced leaves
}

func newSubtreeSync(c *Client, loc *linkEntry, root string, link bool) *subtreeSync {
	// 初始的时候只知道缺失一个根节点
	return &subtreeSync{c, loc, root, []string{root}, link, 0}
}

// 如果missing为0说明同步完了
func (ts *subtreeSync) done() bool {
	return len(ts.missing) == 0
}

// 解析整棵树上的所有节点,查询的结果保存到dest中
func (ts *subtreeSync) resolveAll(dest map[string]entry) error {
	// 不断从missing里面获取缺失的节点的哈希进行查询
	// 查询过程中遇到branchEntry会向missing里面继续添加新的记录
	// 当前节点查询完成就从missing里面移除
	// 一直循环直到所有missing的节点都查询完成
	for !ts.done() {
		hash := ts.missing[0]
		ctx, cancel := context.WithTimeout(context.Background(), ts.c.cfg.Timeout)
		e, err := ts.resolveNext(ctx, hash)
		cancel()
		if err != nil {
			return err
		}
		dest[hash] = e
		ts.missing = ts.missing[1:]
	}
	return nil
}

// 获取输入的哈希对应的记录结果
// 查询到enrEntry或者linkEntry就增加叶子节点的数目
// 查询到branchEntry就把里面记录的哈希放到missing里
func (ts *subtreeSync) resolveNext(ctx context.Context, hash string) (entry, error) {
	e, err := ts.c.resolveEntry(ctx, ts.loc.domain, hash)
	if err != nil {
		return nil, err
	}
	// 查询到enrEntry或者linkEntry就增加叶子节点的数目
	// 查询到branchEntry就把里面记录的哈希放到missing里
	switch e := e.(type) {
	case *enrEntry:
		if ts.link {
			return nil, errENRInLinkTree
		}
		ts.leaves++
	case *linkEntry:
		if !ts.link {
			return nil, errLinkInENRTree
		}
		ts.leaves++
	case *branchEntry:
		ts.missing = append(ts.missing, e.children...)
	}
	return e, nil
}

// linkCache tracks links between trees.
type linkCache struct {
	// backrefs的各个键保存了所有的链接
	// 每个值是还是一个映射,可以理解为数组,代表这个链接被哪些其他链接引用了
	// 值不直接使用数组可能是因为使用map便于删除,直接delete就去掉了这个引用
	backrefs map[string]map[string]struct{}
	changed  bool
}

func (lc *linkCache) isReferenced(r string) bool {
	return len(lc.backrefs[r]) != 0
}

// 设置lc.backrefs[to][from]=string{}{}
// 并设置lc.changed为true
func (lc *linkCache) addLink(from, to string) {
	// 已经有了直接返回
	if _, ok := lc.backrefs[to][from]; ok {
		return
	}

	if lc.backrefs == nil {
		lc.backrefs = make(map[string]map[string]struct{})
	}
	if _, ok := lc.backrefs[to]; !ok {
		lc.backrefs[to] = make(map[string]struct{})
	}
	lc.backrefs[to][from] = struct{}{}
	lc.changed = true
}

// resetLinks clears all links of the given tree.
// 从lc.backrefs中删除from链接中引用的其他链接,在keep中的链接不删除
func (lc *linkCache) resetLinks(from string, keep map[string]struct{}) {
	stk := []string{from}
	for len(stk) > 0 {
		item := stk[len(stk)-1]
		stk = stk[:len(stk)-1]

		// r代表一个链接,refs代表所有引用了这个链接的其他链接
		for r, refs := range lc.backrefs {
			// 这个链接在keep里,不处理
			if _, ok := keep[r]; ok {
				continue
			}
			// 这个链接没有被当前需要解引用的对象引用,不处理
			if _, ok := refs[item]; !ok {
				continue
			}
			lc.changed = true
			// 从引用列表删除当前需要解引用的对象
			delete(refs, item)
			// 没有引用这个链接的了,从backrefs中删除,然后被r引用的链接也要进行处理
			if len(refs) == 0 {
				delete(lc.backrefs, r)
				stk = append(stk, r)
			}
		}
	}
}
