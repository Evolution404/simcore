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

package trie

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/ethdb/memorydb"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/rlp"
)

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
// 计算给定key的梅克尔证明,将每一层的计算结果写入proofDb
// 写入的结果就是路径上的每一个节点对应的 hash->rlp 映射
// fromLevel代表从树的哪一层开始计算
func (t *Trie) Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error {
	// Collect all nodes on the path to key.
	key = keybytesToHex(key)
	// 保存key路径的所有节点,里面只有shortNode和fullNode两种类型
	var nodes []node
	tn := t.root
	// 循环过程中每向下一层key就去掉一层的路径,key逐渐变短
	// 每向下一层node就添加这一层的节点
	for len(key) > 0 && tn != nil {
		// 每次循环更新tn为下一层节点,并缩短key
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				tn = nil
			} else {
				tn = n.Val
				key = key[len(n.Key):]
			}
			nodes = append(nodes, n)
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
			nodes = append(nodes, n)
		case hashNode:
			var err error
			tn, err = t.resolveHash(n, nil)
			if err != nil {
				log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
				return err
			}
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)

	for i, n := range nodes {
		// 一直找到对应的层
		if fromLevel > 0 {
			fromLevel--
			continue
		}
		var hn node
		// 计算路径上每一层的哈希
		// 放入到proofDb中
		n, hn = hasher.proofHash(n)
		if hash, ok := hn.(hashNode); ok || i == 0 {
			// If the node's database encoding is a hash (or is the
			// root node), it becomes a proof element.
			enc, _ := rlp.EncodeToBytes(n)
			if !ok {
				hash = hasher.hashData(enc)
			}
			proofDb.Put(hash, enc)
		}
	}
	return nil
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *SecureTrie) Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error {
	return t.trie.Prove(key, fromLevel, proofDb)
}

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
// rootHash表示要验证的树的根,key为要验证的路径
// 如果返回的err为nil说明验证通过,此时返回的value代表key对应的值
func VerifyProof(rootHash common.Hash, key []byte, proofDb ethdb.KeyValueReader) (value []byte, err error) {
	key = keybytesToHex(key)
	wantHash := rootHash
	for i := 0; ; i++ {
		// 读取rlp编码到buf中
		buf, _ := proofDb.Get(wantHash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node %d (hash %064x) missing", i, wantHash)
		}
		// 从buf中解码出节点对象
		n, err := decodeNode(wantHash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %d: %v", i, err)
		}
		keyrest, cld := get(n, key, true)
		switch cld := cld.(type) {
		case nil:
			// The trie doesn't contain the key.
			return nil, nil
		// 读到hashNode下一轮从数据库中读原始rlp编码
		case hashNode:
			key = keyrest
			copy(wantHash[:], cld)
		case valueNode:
			return cld, nil
		}
	}
}

// proofToPath converts a merkle proof to trie node path. The main purpose of
// this function is recovering a node path from the merkle proof stream. All
// necessary nodes will be resolved and leave the remaining as hashnode.
//
// The given edge proof is allowed to be an existent or non-existent proof.
// 根据输入的rootHash,key,proofDb恢复出来这一条节点链接起来的路径,路径上的hashNode都被解析为原来的对象
// 返回的node就是被恢复出来的整条路径,如果key能搜索到valueNode第二个返回值就是这个valueNode
func proofToPath(rootHash common.Hash, root node, key []byte, proofDb ethdb.KeyValueReader, allowNonExistent bool) (node, []byte, error) {
	// resolveNode retrieves and resolves trie node from merkle proof stream
	// resolveNode用来输入hash,从proofDb中恢复haxh对应的节点对象
	resolveNode := func(hash common.Hash) (node, error) {
		buf, _ := proofDb.Get(hash[:])
		if buf == nil {
			return nil, fmt.Errorf("proof node (hash %064x) missing", hash)
		}
		n, err := decodeNode(hash[:], buf)
		if err != nil {
			return nil, fmt.Errorf("bad proof node %v", err)
		}
		return n, err
	}
	// If the root node is empty, resolve it first.
	// Root node must be included in the proof.
	if root == nil {
		n, err := resolveNode(rootHash)
		if err != nil {
			return nil, nil, err
		}
		root = n
	}
	var (
		err           error
		child, parent node
		keyrest       []byte
		valnode       []byte
	)
	// 将key转换为hex格式
	// 逐层向下解析对象
	// 遇到hashNode的时候才需要特殊处理
	// 首先解析读到的hashNode然后让父节点串联起来这个解析出来的节点
	key, parent = keybytesToHex(key), root
	for {
		keyrest, child = get(parent, key, false)
		switch cld := child.(type) {
		case nil:
			// The trie doesn't contain the key. It's possible
			// the proof is a non-existing proof, but at least
			// we can prove all resolved nodes are correct, it's
			// enough for us to prove range.
			if allowNonExistent {
				return root, nil, nil
			}
			return nil, nil, errors.New("the node is not contained in trie")
		// shortNode,fullNode直接continue进入下一层
		case *shortNode:
			key, parent = keyrest, child // Already resolved
			continue
		case *fullNode:
			key, parent = keyrest, child // Already resolved
			continue
		case hashNode:
			child, err = resolveNode(common.BytesToHash(cld))
			if err != nil {
				return nil, nil, err
			}
		// 读到valueNode就到底了,下面结束读取
		case valueNode:
			valnode = cld
		}
		// Link the parent and child.
		switch pnode := parent.(type) {
		case *shortNode:
			pnode.Val = child
		case *fullNode:
			pnode.Children[key[0]] = child
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", pnode, pnode))
		}
		if len(valnode) > 0 {
			return root, valnode, nil // The whole path is resolved
		}
		key, parent = keyrest, child
	}
}

// unsetInternal removes all internal node references(hashnode, embedded node).
// It should be called after a trie is constructed with two edge paths. Also
// the given boundary keys must be the one used to construct the edge paths.
//
// It's the key step for range proof. All visited nodes should be marked dirty
// since the node content might be modified. Besides it can happen that some
// fullnodes only have one child which is disallowed. But if the proof is valid,
// the missing children will be filled, otherwise it will be thrown anyway.
//
// Note we have the assumption here the given boundary keys are different
// and right is larger than left.
// 清除树上在left和right路径之间的节点
// 输入的right一定要大于left
func unsetInternal(n node, left []byte, right []byte) (bool, error) {
	left, right = keybytesToHex(left), keybytesToHex(right)

	// Step down to the fork point. There are two scenarios can happen:
	// - the fork point is a shortnode: either the key of left proof or
	//   right proof doesn't match with shortnode's key.
	// - the fork point is a fullnode: both two edge proofs are allowed
	//   to point to a non-existent key.
	var (
		pos    = 0
		parent node

		// fork indicator, 0 means no fork, -1 means proof is less, 1 means proof is greater
		shortForkLeft, shortForkRight int
	)
	// 结束这个for循环后, n就代表两条路径分叉位置的节点
findFork:
	for {
		switch rn := (n).(type) {
		case *shortNode:
			rn.flags = nodeFlag{dirty: true}

			// If either the key of left proof or right proof doesn't match with
			// shortnode, stop here and the forkpoint is the shortnode.
			// shortForkLeft和shortForkRight分别记录两条路径是否与当前shortNode中保存的key一致
			// 都是0说明两条路径都与当前的shortNode保存的key一致,继续向下一层
			if len(left)-pos < len(rn.Key) {
				shortForkLeft = bytes.Compare(left[pos:], rn.Key)
			} else {
				shortForkLeft = bytes.Compare(left[pos:pos+len(rn.Key)], rn.Key)
			}
			if len(right)-pos < len(rn.Key) {
				shortForkRight = bytes.Compare(right[pos:], rn.Key)
			} else {
				shortForkRight = bytes.Compare(right[pos:pos+len(rn.Key)], rn.Key)
			}
			if shortForkLeft != 0 || shortForkRight != 0 {
				// 这里直接使用break是跳出switch语句,所以使用label结束for循环
				break findFork
			}
			// 左右两条路径都一致,向下一层
			parent = n
			n, pos = rn.Val, pos+len(rn.Key)
		case *fullNode:
			rn.flags = nodeFlag{dirty: true}

			// If either the node pointed by left proof or right proof is nil,
			// stop here and the forkpoint is the fullnode.
			leftnode, rightnode := rn.Children[left[pos]], rn.Children[right[pos]]
			if leftnode == nil || rightnode == nil || leftnode != rightnode {
				break findFork
			}
			parent = n
			n, pos = rn.Children[left[pos]], pos+1
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", n, n))
		}
	}
	switch rn := n.(type) {
	case *shortNode:
		// There can have these five scenarios:
		// - both proofs are less than the trie path => no valid range
		// - both proofs are greater than the trie path => no valid range
		// - left proof is less and right proof is greater => valid range, unset the shortnode entirely
		// - left proof points to the shortnode, but right proof is greater
		// - right proof points to the shortnode, but left proof is less
		// 两条路径都小于
		if shortForkLeft == -1 && shortForkRight == -1 {
			return false, errors.New("empty range")
		}
		// 两条路径都大于
		if shortForkLeft == 1 && shortForkRight == 1 {
			return false, errors.New("empty range")
		}
		// left小于,right大于
		if shortForkLeft != 0 && shortForkRight != 0 {
			// The fork point is root node, unset the entire trie
			// 根节点就分叉了,返回空树
			if parent == nil {
				return true, nil
			}
			// 分叉位置是shortNode,让父节点的fullNode下的这个分支置空即可
			parent.(*fullNode).Children[left[pos-1]] = nil
			return false, nil
		}
		// 执行到这里是分叉了但是没有完全分叉的情况
		// 比如left完全匹配这个节点,但是right不匹配了
		// 或者left不匹配这个节点,但是right匹配了
		// 需要利用unset函数继续沿着路径清理左侧或者右侧的节点
		// Only one proof points to non-existent key.
		// 这种情况是left完全匹配,沿着left的路径删除所有left右侧的节点
		if shortForkRight != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				// The fork point is root node, unset the entire trie
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[left[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, left[pos:], len(rn.Key), false)
		}
		if shortForkLeft != 0 {
			if _, ok := rn.Val.(valueNode); ok {
				// The fork point is root node, unset the entire trie
				if parent == nil {
					return true, nil
				}
				parent.(*fullNode).Children[right[pos-1]] = nil
				return false, nil
			}
			return false, unset(rn, rn.Val, right[pos:], len(rn.Key), true)
		}
		return false, nil
	// 分叉位置是fullNode
	// 1. 清除fullNode在左右路径中间的节点
	// 2. 继续向下搜索左路径,清除左路径右侧的节点
	// 3. 继续向下搜索右路径,清除右路径左侧的节点
	case *fullNode:
		// unset all internal nodes in the forkpoint
		// 在fullNode位置分叉,将两者中间的节点置空
		for i := left[pos] + 1; i < right[pos]; i++ {
			rn.Children[i] = nil
		}
		// 清除左节点路径的右侧
		if err := unset(rn, rn.Children[left[pos]], left[pos:], 1, false); err != nil {
			return false, err
		}
		// 清除右节点路径的左侧
		if err := unset(rn, rn.Children[right[pos]], right[pos:], 1, true); err != nil {
			return false, err
		}
		return false, nil
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// unset removes all internal node references either the left most or right most.
// It can meet these scenarios:
//
// - The given path is existent in the trie, unset the associated nodes with the
//   specific direction
// - The given path is non-existent in the trie
//   - the fork point is a fullnode, the corresponding child pointed by path
//     is nil, return
//   - the fork point is a shortnode, the shortnode is included in the range,
//     keep the entire branch and return.
//   - the fork point is a shortnode, the shortnode is excluded in the range,
//     unset the entire branch.
// removeLeft为true清空key代表路径左侧所有节点的引用
// removeLeft为false清空key代表路径右侧所有节点的引用
// pos代表当前处理的key的位置
func unset(parent node, child node, key []byte, pos int, removeLeft bool) error {
	switch cld := child.(type) {
	case *fullNode:
		// removeLeft为true就清空左侧的所有子节点
		if removeLeft {
			for i := 0; i < int(key[pos]); i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
			// 否则清空右侧的所有节点
		} else {
			for i := key[pos] + 1; i < 16; i++ {
				cld.Children[i] = nil
			}
			cld.flags = nodeFlag{dirty: true}
		}
		return unset(cld, cld.Children[key[pos]], key, pos+1, removeLeft)
	case *shortNode:
		if len(key[pos:]) < len(cld.Key) || !bytes.Equal(cld.Key, key[pos:pos+len(cld.Key)]) {
			// Find the fork point, it's an non-existent branch.
			// 当前这个shortNode不匹配路径了
			// 如果removeLeft为true,那么当前节点小于路径的话从父节点移除
			// 如果removeLeft为false,那么当前节点大于路径的话从父节点移除
			if removeLeft {
				if bytes.Compare(cld.Key, key[pos:]) < 0 {
					// The key of fork shortnode is less than the path
					// (it belongs to the range), unset the entrie
					// branch. The parent must be a fullnode.
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				} else {
					// The key of fork shortnode is greater than the
					// path(it doesn't belong to the range), keep
					// it with the cached hash available.
				}
			} else {
				if bytes.Compare(cld.Key, key[pos:]) > 0 {
					// The key of fork shortnode is greater than the
					// path(it belongs to the range), unset the entrie
					// branch. The parent must be a fullnode.
					fn := parent.(*fullNode)
					fn.Children[key[pos-1]] = nil
				} else {
					// The key of fork shortnode is less than the
					// path(it doesn't belong to the range), keep
					// it with the cached hash available.
				}
			}
			return nil
		}
		// 找到了路径末尾的节点
		// 从它的父节点上清空末尾的这个节点
		// 末尾节点的父节点一定是一个fullNode
		if _, ok := cld.Val.(valueNode); ok {
			fn := parent.(*fullNode)
			fn.Children[key[pos-1]] = nil
			return nil
		}
		cld.flags = nodeFlag{dirty: true}
		// shortNode保存的不是vlaueNode,继续向下递归处理
		return unset(cld, cld.Val, key, pos+len(cld.Key), removeLeft)
	case nil:
		// If the node is nil, then it's a child of the fork point
		// fullnode(it's a non-existent branch).
		return nil
	default:
		panic("it shouldn't happen") // hashNode, valueNode
	}
}

// hasRightElement returns the indicator whether there exists more elements
// in the right side of the given path. The given path can point to an existent
// key or a non-existent one. This function has the assumption that the whole
// path should already be resolved.
// 假定树中已经不含有hashNode
// 判断给定的路径右侧还有没有节点
func hasRightElement(node node, key []byte) bool {
	// pos记录当前读取到key的下标
	pos, key := 0, keybytesToHex(key)
	for node != nil {
		switch rn := node.(type) {
		case *fullNode:
			// fullNode在后面只要有一个节点不是nil就说明右侧还有树
			for i := key[pos] + 1; i < 16; i++ {
				if rn.Children[i] != nil {
					return true
				}
			}
			// 后面所有位置都是nil
			// 就在当前路径继续向下搜索一层
			node, pos = rn.Children[key[pos]], pos+1
		case *shortNode:
			// shortNode里的key不能完全匹配
			// 比较节点内保存的key与输入的key谁大
			// 节点的key大就说明右侧还有
			if len(key)-pos < len(rn.Key) || !bytes.Equal(rn.Key, key[pos:pos+len(rn.Key)]) {
				return bytes.Compare(rn.Key, key[pos:]) > 0
			}
			// shortNode里的key能够完全匹配
			node, pos = rn.Val, pos+len(rn.Key)
		case valueNode:
			return false // We have resolved the whole path
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", node, node)) // hashnode
		}
	}
	return false
}

// VerifyRangeProof checks whether the given leaf nodes and edge proof
// can prove the given trie leaves range is matched with the specific root.
// Besides, the range should be consecutive (no gap inside) and monotonic
// increasing.
//
// Note the given proof actually contains two edge proofs. Both of them can
// be non-existent proofs. For example the first proof is for a non-existent
// key 0x03, the last proof is for a non-existent key 0x10. The given batch
// leaves are [0x04, 0x05, .. 0x09]. It's still feasible to prove the given
// batch is valid.
//
// The firstKey is paired with firstProof, not necessarily the same as keys[0]
// (unless firstProof is an existent proof). Similarly, lastKey and lastProof
// are paired.
//
// Expect the normal case, this function can also be used to verify the following
// range proofs:
//
// - All elements proof. In this case the proof can be nil, but the range should
//   be all the leaves in the trie.
//
// - One element proof. In this case no matter the edge proof is a non-existent
//   proof or not, we can always verify the correctness of the proof.
//
// - Zero element proof. In this case a single non-existent proof is enough to prove.
//   Besides, if there are still some other leaves available on the right side, then
//   an error will be returned.
//
// Except returning the error to indicate the proof is valid or not, the function will
// also return a flag to indicate whether there exists more accounts/slots in the trie.
//
// Note: This method does not verify that the proof is of minimal form. If the input
// proofs are 'bloated' with neighbour leaves or random data, aside from the 'useful'
// data, then the proof will still be accepted.
// keys和values中的数据一一对应,代表要验证的键值对,而且输入的key必须要单调递增
// 返回的bool代表树中在最后一个验证的key后面是否还有节点,error代表验证是否通过
func VerifyRangeProof(rootHash common.Hash, firstKey []byte, lastKey []byte, keys [][]byte, values [][]byte, proof ethdb.KeyValueReader) (bool, error) {
	if len(keys) != len(values) {
		return false, fmt.Errorf("inconsistent proof data, keys: %d, values: %d", len(keys), len(values))
	}
	// Ensure the received batch is monotonic increasing and contains no deletions
	for i := 0; i < len(keys)-1; i++ {
		if bytes.Compare(keys[i], keys[i+1]) >= 0 {
			return false, errors.New("range is not monotonically increasing")
		}
	}
	for _, value := range values {
		if len(value) == 0 {
			return false, errors.New("range contains deletion")
		}
	}
	// Special case, there is no edge proof at all. The given range is expected
	// to be the whole leaf-set in the trie.
	// 输入的keys和values包括了整棵树中的所有叶子节点
	// 直接计算出来树根的哈希与输入的rootHash对比
	if proof == nil {
		tr := NewStackTrie(nil)
		for index, key := range keys {
			tr.TryUpdate(key, values[index])
		}
		// 不匹配验证失败
		if have, want := tr.Hash(), rootHash; have != want {
			return false, fmt.Errorf("invalid proof, want hash %x, got %x", want, have)
		}
		// 验证匹配,返回nil
		// 而且不存在其他节点了,返回false
		return false, nil // No more elements
	}
	// Special case, there is a provided edge proof but zero key/value
	// pairs, ensure there are no more accounts / slots in the trie.
	if len(keys) == 0 {
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, true)
		if err != nil {
			return false, err
		}
		// val!=nil代表这个proof是一条完整的路径
		// proof是完整的路径或者右侧还有节点都要求这里的keys不应该是空
		if val != nil || hasRightElement(root, firstKey) {
			return false, errors.New("more entries available")
		}
		return hasRightElement(root, firstKey), nil
	}
	// Special case, there is only one element and two edge keys are same.
	// In this case, we can't construct two edge paths. So handle it here.
	if len(keys) == 1 && bytes.Equal(firstKey, lastKey) {
		// 这里要求proof必须表示了完整的路径
		root, val, err := proofToPath(rootHash, nil, firstKey, proof, false)
		if err != nil {
			return false, err
		}
		// 验证proof代表的路径和输入的keys里的唯一的路径是否一致
		if !bytes.Equal(firstKey, keys[0]) {
			return false, errors.New("correct proof but invalid key")
		}
		if !bytes.Equal(val, values[0]) {
			return false, errors.New("correct proof but invalid data")
		}
		// 验证通过
		return hasRightElement(root, firstKey), nil
	}
	// Ok, in all other cases, we require two edge paths available.
	// First check the validity of edge keys.
	if bytes.Compare(firstKey, lastKey) >= 0 {
		return false, errors.New("invalid edge keys")
	}
	// todo(rjl493456442) different length edge keys should be supported
	if len(firstKey) != len(lastKey) {
		return false, errors.New("inconsistent edge keys")
	}
	// Convert the edge proofs to edge trie paths. Then we can
	// have the same tree architecture with the original one.
	// For the first edge proof, non-existent proof is allowed.
	// 恢复出来firstKey的路径
	root, _, err := proofToPath(rootHash, nil, firstKey, proof, true)
	if err != nil {
		return false, err
	}
	// Pass the root node here, the second path will be merged
	// with the first one. For the last edge proof, non-existent
	// proof is also allowed.
	// 在刚才firstKey路径的基础上再加上lastKey的路径
	// 执行后root就是有了开始结束两条路径的树
	root, _, err = proofToPath(rootHash, root, lastKey, proof, true)
	if err != nil {
		return false, err
	}
	// Remove all internal references. All the removed parts should
	// be re-filled(or re-constructed) by the given leaves range.
	empty, err := unsetInternal(root, firstKey, lastKey)
	if err != nil {
		return false, err
	}
	// Rebuild the trie with the leaf stream, the shape of trie
	// should be same with the original one.
	tr := &Trie{root: root, db: NewDatabase(memorydb.New())}
	if empty {
		tr.root = nil
	}
	// 使用要验证的key填充新建的树
	for index, key := range keys {
		tr.TryUpdate(key, values[index])
	}
	// 计算树根的哈希是否匹配
	if tr.Hash() != rootHash {
		return false, fmt.Errorf("invalid proof, want hash %x, got %x", rootHash, tr.Hash())
	}
	return hasRightElement(root, keys[len(keys)-1]), nil
}

// get returns the child of the given node. Return nil if the
// node with specified key doesn't exist at all.
//
// There is an additional flag `skipResolved`. If it's set then
// all resolved nodes won't be returned.
// 当skipResolved为true的时候返回的node不可能是shortNode和fullNode
// 当skipResolved为true,一直沿着key的路径找到第一个hashNode或者valueNode
// 当skipResolved为false,就直接找顺着key的第一个节点,hashNode或者valueNode直接返回
func get(tn node, key []byte, skipResolved bool) ([]byte, node) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				return nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
			if !skipResolved {
				return key, tn
			}
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
			if !skipResolved {
				return key, tn
			}
		case hashNode:
			return key, n
		case nil:
			return key, nil
		case valueNode:
			return nil, n
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
}
