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

// Package forkid implements EIP-2124 (https://eips.ethereum.org/EIPS/eip-2124).
// NewID     获取当前链的ID对象
// NewFilter 获取一个过滤器
//   给返回的过滤器输入远程节点的ID对象,如果有err!=nil说明两个节点不匹配
package forkid

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"math/big"
	"reflect"
	"strings"

	"github.com/Evolution404/simcore/common"
	"github.com/Evolution404/simcore/core/types"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/params"
)

var (
	// ErrRemoteStale is returned by the validator if a remote fork checksum is a
	// subset of our already applied forks, but the announced next fork block is
	// not on our already passed chain.
	// 远程节点是之前的版本返回这个错误
	ErrRemoteStale = errors.New("remote needs update")

	// ErrLocalIncompatibleOrStale is returned by the validator if a remote fork
	// checksum does not match any local checksum variation, signalling that the
	// two chains have diverged in the past at some point (possibly at genesis).
	// 和远程节点的校验和不匹配,而且校验和也不在之前版本中
	ErrLocalIncompatibleOrStale = errors.New("local incompatible or needs update")
)

// Blockchain defines all necessary method to build a forkID.
// 实现了Config、Genesis、CurrentHeader三个方法的对象可以直接生成区块链标识符
type Blockchain interface {
	// Config retrieves the chain's fork configuration.
	Config() *params.ChainConfig

	// Genesis retrieves the chain's genesis block.
	Genesis() *types.Block

	// CurrentHeader retrieves the current head header of the canonical chain.
	CurrentHeader() *types.Header
}

// ID is a fork identifier as defined by EIP-2124.
// 代表一个区块链标识符
type ID struct {
	Hash [4]byte // CRC32 checksum of the genesis block and passed fork block numbers
	Next uint64  // Block number of the next upcoming fork, or 0 if no forks are known
}

// Filter is a fork id filter to validate a remotely advertised ID.
// 验证远程节点的区块链标识符是否和本地匹配
type Filter func(id ID) error

// NewID calculates the Ethereum fork ID from the chain config, genesis hash, and head.
// 根据区块链配置、创世区块以及当前区块高度创建区块链标识符
func NewID(config *params.ChainConfig, genesis common.Hash, head uint64) ID {
	// Calculate the starting checksum from the genesis hash
	// 先计算创世区块时的标识符，接下要挨个分叉进行更新
	hash := crc32.ChecksumIEEE(genesis[:])

	// Calculate the current fork checksum and the next fork block
	// 记录下一次分叉的位置，如果当前高度高于所有分叉next是0
	var next uint64
	// 获取所有分叉高度，依次输入小于当前区块高度的分叉来更新区块链标识符
	for _, fork := range gatherForks(config) {
		if fork <= head {
			// Fork already passed, checksum the previous hash and the fork number
			hash = checksumUpdate(hash, fork)
			continue
		}
		// 由于上面有continue，如果区块高度高于所有分叉，这一句永远不会执行，next也就是0
		next = fork
		break
	}
	// 返回最终的区块链标识符
	return ID{Hash: checksumToBytes(hash), Next: next}
}

// NewIDWithChain calculates the Ethereum fork ID from an existing chain instance.
// 基于BlockChain对象生成区块链标识符
func NewIDWithChain(chain Blockchain) ID {
	return NewID(
		chain.Config(),
		// 创世区块对象还要再调用Hash方法转换成哈希类型
		chain.Genesis().Hash(),
		// 需要从当前区块头对象中取出当前的区块高度
		chain.CurrentHeader().Number.Uint64(),
	)
}

// NewFilter creates a filter that returns if a fork ID should be rejected or not
// based on the local chain's status.
// 生成一个判断远程节点标识符是否匹配的过滤器
// 生成的过滤器会随着本地区块高度的变化动态的修改返回结果
// 也就是每次调用过滤器都会返回本地区块链当前状态与远程节点匹配的结果
func NewFilter(chain Blockchain) Filter {
	return newFilter(
		chain.Config(),
		chain.Genesis().Hash(),
		func() uint64 {
			return chain.CurrentHeader().Number.Uint64()
		},
	)
}

// NewStaticFilter creates a filter at block zero.
// 生成一个永远保持在创世区块的标识符过滤器
func NewStaticFilter(config *params.ChainConfig, genesis common.Hash) Filter {
	head := func() uint64 { return 0 }
	return newFilter(config, genesis, head)
}

// newFilter is the internal version of NewFilter, taking closures as its arguments
// instead of a chain. The reason is to allow testing it without having to simulate
// an entire blockchain.
// 输入区块链配置、创世区块哈希和一个获取区块高度的回调函数来生成过滤器
func newFilter(config *params.ChainConfig, genesis common.Hash, headfn func() uint64) Filter {
	// Calculate the all the valid fork hash and fork next combos
	// sums保存了所有分叉历史的校验和
	// sums[0]保存创世区块的校验和,之后每次分叉增加一项
	var (
		forks = gatherForks(config)
		// 保存从创世区块开始，经过各次分叉后的FORK_HASH
		sums  = make([][4]byte, len(forks)+1) // 0th is the genesis
	)
	// 首先计算创世区块时的FORK_HASH
	hash := crc32.ChecksumIEEE(genesis[:])
	sums[0] = checksumToBytes(hash)
	// 然后遍历各次分叉
	for i, fork := range forks {
		hash = checksumUpdate(hash, fork)
		sums[i+1] = checksumToBytes(hash)
	}
	// Add two sentries to simplify the fork checks and don't require special
	// casing the last one.
	// 添加一个永远不会越过的分叉高度，避免处理边界情况
	forks = append(forks, math.MaxUint64) // Last fork will never be passed

	// Create a validator that will filter out incompatible chains
	return func(id ID) error {
		// Run the fork checksum validation ruleset:
		//   1. If local and remote FORK_CSUM matches, compare local head to FORK_NEXT.
		//        The two nodes are in the same fork state currently. They might know
		//        of differing future forks, but that's not relevant until the fork
		//        triggers (might be postponed, nodes might be updated to match).
		//      1a. A remotely announced but remotely not passed block is already passed
		//          locally, disconnect, since the chains are incompatible.
		//      1b. No remotely announced fork; or not yet passed locally, connect.
		//   2. If the remote FORK_CSUM is a subset of the local past forks and the
		//      remote FORK_NEXT matches with the locally following fork block number,
		//      connect.
		//        Remote node is currently syncing. It might eventually diverge from
		//        us, but at this current point in time we don't have enough information.
		//   3. If the remote FORK_CSUM is a superset of the local past forks and can
		//      be completed with locally known future forks, connect.
		//        Local node is currently syncing. It might eventually diverge from
		//        the remote, but at this current point in time we don't have enough
		//        information.
		//   4. Reject in all other cases.
		// 获取当前区块高度
		head := headfn()
		for i, fork := range forks {
			// If our head is beyond this fork, continue to the next (we have a dummy
			// fork of maxuint64 as the last item to always fail this check eventually).
			// 一直找到当前区块高度所在的分叉
			if head >= fork {
				continue
			}
			// Found the first unpassed fork block, check if our current state matches
			// the remote checksum (rule #1).
			// 本地和远程的FORK_HASH匹配匹配
			if sums[i] == id.Hash {
				// Fork checksum matched, check if a remote future fork block already passed
				// locally without the local node being aware of it (rule #1a).
				// 本地已经越过了远程节点的FORK_NEXT，这时候要报错
				if id.Next > 0 && head >= id.Next {
					// 本地版本过期了
					return ErrLocalIncompatibleOrStale
				}
				// Haven't passed locally a remote-only fork, accept the connection (rule #1b).
				// 其他情况都通过
				return nil
			}
			// The local and remote nodes are in different forks currently, check if the
			// remote checksum is a subset of our local forks (rule #2).
			// 远程节点是本地的子集，远程节点的FORK_NEXT要与本地匹配
			for j := 0; j < i; j++ {
				if sums[j] == id.Hash {
					// Remote checksum is a subset, validate based on the announced next fork
					// 远程节点认为的下一个分叉点与本地不一致，要报错
					if forks[j] != id.Next {
						return ErrRemoteStale
					}
					// 远程节点知道下一个分叉的位置,说明远程节点区块没有同步到下一个分叉
					return nil
				}
			}
			// Remote chain is not a subset of our local one, check if it's a superset by
			// any chance, signalling that we're simply out of sync (rule #3).
			// 本地节点是远程节点的子集
			for j := i + 1; j < len(sums); j++ {
				if sums[j] == id.Hash {
					// Yay, remote checksum is a superset, ignore upcoming forks
					return nil
				}
			}
			// No exact, subset or superset match. We are on differing chains, reject.
			// 本地节点计算了所有已知的分叉点可能生成的FORK_HASH都不能与远程节点匹配
			// 此时有可能与远程节点不匹配或者本地软件版本太旧了，不知道最新的分叉位置
			return ErrLocalIncompatibleOrStale
		}
		log.Error("Impossible fork ID validation", "id", id)
		return nil // Something's very wrong, accept rather than reject
	}
}

// checksumUpdate calculates the next IEEE CRC32 checksum based on the previous
// one and a fork block number (equivalent to CRC32(original-blob || fork)).
// 已经知道了之前的校验和，计算新增输入的分叉高度后的新的校验和
func checksumUpdate(hash uint32, fork uint64) uint32 {
	var blob [8]byte
	binary.BigEndian.PutUint64(blob[:], fork)
	return crc32.Update(hash, crc32.IEEETable, blob[:])
}

// checksumToBytes converts a uint32 checksum into a [4]byte array.
// 将uint32类型的校验和转换成长度为4的字节数组
func checksumToBytes(hash uint32) [4]byte {
	var blob [4]byte
	binary.BigEndian.PutUint32(blob[:], hash)
	return blob
}

// gatherForks gathers all the known forks and creates a sorted list out of them.
// 用于从区块链配置中得到所有的分叉高度
func gatherForks(config *params.ChainConfig) []uint64 {
	// Gather all the fork block numbers via reflection
	kind := reflect.TypeOf(params.ChainConfig{})
	conf := reflect.ValueOf(config).Elem()

	var forks []uint64
	// 遍历配置信息的所有字段
	for i := 0; i < kind.NumField(); i++ {
		// Fetch the next field and skip non-fork rules
		field := kind.Field(i)
		// 找到字段是以Block结尾的
		if !strings.HasSuffix(field.Name, "Block") {
			continue
		}
		// 而且字段的数据类型必须是big.Int
		if field.Type != reflect.TypeOf(new(big.Int)) {
			continue
		}
		// Extract the fork rule block number and aggregate it
		// 提取出来分叉的高度
		rule := conf.Field(i).Interface().(*big.Int)
		if rule != nil {
			forks = append(forks, rule.Uint64())
		}
	}
	// Sort the fork block numbers to permit chronological XOR
	// 将所有分叉高度从小到大排序
	for i := 0; i < len(forks); i++ {
		for j := i + 1; j < len(forks); j++ {
			if forks[i] > forks[j] {
				forks[i], forks[j] = forks[j], forks[i]
			}
		}
	}
	// Deduplicate block numbers applying multiple forks
	// 去除重复的分叉高度
	for i := 1; i < len(forks); i++ {
		if forks[i] == forks[i-1] {
			forks = append(forks[:i], forks[i+1:]...)
			i--
		}
	}
	// Skip any forks in block 0, that's the genesis ruleset
	// 去除高度为0的分叉
	if len(forks) > 0 && forks[0] == 0 {
		forks = forks[1:]
	}
	return forks
}
