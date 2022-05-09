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
	"errors"

	"github.com/Evolution404/simcore/core/types"
)

var (
	// errSectionOutOfBounds is returned if the user tried to add more bloom filters
	// to the batch than available space, or if tries to retrieve above the capacity.
	errSectionOutOfBounds = errors.New("section out of bounds")

	// errBloomBitOutOfBounds is returned if the user tried to retrieve specified
	// bit bloom above the capacity.
	errBloomBitOutOfBounds = errors.New("bloom bit out of bounds")
)

// Generator takes a number of bloom filters and generates the rotated bloom bits
// to be used for batched filtering.
// 用来聚合一组布隆过滤器,可以快速查询这一组过滤器的指定位的结果
type Generator struct {
	// 保存了sections个布隆过滤器
	// blooms[x]保存了这sections个布隆过滤器的第x位的值
	blooms   [types.BloomBitLength][]byte // Rotated blooms for per-bit matching
	sections uint                         // Number of sections to batch together
	// 保存的section的个数,必须保证nextSec<=sections
	nextSec  uint                         // Next section to set when adding a bloom
}

// NewGenerator creates a rotated bloom generator that can iteratively fill a
// batched bloom filter's bits.
// 生成Generator对象,传入容量,容量必须是8的倍数
func NewGenerator(sections uint) (*Generator, error) {
	if sections%8 != 0 {
		return nil, errors.New("section count not multiple of 8")
	}
	b := &Generator{sections: sections}
	for i := 0; i < types.BloomBitLength; i++ {
		// sections个布隆过滤器总共需要 2048*sections bit
		// 这里除以8,正好保存所有布隆过滤器
		b.blooms[i] = make([]byte, sections/8)
	}
	return b, nil
}

// AddBloom takes a single bloom filter and sets the corresponding bit column
// in memory accordingly.
// index代表要添加第几个布隆过滤器
func (b *Generator) AddBloom(index uint, bloom types.Bloom) error {
	// Make sure we're not adding more bloom filters than our capacity
	// 容量满了报错
	if b.nextSec >= b.sections {
		return errSectionOutOfBounds
	}
	if b.nextSec != index {
		return errors.New("bloom filter with unexpected index")
	}
	// Rotate the bloom and insert into our collection
	// 计算要修改哪个字节
	byteIndex := b.nextSec / 8
	// 计算处于被修改的字节哪一位,单个字节内:最右边是第0位,最左边是第7位
	bitIndex := byte(7 - b.nextSec%8)
	// 遍历新增布隆过滤器中的每个字节,每次循环向旋转格式中写入一个字节
	for byt := 0; byt < types.BloomByteLength; byt++ {
		// 从第0字节开始,第0字节是最后一个字节
		bloomByte := bloom[types.BloomByteLength-1-byt]
		// 如果该字节全0,没有必要写入,本来旋转格式中也是全0
		if bloomByte == 0 {
			continue
		}
		// base代表截止前一轮已经写入了多少位,代表本轮要从第几位开始
		base := 8 * byt
		// 设置8个比特位
		b.blooms[base+7][byteIndex] |= ((bloomByte >> 7) & 1) << bitIndex
		b.blooms[base+6][byteIndex] |= ((bloomByte >> 6) & 1) << bitIndex
		b.blooms[base+5][byteIndex] |= ((bloomByte >> 5) & 1) << bitIndex
		b.blooms[base+4][byteIndex] |= ((bloomByte >> 4) & 1) << bitIndex
		b.blooms[base+3][byteIndex] |= ((bloomByte >> 3) & 1) << bitIndex
		b.blooms[base+2][byteIndex] |= ((bloomByte >> 2) & 1) << bitIndex
		b.blooms[base+1][byteIndex] |= ((bloomByte >> 1) & 1) << bitIndex
		b.blooms[base][byteIndex] |= (bloomByte & 1) << bitIndex
	}
	// 已经存储的过滤器个数加一
	b.nextSec++
	return nil
}

// Bitset returns the bit vector belonging to the given bit index after all
// blooms have been added.
// 查询前必须将生成器填充满,要查询的比特位一定是[0,2047]
// 返回结果第i位就代表第i个布隆过滤器第idx位的结果
func (b *Generator) Bitset(idx uint) ([]byte, error) {
	// 容量必须是满的
	if b.nextSec != b.sections {
		return nil, errors.New("bloom not fully generated yet")
	}
	// 查询的比特位一定要小于2048
	if idx >= types.BloomBitLength {
		return nil, errBloomBitOutOfBounds
	}
	// 直接返回旋转格式的第idx个元素即可
	return b.blooms[idx], nil
}
