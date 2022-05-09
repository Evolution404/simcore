// Copyright 2021 The go-ethereum Authors
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

package rlpx

import (
	"io"
)

// readBuffer implements buffering for network reads. This type is similar to bufio.Reader,
// with two crucial differences: the buffer slice is exposed, and the buffer keeps all
// read data available until reset.
//
// How to use this type:
//
// Keep a readBuffer b alongside the underlying network connection. When reading a packet
// from the connection, first call b.reset(). This empties b.data. Now perform reads
// through b.read() until the end of the packet is reached. The complete packet data is
// now available in b.data.
// 网络数据的读取缓冲区
// 外部：指使用缓冲区获取数据的一方
// 底层：指数据来源, 一般是网络连接
type readBuffer struct {
  // data字节数组分为三段: len(data),end,cap(data)
  // len(data): 已经通过read方法返回给外部的所有数据
  // end: 已经从底层读取的所有数据
  // cap(data): 每次从底层读取数据, 都会尽量填满cap(data)
	data []byte
  // end记录data中有数据的长度
	end  int
}

// reset removes all processed data which was read since the last call to reset.
// After reset, len(b.data) is zero.
// reset移除所有已经返回给外部的数据
// 也就是从0,len(data),end变成len(data),end
// 去除已经返回过的0,len(data)范围
func (b *readBuffer) reset() {
	unprocessed := b.end - len(b.data)
	copy(b.data[:unprocessed], b.data[len(b.data):b.end])
	b.end = unprocessed
	b.data = b.data[:0]
}

// read reads at least n bytes from r, returning the bytes.
// The returned slice is valid until the next call to reset.
func (b *readBuffer) read(r io.Reader, n int) ([]byte, error) {
  // offset代表当前已经返回给外部的数据长度
	offset := len(b.data)
  // have代表当前缓存的数据长度
	have := b.end - len(b.data)

	// If n bytes are available in the buffer, there is no need to read from r at all.
  // 外部需要的数据都在缓存中，直接返回
	if have >= n {
		b.data = b.data[:offset+n]
		return b.data[offset : offset+n], nil
	}

	// Make buffer space available.
	need := n - have
	b.grow(need)

	// Read.
  // ReadAtLeast将尽可能填满b.data的整个容量
	rn, err := io.ReadAtLeast(r, b.data[b.end:cap(b.data)], need)
	if err != nil {
		return nil, err
	}
  // 更新已经读取到的数据
	b.end += rn
  // 更新已经返回的数据
	b.data = b.data[:offset+n]
	return b.data[offset : offset+n], nil
}

// grow ensures the buffer has at least n bytes of unused space.
// 用于确保缓存中至少还有n字节未使用的空间
// 未使用的空间指：b.end到cap(b.data)的范围
func (b *readBuffer) grow(n int) {
	if cap(b.data)-b.end >= n {
		return
	}
	need := n - (cap(b.data) - b.end)
	offset := len(b.data)
	b.data = append(b.data[:cap(b.data)], make([]byte, need)...)
	b.data = b.data[:offset]
}

// writeBuffer implements buffering for network writes. This is essentially
// a convenience wrapper around a byte slice.
// 网络数据的写入缓冲区，本质是一个字节数组，不断复用内部的字节数组，减少内存分配提高效率
// 提供reset、appendZero、Write方法
// TODO: 尝试提供一个预分配空间的方法，将多次内存分配合并
type writeBuffer struct {
	data []byte
}

// 清空缓冲区的所有数据
func (b *writeBuffer) reset() {
	b.data = b.data[:0]
}

// 往缓冲区追加指定个数的空字节，返回一个长度为n的切片
func (b *writeBuffer) appendZero(n int) []byte {
	offset := len(b.data)
	b.data = append(b.data, make([]byte, n)...)
	return b.data[offset : offset+n]
}

// 往缓冲区写入数据
func (b *writeBuffer) Write(data []byte) (int, error) {
	b.data = append(b.data, data...)
	return len(data), nil
}

// 3字节无符号数的上限，用于错误处理
const maxUint24 = int(^uint32(0) >> 8)

// 输入长度为3的字节数组，转换成uint32
func readUint24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

// 将uint24转换成长度为3的字节数组
// uint32的后面24个比特位保存了数据
func putUint24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// growslice ensures b has the wanted length by either expanding it to its capacity
// or allocating a new slice if b has insufficient capacity.
// 返回一个长度达到wantLength的切片，有三种处理情况
// 1. 本来长度大于wantLength直接返回
// 2. 容量大于wantLength直接将长度扩充到满容量
// 3. 容量不足wantLength，重新创建一个wantLength的切片返回
func growslice(b []byte, wantLength int) []byte {
	if len(b) >= wantLength {
		return b
	}
	if cap(b) >= wantLength {
		return b[:cap(b)]
	}
	return make([]byte, wantLength)
}
