// Copyright 2014 The go-ethereum Authors
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

// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.

// keyBytes 就是初始的字节数组

// hex格式
// 每一个字节保存了一个半字节
// 末尾可能保存有一字节的terminator为16

// Compact的格式
// 长度为偶数 增加额外一字节作为标记
//   叶子节点 0010 0000
//   扩展节点 0000 0000
// 长度为奇数 使用最前面的4个比特位作为标记
//   叶子节点 0011 xxxx
//   扩展节点 0001 xxxx
// 也就是说第4位为1代表长度是奇数,第3位为1代表是叶子节点
func hexToCompact(hex []byte) []byte {
	// terminator为1标记了是叶子节点
	// 为0标记了是扩展节点
	// 说明叶子节点有terminator,扩展节点没有terminator
	terminator := byte(0)
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}
	buf := make([]byte, len(hex)/2+1)
	buf[0] = terminator << 5 // the flag byte
	// 长度是奇数
	if len(hex)&1 == 1 {
		// 长度是奇数的第4位是1
		buf[0] |= 1 << 4 // odd flag
		// 后4位使用hex[0]填充
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}
	decodeNibbles(hex, buf[1:])
	return buf
}

// hexToCompactInPlace places the compact key in input buffer, returning the length
// needed for the representation
// 直接修改输入的hex数组,转换为Compact模式
// 返回值是Compact编码的长度
func hexToCompactInPlace(hex []byte) int {
	var (
		hexLen    = len(hex) // length of the hex input
		firstByte = byte(0)
	)
	// Check if we have a terminator there
	if hexLen > 0 && hex[hexLen-1] == 16 {
		firstByte = 1 << 5
		hexLen-- // last part was the terminator, ignore that
	}
	var (
		binLen = hexLen/2 + 1
		ni     = 0 // index in hex
		bi     = 1 // index in bin (compact)
	)
	if hexLen&1 == 1 {
		firstByte |= 1 << 4 // odd flag
		firstByte |= hex[0] // first nibble is contained in the first byte
		ni++
	}
	for ; ni < hexLen; bi, ni = bi+1, ni+2 {
		hex[bi] = hex[ni]<<4 | hex[ni+1]
	}
	hex[0] = firstByte
	return binLen
}

// 生成Hex格式,叶子结点有terminator
// Hex格式中叶子节点最后有terminator,扩展节点没有terminator
func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := keybytesToHex(compact)
	// delete terminator flag
	// base[0] < 2代表是扩展节点,扩展节点没有terminator,所以这里去掉
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// apply odd flag
	// 长度奇数chop是1,长度偶数chop是2
	chop := 2 - base[0]&1
	// 偶数标记位是一字节,转换成hex是前两字节
	// 奇数标记位是四位,转换成hex是前一字节
	return base[chop:]
}

// 将一个字节拆分成两个字节,最后添加terminator为16
func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
// 去掉hex可能存在的terminator
// 然后对hex元素两两合并,返回key
// 输入的hex的长度必须是偶数
func hexToKeybytes(hex []byte) []byte {
	// 去掉末尾terminator
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

// 将nibbles内的数据两两合并到bytes里面
// 输入的nibbles长度一定是偶数
func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// prefixLen returns the length of the common prefix of a and b.
// 得到a和b共同前缀的长度
func prefixLen(a, b []byte) int {
	// length为min(len(a),len(b))
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm returns whether a hex key has the terminator flag.
// 判断输入s是否有terminator,叶子节点返回true,扩展节点返回false
// 也就是s的末尾项是不是16也就是16进制的10
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}
