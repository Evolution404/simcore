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

// Package enr implements Ethereum Node Records as defined in EIP-778. A node record holds
// arbitrary information about a node on the peer-to-peer network. Node information is
// stored in key/value pairs. To store and retrieve key/values in a record, use the Entry
// interface.
//
// Signature Handling
//
// Records must be signed before transmitting them to another node.
//
// Decoding a record doesn't check its signature. Code working with records from an
// untrusted source must always verify two things: that the record uses an identity scheme
// deemed secure, and that the signature is valid according to the declared scheme.
//
// When creating a record, set the entries you want and use a signing function provided by
// the identity scheme to add the signature. Modifying a record invalidates the signature.
//
// Package enr supports the "secp256k1-keccak" identity scheme.
package enr

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Evolution404/simcore/rlp"
)

// 一条节点的记录最多不能超过300字节
const SizeLimit = 300 // maximum encoded size of a node record in bytes

var (
	ErrInvalidSig     = errors.New("invalid signature on node record")
	errNotSorted      = errors.New("record key/value pairs are not sorted by key")
	errDuplicateKey   = errors.New("record contains duplicate key")
	errIncompletePair = errors.New("record contains incomplete k/v pair")
	errIncompleteList = errors.New("record contains less than two list elements")
	errTooBig         = fmt.Errorf("record bigger than %d bytes", SizeLimit)
	errEncodeUnsigned = errors.New("can't encode unsigned record")
	errNotFound       = errors.New("no such key in record")
)

// An IdentityScheme is capable of verifying record signatures and
// deriving node addresses.
// IdentityScheme对象可以验证记录签名的有效性
// 还能够通过记录计算出地址
// 实现这个接口的有V4ID,v4CompatID,NullID
type IdentityScheme interface {
	Verify(r *Record, sig []byte) error
	NodeAddr(r *Record) []byte
}

// SchemeMap is a registry of named identity schemes.
// 保存多种identity schemes从名字到对象的映射
type SchemeMap map[string]IdentityScheme

func (m SchemeMap) Verify(r *Record, sig []byte) error {
	// 获取identity schemes对象
	s := m[r.IdentityScheme()]
	if s == nil {
		return ErrInvalidSig
	}
	// 通过identity schemes对象来进行验证
	return s.Verify(r, sig)
}

func (m SchemeMap) NodeAddr(r *Record) []byte {
	s := m[r.IdentityScheme()]
	if s == nil {
		return nil
	}
	return s.NodeAddr(r)
}

// Record represents a node record. The zero value is an empty record.
// Record对象了包括三个部分,seq代表记录的序号,pairs记录里的各个键值对,signature记录的签名
// 其中signature最后生成,在设置好序号和所有键值对后再进行签名
type Record struct {
	// 表示记录的序号
	seq uint64 // sequence number
	// 这里签名只保存了r和s,长度64字节
	signature []byte // the signature
	// 保存记录的完整rlp编码
	raw []byte // RLP encoded record
	// 保存记录中的各个条目
	pairs []pair // sorted list of all key/value pairs
}

// pair is a key/value pair in a record.
// pair用来保存一个键值对
type pair struct {
	k string
	v rlp.RawValue
}

// Seq returns the sequence number.
func (r *Record) Seq() uint64 {
	return r.seq
}

// SetSeq updates the record sequence number. This invalidates any signature on the record.
// Calling SetSeq is usually not required because setting any key in a signed record
// increments the sequence number.
// 修改r.seq为输入的值,并清空signature和raw
// 由于修改了序号,缓存的rlp编码和原来的签名都无效了
func (r *Record) SetSeq(s uint64) {
	r.signature = nil
	r.raw = nil
	r.seq = s
}

// Load retrieves the value of a key/value pair. The given Entry must be a pointer and will
// be set to the value of the entry in the record.
//
// Errors returned by Load are wrapped in KeyError. You can distinguish decoding errors
// from missing keys using the IsNotFound function.
// 从Record.pairs中读取指定的key到Entry里
func (r *Record) Load(e Entry) error {
	// 找到Record.pairs中与输入Entry的key相同的位置
	i := sort.Search(len(r.pairs), func(i int) bool { return r.pairs[i].k >= e.ENRKey() })
	// 将pairs[i].v 里保存的的rlp编码解码到e上
	if i < len(r.pairs) && r.pairs[i].k == e.ENRKey() {
		if err := rlp.DecodeBytes(r.pairs[i].v, e); err != nil {
			return &KeyError{Key: e.ENRKey(), Err: err}
		}
		return nil
	}
	return &KeyError{Key: e.ENRKey(), Err: errNotFound}
}

// Set adds or updates the given entry in the record. It panics if the value can't be
// encoded. If the record is signed, Set increments the sequence number and invalidates
// the sequence number.
// 更新或插入Record.pairs中的一项
func (r *Record) Set(e Entry) {
	blob, err := rlp.EncodeToBytes(e)
	if err != nil {
		panic(fmt.Errorf("enr: can't encode %s: %v", e.ENRKey(), err))
	}
	// 每次增加新的键值对,原来的签名和缓存的rlp编码都失效没有意义了
	r.invalidate()

	pairs := make([]pair, len(r.pairs))
	copy(pairs, r.pairs)
	i := sort.Search(len(pairs), func(i int) bool { return pairs[i].k >= e.ENRKey() })
	switch {
	// 是之前存在的key,直接修改
	case i < len(pairs) && pairs[i].k == e.ENRKey():
		// element is present at r.pairs[i]
		pairs[i].v = blob
	// 之前不存在key,需要插入
	case i < len(r.pairs):
		// insert pair before i-th elem
		// 向第i个位置插入一个pair对象
		el := pair{e.ENRKey(), blob}
		pairs = append(pairs, pair{})
		copy(pairs[i+1:], pairs[i:])
		pairs[i] = el
	// 新的key超过所有原有的key,放置到末尾
	default:
		// element should be placed at the end of r.pairs
		pairs = append(pairs, pair{e.ENRKey(), blob})
	}
	r.pairs = pairs
}

// 重置Record
// 清空signature,raw然后让seq自增
func (r *Record) invalidate() {
	if r.signature != nil {
		r.seq++
	}
	r.signature = nil
	r.raw = nil
}

// Signature returns the signature of the record.
// 获取签名,是被重新复制的一份
func (r *Record) Signature() []byte {
	if r.signature == nil {
		return nil
	}
	cpy := make([]byte, len(r.signature))
	copy(cpy, r.signature)
	return cpy
}

// EncodeRLP implements rlp.Encoder. Encoding fails if
// the record is unsigned.
// 对Record对象进行rlp编码,未签名的Record对象不能编码
// 对Record的rlp编码就是写入保存的raw
// 因为在SetSig函数中signature和raw字段被同时设置
// 所以signature不是nil,raw里就保存了rlp编码
func (r Record) EncodeRLP(w io.Writer) error {
	// 还没有生成签名的记录不能生成rlp编码
	if r.signature == nil {
		return errEncodeUnsigned
	}
	_, err := w.Write(r.raw)
	return err
}

// DecodeRLP implements rlp.Decoder. Decoding doesn't verify the signature.
// 从rlp流中解码出一个Record对象
// Record的rlp编码是一个list
// 第一项是signature,第二项是seq,后面依次每两个组成一个键值对
func (r *Record) DecodeRLP(s *rlp.Stream) error {
	dec, raw, err := decodeRecord(s)
	if err != nil {
		return err
	}
	*r = dec
	r.raw = raw
	return nil
}

// 从输入的rlp流s中解析出来一条记录
// 首先解析signature,然后是seq
// 最后是可选的数个键值对,键值对的键必须保证递增且无重复
func decodeRecord(s *rlp.Stream) (dec Record, raw []byte, err error) {
	raw, err = s.Raw()
	if err != nil {
		return dec, raw, err
	}
	if len(raw) > SizeLimit {
		return dec, raw, errTooBig
	}

	// Decode the RLP container.
	s = rlp.NewStream(bytes.NewReader(raw), 0)
	// 确保rlp编码是一个list
	if _, err := s.List(); err != nil {
		return dec, raw, err
	}
	// 解码list里的第一个元素为签名
	if err = s.Decode(&dec.signature); err != nil {
		if err == rlp.EOL {
			err = errIncompleteList
		}
		return dec, raw, err
	}
	// 第二个元素是seq
	if err = s.Decode(&dec.seq); err != nil {
		if err == rlp.EOL {
			err = errIncompleteList
		}
		return dec, raw, err
	}
	// The rest of the record contains sorted k/v pairs.
	// 剩下的部分是数个键值对
	// 键值对的键必须逐个递增,且不能重复
	var prevkey string
	for i := 0; ; i++ {
		var kv pair
		if err := s.Decode(&kv.k); err != nil {
			if err == rlp.EOL {
				break
			}
			return dec, raw, err
		}
		if err := s.Decode(&kv.v); err != nil {
			if err == rlp.EOL {
				return dec, raw, errIncompletePair
			}
			return dec, raw, err
		}
		// 确保key没有重复,并且都是递增
		if i > 0 {
			if kv.k == prevkey {
				return dec, raw, errDuplicateKey
			}
			if kv.k < prevkey {
				return dec, raw, errNotSorted
			}
		}
		dec.pairs = append(dec.pairs, kv)
		prevkey = kv.k
	}
	return dec, raw, s.ListEnd()
}

// IdentityScheme returns the name of the identity scheme in the record.
// 获取Record的pairs中保存的id字段
func (r *Record) IdentityScheme() string {
	var id ID
	r.Load(&id)
	return string(id)
}

// VerifySignature checks whether the record is signed using the given identity scheme.
// 验证签名是否有效
func (r *Record) VerifySignature(s IdentityScheme) error {
	return s.Verify(r, r.signature)
}

// SetSig sets the record signature. It returns an error if the encoded record is larger
// than the size limit or if the signature is invalid according to the passed scheme.
//
// You can also use SetSig to remove the signature explicitly by passing a nil scheme
// and signature.
//
// SetSig panics when either the scheme or the signature (but not both) are nil.
// SeqSig用于为Record对象设置签名
// 参数要求: 需要传入身份模式和签名,两者要么同时为nil,要么都不为nil
// 同时为nil: 用于清空Record对象的签名和缓存的rlp编码
// 都不为nil:
func (r *Record) SetSig(s IdentityScheme, sig []byte) error {
	switch {
	// Prevent storing invalid data.
	// 身份模式和签名不能只有一个是nil，这种情况直接panic
	case s == nil && sig != nil:
		panic("enr: invalid call to SetSig with non-nil signature but nil scheme")
	case s != nil && sig == nil:
		panic("enr: invalid call to SetSig with nil signature but non-nil scheme")
	// Verify if we have a scheme.
	// 两者都不是nil的情况
	// 1. 验证签名是否有效
	// 2. 如果签名有效, 对Record对象进行rlp编码
	case s != nil:
		// 验证签名是否有效
		if err := s.Verify(r, sig); err != nil {
			return err
		}
		// 计算[sig,seq,k1,v1,k2,v2]列表的rlp编码
		raw, err := r.encode(sig)
		if err != nil {
			return err
		}
		// 保存签名和rlp编码
		r.signature, r.raw = sig, raw
	// Reset otherwise.
	// 两者都为nil
	default:
		r.signature, r.raw = nil, nil
	}
	return nil
}

// AppendElements appends the sequence number and entries to the given slice.
// 将Record对象转换成[seq,k1,v1,k2,v2]形式的列表,追加到输入的列表后面
// 这个函数如果输入nil,其实就是将Record对象转换成了一个数组,接下来一般是进行rlp编码
func (r *Record) AppendElements(list []interface{}) []interface{} {
	// 追加的内容第一项是seq
	list = append(list, r.seq)
	// 依次追加后面的键值对
	for _, p := range r.pairs {
		list = append(list, p.k, p.v)
	}
	return list
}

// 计算[sig,seq,k1,v1,k2,v2]这个列表的rlp编码
func (r *Record) encode(sig []byte) (raw []byte, err error) {
	// 创建即将被rlp编码的数组,长度1是第一项为签名,容量是每个键值对两项以及额外的签名和序号
	list := make([]interface{}, 1, 2*len(r.pairs)+2)
	list[0] = sig
	// 构造 sig,seq,k1,v1,k2,v2 这样的一个列表
	// 先将第一项设置为输入的签名
	list[0] = sig
	// 然后将Record中的其他内容追加到后面
	list = r.AppendElements(list)
	// 然后计算rlp编码
	if raw, err = rlp.EncodeToBytes(list); err != nil {
		return nil, err
	}
	if len(raw) > SizeLimit {
		return nil, errTooBig
	}
	return raw, nil
}
