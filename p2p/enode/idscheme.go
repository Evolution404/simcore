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

package enode

import (
	"crypto/ecdsa"
	"fmt"
	"io"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
	"golang.org/x/crypto/sha3"
)

// List of known secure identity schemes.
// 当前正常使用的所有节点标识模型
var ValidSchemes = enr.SchemeMap{
	"v4": V4ID{},
}

// 正常使用的以及用于测试的节点标识模型
var ValidSchemesForTesting = enr.SchemeMap{
	"v4":   V4ID{},
	"null": NullID{},
}

// v4ID is the "v4" identity scheme.
type V4ID struct{}

// SignV4 signs a record using the v4 scheme.
// 使用输入的私钥对记录r签名
// 这个函数为Record对象增加了id,secp256k1键值对,然后调用了Record.SetSig
func SignV4(r *enr.Record, privkey *ecdsa.PrivateKey) error {
	// Copy r to avoid modifying it if signing fails.
	cpy := *r
	// 往Record对象里加入两个pair  id:v4,secp256k1:publickey
	cpy.Set(enr.ID("v4"))
	// 保存的公钥是33字节的压缩格式
	cpy.Set(Secp256k1(privkey.PublicKey))

	h := sha3.NewLegacyKeccak256()
	// 计算节点记录的rlp编码
	rlp.Encode(h, cpy.AppendElements(nil))
	// 对rlp编码的哈希进行签名
	sig, err := crypto.Sign(h.Sum(nil), privkey)
	if err != nil {
		return err
	}
	// 去掉签名末尾的v,转换成64字节格式
	sig = sig[:len(sig)-1] // remove v
	// 签名已经计算出来了,通过SetSig方法注册到Record对象内部
	if err = cpy.SetSig(V4ID{}, sig); err == nil {
		*r = cpy
	}
	return err
}

// 验证enr.Record对象的签名
// 用于实现IdentityScheme接口
func (V4ID) Verify(r *enr.Record, sig []byte) error {
	// 从Record中加载公钥,并且长度必须是33字节
	// 这里不使用Secp256k1类型,是为了避免接下来VerifySignature函数之前将公钥对象再进行一次转换成字节数组
	var entry s256raw
	if err := r.Load(&entry); err != nil {
		return err
	} else if len(entry) != 33 {
		return fmt.Errorf("invalid public key")
	}

	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, r.AppendElements(nil))
	if !crypto.VerifySignature(entry, h.Sum(nil), sig) {
		return enr.ErrInvalidSig
	}
	return nil
}

// 利用节点记录enr.Record对象,计算出节点ID
// 节点ID计算规则: keccak256(pub.X || pub.Y)
// 节点地址就是将公钥的X,Y拼在一起变成64字节的buf,然后对buf求哈希
func (V4ID) NodeAddr(r *enr.Record) []byte {
	var pubkey Secp256k1
	// 解析出来原始的公钥,未经压缩的
	err := r.Load(&pubkey)
	if err != nil {
		return nil
	}
	// 将公钥的X和Y坐标拼接起来成64字节
	buf := make([]byte, 64)
	math.ReadBits(pubkey.X, buf[:32])
	math.ReadBits(pubkey.Y, buf[32:])
	// 对64字节拼接结果求哈希
	return crypto.Keccak256(buf)
}

// Secp256k1 is the "secp256k1" key, which holds a public key.
// 代表键值对中的公钥键值对
// 公钥在记录中是以压缩格式保存
type Secp256k1 ecdsa.PublicKey

func (v Secp256k1) ENRKey() string { return "secp256k1" }

// EncodeRLP implements rlp.Encoder.
// 对公钥压缩后进行rlp编码
func (v Secp256k1) EncodeRLP(w io.Writer) error {
	// 保存压缩格式公钥
	return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v)))
}

// DecodeRLP implements rlp.Decoder.
// 解码rlp编码,将解析出来的内容进行解压
func (v *Secp256k1) DecodeRLP(s *rlp.Stream) error {
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	// 解压公钥
	pk, err := crypto.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	*v = (Secp256k1)(*pk)
	return nil
}

// s256raw is an unparsed secp256k1 public key entry.
// 代表公钥的原始字节数组,在V4ID.Verify函数中使用
// 避免使用Secp256k1解码出来的是公钥对象还要再转换成字节数组
// 因为crypto.VerifySignature输入的公钥是字节数组
type s256raw []byte

func (s256raw) ENRKey() string { return "secp256k1" }

// v4CompatID is a weaker and insecure version of the "v4" scheme which only checks for the
// presence of a secp256k1 public key, but doesn't verify the signature.
// 不执行签名,只检查记录中是否有公钥
type v4CompatID struct {
	V4ID
}

// 验证过程只尝试加载公钥
func (v4CompatID) Verify(r *enr.Record, sig []byte) error {
	var pubkey Secp256k1
	return r.Load(&pubkey)
}

func signV4Compat(r *enr.Record, pubkey *ecdsa.PublicKey) {
	r.Set((*Secp256k1)(pubkey))
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil {
		panic(err)
	}
}

// NullID is the "null" ENR identity scheme. This scheme stores the node
// ID in the record without any signature.
// 不进行签名,节点的地址就是SignNull传入的id
type NullID struct{}

func (NullID) Verify(r *enr.Record, sig []byte) error {
	return nil
}

func (NullID) NodeAddr(r *enr.Record) []byte {
	var id ID
	r.Load(enr.WithEntry("nulladdr", &id))
	return id[:]
}

func SignNull(r *enr.Record, id ID) *Node {
	r.Set(enr.ID("null"))
	r.Set(enr.WithEntry("nulladdr", id))
	if err := r.SetSig(NullID{}, []byte{}); err != nil {
		panic(err)
	}
	return &Node{r: *r, id: id}
}
