// Copyright 2020 The go-ethereum Authors
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

package v5wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"hash"

	"github.com/Evolution404/simcore/common/math"
	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enode"
	"golang.org/x/crypto/hkdf"
)

const (
	// Encryption/authentication parameters.
	// aes加密解密使用的密钥长度是16字节
	aesKeySize   = 16
	// 默认的Nonce长度是12字节
	gcmNonceSize = 12
)

// Nonce represents a nonce used for AES/GCM.
type Nonce [gcmNonceSize]byte

// EncodePubkey encodes a public key.
// 获取压缩格式的公钥,公钥所在的曲线必须是secp256k1
func EncodePubkey(key *ecdsa.PublicKey) []byte {
	switch key.Curve {
	case crypto.S256():
		return crypto.CompressPubkey(key)
	default:
		panic("unsupported curve " + key.Curve.Params().Name + " in EncodePubkey")
	}
}

// DecodePubkey decodes a public key in compressed format.
// 将压缩格式的公钥还原成ecdsa.PublicKey对象
// 输入的曲线curve必须是secp256k1
func DecodePubkey(curve elliptic.Curve, e []byte) (*ecdsa.PublicKey, error) {
	switch curve {
	case crypto.S256():
		if len(e) != 33 {
			return nil, errors.New("wrong size public key data")
		}
		return crypto.DecompressPubkey(e)
	default:
		return nil, fmt.Errorf("unsupported curve %s in DecodePubkey", curve.Params().Name)
	}
}

// idNonceHash computes the ID signature hash used in the handshake.
// 该函数用来生成签名数据的哈希,也就是如下这个数据的哈希
// id-signature-input = "discovery v5 identity proof" || challenge-data || ephemeral-pubkey || node-id-B
// 返回 sha256(id-signature-input)
// 变动的部分是挑战数据,本地临时公钥,远程节点的ID
func idNonceHash(h hash.Hash, challenge, ephkey []byte, destID enode.ID) []byte {
	h.Reset()
	h.Write([]byte("discovery v5 identity proof"))
	h.Write(challenge)
	h.Write(ephkey)
	h.Write(destID[:])
	return h.Sum(nil)
}

// makeIDSignature creates the ID nonce signature.
// 生成握手包中的id-signature
// 先拼接出来签名数据(id-signature-input),然后计算签名数据的哈希(sha256(id-signature-input)),然后对哈希签名
// id-signature = id_sign(sha256(id-signature-input))
// id-signature-input = "discovery v5 identity proof" || challenge-data || ephemeral-pubkey || node-id-B
// 输入的key是本地私钥,ephkey是本地刚刚生成的临时公钥
// 生成签名需要本地私钥,签名的数据是由挑战数据,本地临时公钥和远程节点ID这些组成
// 返回的签名是64字节格式,包括r和s去掉了v
func makeIDSignature(hash hash.Hash, key *ecdsa.PrivateKey, challenge, ephkey []byte, destID enode.ID) ([]byte, error) {
	// 首先计算签名数据的哈希
	input := idNonceHash(hash, challenge, ephkey, destID)
	switch key.Curve {
	case crypto.S256():
		// 然后用私钥对数据的哈希签名
		idsig, err := crypto.Sign(input, key)
		if err != nil {
			return nil, err
		}
		return idsig[:len(idsig)-1], nil // remove recovery ID
	default:
		return nil, fmt.Errorf("unsupported curve %s", key.Curve.Params().Name)
	}
}

// s256raw is an unparsed secp256k1 public key ENR entry.
// 未经压缩的secp256k1曲线的公钥
type s256raw []byte

func (s256raw) ENRKey() string { return "secp256k1" }

// verifyIDSignature checks that signature over idnonce was made by the given node.
// 接收到握手包后验证签名是否有效
// n是从握手包中解析出来的远程节点记录,保存了远程节点的公钥
// challenge是本地发送WHOAREYOU包时保存下来的挑战数据
// ephkey是从握手包中获取的远程节点A生成的临时公钥
// destID是本地节点的ID
func verifyIDSignature(hash hash.Hash, sig []byte, n *enode.Node, challenge, ephkey []byte, destID enode.ID) error {
	// 现在只有v4
	switch idscheme := n.Record().IdentityScheme(); idscheme {
	case "v4":
		var pubkey s256raw
		if n.Load(&pubkey) != nil {
			return errors.New("no secp256k1 public key in record")
		}
		input := idNonceHash(hash, challenge, ephkey, destID)
		if !crypto.VerifySignature(pubkey, input, sig) {
			return errInvalidNonceSig
		}
		return nil
	default:
		return fmt.Errorf("can't verify ID nonce signature against scheme %q", idscheme)
	}
}

type hashFn func() hash.Hash

// deriveKeys creates the session keys.
// 通过本地私钥和远程的临时公钥得出来对称加密使用的密钥,返回会话对象
// 生成session需要本地私钥,远程临时公钥,节点A的id,节点B的id,挑战数据
// 需要注意接收方和发送方调用这个函数恢复出来的会话对象完全一致
// 所以需要有一方调用session.keysFlipped来交换writeKey和readKey
func deriveKeys(hash hashFn, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, n1, n2 enode.ID, challenge []byte) *session {
	const text = "discovery v5 key agreement"
	var info = make([]byte, 0, len(text)+len(n1)+len(n2))
	info = append(info, text...)
	info = append(info, n1[:]...)
	info = append(info, n2[:]...)

	// 两个节点都能计算出来的相同的秘密
	eph := ecdh(priv, pub)
	if eph == nil {
		return nil
	}
	kdf := hkdf.New(hash, eph, challenge, info)
	sec := session{writeKey: make([]byte, aesKeySize), readKey: make([]byte, aesKeySize)}
	// 将秘密扩展成两个密钥
	kdf.Read(sec.writeKey)
	kdf.Read(sec.readKey)
	for i := range eph {
		eph[i] = 0
	}
	// 返回会话对象
	return &sec
}

// ecdh creates a shared secret.
// 通过本地私钥和远程临时公钥,计算本地和远程节点共享的密钥
func ecdh(privkey *ecdsa.PrivateKey, pubkey *ecdsa.PublicKey) []byte {
	// 计算本地私钥与远程节点公钥的乘积
	// secX,secY分别是椭圆曲线上点的横纵坐标
	secX, secY := pubkey.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes())
	if secX == nil {
		return nil
	}
	sec := make([]byte, 33)
	sec[0] = 0x02 | byte(secY.Bit(0))
	math.ReadBits(secX, sec[1:])
	return sec
}

// encryptGCM encrypts pt using AES-GCM with the given key and nonce. The ciphertext is
// appended to dest, which must not overlap with plaintext. The resulting ciphertext is 16
// bytes longer than plaintext because it contains an authentication tag.
// 使用给定的key和nonce加密plaintext,将密文追加到dest,并返回密文
// 密文比原文长度增加了16字节,因为增加了认证信息
func encryptGCM(dest, key, nonce, plaintext, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Errorf("can't create block cipher: %v", err))
	}
	// 这里可以直接使用cipher.NewGCM,因为nonce的长度就是标准的12字节
	// 这里可能是为了避免以后可能修改nonce的长度
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		panic(fmt.Errorf("can't create GCM: %v", err))
	}
	// 将密文追加到dest后部,并返回密文
	return aesgcm.Seal(dest, nonce, plaintext, authData), nil
}

// decryptGCM decrypts ct using AES-GCM with the given key and nonce.
// AES-GCM的解密函数,用来解密ct
func decryptGCM(key, nonce, ct, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("can't create block cipher: %v", err)
	}
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("invalid GCM nonce size: %d", len(nonce))
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return nil, fmt.Errorf("can't create GCM: %v", err)
	}
	pt := make([]byte, 0, len(ct))
	return aesgcm.Open(pt, nonce, ct, authData)
}
