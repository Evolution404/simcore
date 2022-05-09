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
	"crypto/ecdsa"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Evolution404/simcore/crypto"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
	"golang.org/x/crypto/sha3"
)

// Tree is a merkle tree of node records.
// Tree对象里面保存了两棵树,分别是节点信息的树和其他可以查询的链接组成的树
// 节点信息树 最底层是enrEntry(enr:xxx),中间各层都是branchEntry(enrtree-branch:xxx,xxx,xxx)直至树根
// 链接树 最底层是linkEntry(enrtree://xxx),中间各层也都是branchEntry直至树根
type Tree struct {
	// root中保存了节点信息树和链接树对应的树根
	root    *rootEntry
	// key是保存的entry的哈希值前16字节的base32编码
	entries map[string]entry
}

// Sign signs the tree with the given private key and sets the sequence number.
// 对给定的树进行签名,签名保存在t.root.sig里面
// 返回链接,例如 enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org
func (t *Tree) Sign(key *ecdsa.PrivateKey, domain string) (url string, err error) {
	root := *t.root
	// 生成签名
	sig, err := crypto.Sign(root.sigHash(), key)
	if err != nil {
		return "", err
	}
	// 保存签名到Tree里面
	root.sig = sig
	t.root = &root
	// 生成链接
	link := newLinkEntry(domain, &key.PublicKey)
	return link.String(), nil
}

// SetSignature verifies the given signature and assigns it as the tree's current
// signature if valid.
// 验证给定的签名对这棵树是否合法,合法的话就保存这个签名到树中
func (t *Tree) SetSignature(pubkey *ecdsa.PublicKey, signature string) error {
	sig, err := b64format.DecodeString(signature)
	if err != nil || len(sig) != crypto.SignatureLength {
		return errInvalidSig
	}
	root := *t.root
	root.sig = sig
	// 判断新的签名是不是合法
	if !root.verifySignature(pubkey) {
		return errInvalidSig
	}
	// 新的签名合法,修改t.root保存的签名
	t.root = &root
	return nil
}

// Seq returns the sequence number of the tree.
func (t *Tree) Seq() uint {
	return t.root.seq
}

// Signature returns the signature of the tree.
func (t *Tree) Signature() string {
	return b64format.EncodeToString(t.root.sig)
}

// ToTXT returns all DNS TXT records required for the tree.
func (t *Tree) ToTXT(domain string) map[string]string {
	// 初始的映射是域名到树根
	records := map[string]string{domain: t.root.String()}
	// 其他的子节点保存成 hash.域名 到 entry字符串的映射
	for _, e := range t.entries {
		sd := subdomain(e)
		if domain != "" {
			sd = sd + "." + domain
		}
		records[sd] = e.String()
	}
	return records
}

// Links returns all links contained in the tree.
// 返回树中所有的链接信息
func (t *Tree) Links() []string {
	var links []string
	for _, e := range t.entries {
		if le, ok := e.(*linkEntry); ok {
			links = append(links, le.String())
		}
	}
	return links
}

// Nodes returns all nodes contained in the tree.
// 返回树中的所有节点信息
func (t *Tree) Nodes() []*enode.Node {
	var nodes []*enode.Node
	for _, e := range t.entries {
		if ee, ok := e.(*enrEntry); ok {
			nodes = append(nodes, ee.node)
		}
	}
	return nodes
}

/*
We want to keep the UDP size below 512 bytes. The UDP size is roughly:
UDP length = 8 + UDP payload length ( 229 )
UPD Payload length:
 - dns.id 2
 - dns.flags 2
 - dns.count.queries 2
 - dns.count.answers 2
 - dns.count.auth_rr 2
 - dns.count.add_rr 2
 - queries (query-size + 6)
 - answers :
 	- dns.resp.name 2
 	- dns.resp.type 2
 	- dns.resp.class 2
 	- dns.resp.ttl 4
 	- dns.resp.len 2
 	- dns.txt.length 1
 	- dns.txt resp_data_size

So the total size is roughly a fixed overhead of `39`, and the size of the
query (domain name) and response.
The query size is, for example, FVY6INQ6LZ33WLCHO3BPR3FH6Y.snap.mainnet.ethdisco.net (52)

We also have some static data in the response, such as `enrtree-branch:`, and potentially
splitting the response up with `" "`, leaving us with a size of roughly `400` that we need
to stay below.

The number `370` is used to have some margin for extra overhead (for example, the dns query
may be larger - more subdomains).
*/
const (
	hashAbbrevSize = 1 + 16*13/8          // Size of an encoded hash (plus comma)
	maxChildren    = 370 / hashAbbrevSize // 13 children
	minHashLength  = 12
)

// MakeTree creates a tree containing the given nodes and links.
// 给定节点和链接信息,构造Tree对象
func MakeTree(seq uint, nodes []*enode.Node, links []string) (*Tree, error) {
	// Sort records by ID and ensure all nodes have a valid record.
	records := make([]*enode.Node, len(nodes))

	copy(records, nodes)
	sortByID(records)
	// 确保所有记录都有签名
	for _, n := range records {
		if len(n.Record().Signature()) == 0 {
			return nil, fmt.Errorf("can't add node %v: unsigned node record", n.ID())
		}
	}

	// Create the leaf list.
	// 遍历输入的信息,保存到entry类型的列表中
	enrEntries := make([]entry, len(records))
	for i, r := range records {
		enrEntries[i] = &enrEntry{r}
	}
	linkEntries := make([]entry, len(links))
	for i, l := range links {
		le, err := parseLink(l)
		if err != nil {
			return nil, err
		}
		linkEntries[i] = le
	}

	// Create intermediate nodes.
	// 构造节点的梅克尔树
	t := &Tree{entries: make(map[string]entry)}
	eroot := t.build(enrEntries)
	t.entries[subdomain(eroot)] = eroot
	// 构造链接的梅克尔树
	lroot := t.build(linkEntries)
	t.entries[subdomain(lroot)] = lroot
	t.root = &rootEntry{seq: seq, eroot: subdomain(eroot), lroot: subdomain(lroot)}
	return t, nil
}

// 利用输入的构造梅克尔树的树根,中间的所有节点都通过保存到了t.entries中,只有根节点没有保存
// 通过递归进行构造树结构,每次调用构造一层,逐层递归向上构造树
func (t *Tree) build(entries []entry) entry {
	// 如果就1个元素,树根就是他自己
	if len(entries) == 1 {
		return entries[0]
	}
	// 如果保存的节点不超过13个
	// 树根使用一个branchEntry
	if len(entries) <= maxChildren {
		hashes := make([]string, len(entries))
		for i, e := range entries {
			hashes[i] = subdomain(e)
			t.entries[hashes[i]] = e
		}
		return &branchEntry{hashes}
	}
	// 超过13个元素,需要构造多层的树,下面的循环中构造一层子树
	// 最后的return处继续递归向上构造新的层级

	// subtrees用来表示生成的子树
	var subtrees []entry
	for len(entries) > 0 {
		n := maxChildren
		if len(entries) < n {
			n = len(entries)
		}
		// 将列表中的前13个元素构造出来一个branchEntry对象
		sub := t.build(entries[:n])
		entries = entries[n:]
		subtrees = append(subtrees, sub)
		t.entries[subdomain(sub)] = sub
	}
	// 当前层已经构造完成,递归向上构造树
	return t.build(subtrees)
}

// 将列表里的节点按照id的大小排序
func sortByID(nodes []*enode.Node) []*enode.Node {
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID().Bytes(), nodes[j].ID().Bytes()) < 0
	})
	return nodes
}

// Entry Types

type entry interface {
	fmt.Stringer
}

type (
	// enrtree-root有e,l,seq,sig四个字段
	// 版本现在固定是v1,写死在rootPrefix里面
	rootEntry struct {
		eroot string
		lroot string
		seq   uint
		sig   []byte
	}
	branchEntry struct {
		children []string
	}
	enrEntry struct {
		node *enode.Node
	}
	linkEntry struct {
		// 代表原始的字符串去掉前缀
		// 例如: AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@nodes.example.org
		str    string
		// 切割出来的域名
		domain string
		// 解析出来的公钥
		pubkey *ecdsa.PublicKey
	}
)

// Entry Encoding

var (
	b32format = base32.StdEncoding.WithPadding(base32.NoPadding)
	b64format = base64.RawURLEncoding
)

const (
	rootPrefix   = "enrtree-root:v1"
	linkPrefix   = "enrtree://"
	branchPrefix = "enrtree-branch:"
	enrPrefix    = "enr:"
)

// 计算输入entry的哈希值,取哈希值前16字节转化为base32
func subdomain(e entry) string {
	h := sha3.NewLegacyKeccak256()
	io.WriteString(h, e.String())
	return b32format.EncodeToString(h.Sum(nil)[:16])
}

func (e *rootEntry) String() string {
	return fmt.Sprintf(rootPrefix+" e=%s l=%s seq=%d sig=%s", e.eroot, e.lroot, e.seq, b64format.EncodeToString(e.sig))
}

// enrtree-root里面的签名是对这个哈希进行签名
// 也就是计算例如下面格式的哈希
// enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1
func (e *rootEntry) sigHash() []byte {
	h := sha3.NewLegacyKeccak256()
	fmt.Fprintf(h, rootPrefix+" e=%s l=%s seq=%d", e.eroot, e.lroot, e.seq)
	return h.Sum(nil)
}

// 判断rootEntry里的签名是不是指定的公钥执行的
func (e *rootEntry) verifySignature(pubkey *ecdsa.PublicKey) bool {
	sig := e.sig[:crypto.RecoveryIDOffset] // remove recovery id
	enckey := crypto.FromECDSAPub(pubkey)
	return crypto.VerifySignature(enckey, e.sigHash(), sig)
}

func (e *branchEntry) String() string {
	return branchPrefix + strings.Join(e.children, ",")
}

func (e *enrEntry) String() string {
	return e.node.String()
}

func (e *linkEntry) String() string {
	return linkPrefix + e.str
}

// 利用域名和公钥,创建linkEntry对象
func newLinkEntry(domain string, pubkey *ecdsa.PublicKey) *linkEntry {
	key := b32format.EncodeToString(crypto.CompressPubkey(pubkey))
	str := key + "@" + domain
	return &linkEntry{str, domain, pubkey}
}

// Entry Parsing

// 输入的e是查询到的原始字符串,validSchemes用于enr类型解码
// 根据e的前缀,判断是link,branch还是enr 并构造相应的对象
func parseEntry(e string, validSchemes enr.IdentityScheme) (entry, error) {
	switch {
	case strings.HasPrefix(e, linkPrefix):
		return parseLinkEntry(e)
	case strings.HasPrefix(e, branchPrefix):
		return parseBranch(e)
	case strings.HasPrefix(e, enrPrefix):
		return parseENR(e, validSchemes)
	default:
		return nil, errUnknownEntry
	}
}

// 解析enrtree-root
// enrtree-root:v1 e=JWXYDBPXYWG6FX3GMDIBFA6CJ4 l=C7HRFPF3BLGF3YR4DY5KX3SMBE seq=1 sig=o908WmNp7LibOfPsr4btQwatZJ5URBr2ZAuxvK4UWHlsB9sUOTJQaGAlLPVAhM__XJesCHxLISo94z5Z2a463gA
func parseRoot(e string) (rootEntry, error) {
	var eroot, lroot, sig string
	var seq uint
	// 从字符串中读取各个变量
	if _, err := fmt.Sscanf(e, rootPrefix+" e=%s l=%s seq=%d sig=%s", &eroot, &lroot, &seq, &sig); err != nil {
		return rootEntry{}, entryError{"root", errSyntax}
	}
	// 验证两个哈希格式的正确性
	if !isValidHash(eroot) || !isValidHash(lroot) {
		return rootEntry{}, entryError{"root", errInvalidChild}
	}
	// 验证签名格式的正确性
	sigb, err := b64format.DecodeString(sig)
	if err != nil || len(sigb) != crypto.SignatureLength {
		return rootEntry{}, entryError{"root", errInvalidSig}
	}
	return rootEntry{eroot, lroot, seq, sigb}, nil
}

// 解析如下格式的链接,构造linkEntry返回
// enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org
func parseLinkEntry(e string) (entry, error) {
	le, err := parseLink(e)
	if err != nil {
		return nil, err
	}
	return le, nil
}

// 解析出来linkEntry对象,前缀是enrtree://
func parseLink(e string) (*linkEntry, error) {
	if !strings.HasPrefix(e, linkPrefix) {
		return nil, fmt.Errorf("wrong/missing scheme 'enrtree' in URL")
	}
	// 去掉前缀
	e = e[len(linkPrefix):]
	pos := strings.IndexByte(e, '@')
	if pos == -1 {
		return nil, entryError{"link", errNoPubkey}
	}
	// 以@为界,切分出来公钥和域名
	keystring, domain := e[:pos], e[pos+1:]
	keybytes, err := b32format.DecodeString(keystring)
	if err != nil {
		return nil, entryError{"link", errBadPubkey}
	}
	key, err := crypto.DecompressPubkey(keybytes)
	if err != nil {
		return nil, entryError{"link", errBadPubkey}
	}
	return &linkEntry{e, domain, key}, nil
}

// 构造branchEntry对象
// enrtree-branch:2XS2367YHAXJFGLZHVAWLQD4ZY,H4FHT4B454P6UXFD7JCYQ5PWDY,MHTDO6TMUBRIA2XWG5LUDACK24
func parseBranch(e string) (entry, error) {
	e = e[len(branchPrefix):]
	if e == "" {
		return &branchEntry{}, nil // empty entry is OK
	}
	hashes := make([]string, 0, strings.Count(e, ","))
	for _, c := range strings.Split(e, ",") {
		if !isValidHash(c) {
			return nil, entryError{"branch", errInvalidChild}
		}
		hashes = append(hashes, c)
	}
	return &branchEntry{hashes}, nil
}

// 根据字符串构造enrEntry对象,例如如下字符串
// enr:-HW4QLAYqmrwllBEnzWWs7I5Ev2IAs7x_dZlbYdRdMUx5EyKHDXp7AV5CkuPGUPdvbv1_Ms1CPfhcGCvSElSosZmyoqAgmlkgnY0iXNlY3AyNTZrMaECriawHKWdDRk2xeZkrOXBQ0dfMFLHY4eENZwdufn1S1o
func parseENR(e string, validSchemes enr.IdentityScheme) (entry, error) {
	e = e[len(enrPrefix):]
	// 前缀后保存的是base64格式的rlp编码
	enc, err := b64format.DecodeString(e)
	if err != nil {
		return nil, entryError{"enr", errInvalidENR}
	}
	var rec enr.Record
	if err := rlp.DecodeBytes(enc, &rec); err != nil {
		return nil, entryError{"enr", err}
	}
	n, err := enode.New(validSchemes, &rec)
	if err != nil {
		return nil, entryError{"enr", err}
	}
	return &enrEntry{n}, nil
}

// 判断输入的base32字符串解码后是不是合法的哈希值
// 解码后的长度要[12,32]之间,base32字符串不包括换行符,解码过程不能出现错误
func isValidHash(s string) bool {
	// 计算base32解码后的长度
	dlen := b32format.DecodedLen(len(s))
	// 解码后的长度不能小于哈希的最小长度,也不能大于32字节,base32字符串s中也不能包含有换行这些符号
	if dlen < minHashLength || dlen > 32 || strings.ContainsAny(s, "\n\r") {
		return false
	}
	// 将base32解码到buf中
	buf := make([]byte, 32)
	_, err := b32format.Decode(buf, []byte(s))
	return err == nil
}

// truncateHash truncates the given base32 hash string to the minimum acceptable length.
// 将字符串截短,只取哈希的前12字节
func truncateHash(hash string) string {
	// 计算12个字节的数据经过base32编码后的长度
	maxLen := b32format.EncodedLen(minHashLength)
	if len(hash) < maxLen {
		panic(fmt.Errorf("dnsdisc: hash %q is too short", hash))
	}
	// 最终取哈希的前12字节进行编码的base32字符串
	return hash[:maxLen]
}

// URL encoding

// ParseURL parses an enrtree:// URL and returns its components.
// 将以下格式链接切分成域名和公钥
// enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org
func ParseURL(url string) (domain string, pubkey *ecdsa.PublicKey, err error) {
	le, err := parseLink(url)
	if err != nil {
		return "", nil, err
	}
	return le.domain, le.pubkey, nil
}
