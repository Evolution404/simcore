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

package nodestate

import (
	"errors"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/Evolution404/simcore/common/mclock"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/metrics"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/enr"
	"github.com/Evolution404/simcore/rlp"
)

var (
	ErrInvalidField = errors.New("invalid field type")
	ErrClosed       = errors.New("already closed")
)

type (
	// NodeStateMachine implements a network node-related event subscription system.
	// It can assign binary state flags and fields of arbitrary type to each node and allows
	// subscriptions to flag/field changes which can also modify further flags and fields,
	// potentially triggering further subscriptions. An operation includes an initial change
	// and all resulting subsequent changes and always ends in a consistent global state.
	// It is initiated by a "top level" SetState/SetField call that blocks (also blocking other
	// top-level functions) until the operation is finished. Callbacks making further changes
	// should use the non-blocking SetStateSub/SetFieldSub functions. The tree of events
	// resulting from the initial changes is traversed in a breadth-first order, ensuring for
	// each subscription callback that all other callbacks caused by the same change triggering
	// the current callback are processed before anything is triggered by the changes made in the
	// current callback. In practice this logic ensures that all subscriptions "see" events in
	// the logical order, callbacks are never called concurrently and "back and forth" effects
	// are also possible. The state machine design should ensure that infinite event cycles
	// cannot happen.
	// The caller can also add timeouts assigned to a certain node and a subset of state flags.
	// If the timeout elapses, the flags are reset. If all relevant flags are reset then the timer
	// is dropped. State flags with no timeout are persisted in the database if the flag
	// descriptor enables saving. If a node has no state flags set at any moment then it is discarded.
	// Note: in order to avoid mutex deadlocks the callbacks should never lock a mutex that
	// might be locked when the top level SetState/SetField functions are called. If a function
	// potentially performs state/field changes then it is recommended to mention this fact in the
	// function description, along with whether it should run inside an operation callback.
	NodeStateMachine struct {
		// started用来标记Start函数是否调用过
		started, closed bool
		lock            sync.Mutex
		clock           mclock.Clock
		db              ethdb.KeyValueStore
		// 在数据库中存储的数据使用的前缀,在NewNodeStateMachine函数中指定
		dbNodeKey []byte
		// 记录了所有的节点,根据节点id区分
		// SetField,SetState会增加nodes中的项
		// 以及Start函数也会从数据库中恢复nodes
		nodes map[enode.ID]*nodeInfo
		// Start前:记录了从offlineState转移到的状态
		// 调用Start后,在Stop前:记录了从什么状态转移到offlineState
		offlineCallbackList []offlineCallback
		// opFlag为true代表当前正在有操作进行
		// 也就是说当前有协程正在运行在opStart和opFinish之间
		// 此时再调用opStart将会阻塞
		opFlag bool       // an operation has started
		opWait *sync.Cond // signaled when the operation ends
		// 当前操作的一系列回调函数,回调函数在opFinish中调用
		opPending []func() // pending callback list of the current operation

		// Registered state flags or fields. Modifications are allowed
		// only when the node state machine has not been started.
		setup *Setup
		// 与setup.fields中的元素一一对应
		fields []*fieldInfo
		// 记录setup.flags中的哪些persistent设为true
		saveFlags bitMask

		// Installed callbacks. Modifications are allowed only when the
		// node state machine has not been started.
		// 保存了订阅的比特位和对应的回调函数
		stateSubs []stateSub

		// Testing hooks, only for testing purposes.
		// 只有测试的时候使用
		saveNodeHook func(*nodeInfo)
	}

	// Flags represents a set of flags from a certain setup
	Flags struct {
		mask  bitMask
		setup *Setup
	}

	// Field represents a field from a certain setup
	Field struct {
		index int
		setup *Setup
	}

	// flagDefinition describes a node state flag. Each registered instance is automatically
	// mapped to a bit of the 64 bit node states.
	// If persistent is true then the node is saved when state machine is shutdown.
	flagDefinition struct {
		name       string
		persistent bool
	}

	// fieldDefinition describes an optional node field of the given type. The contents
	// of the field are only retained for each node as long as at least one of the
	// state flags is set.
	fieldDefinition struct {
		name   string
		ftype  reflect.Type
		encode func(interface{}) ([]byte, error)
		decode func([]byte) (interface{}, error)
	}

	// stateSetup contains the list of flags and fields used by the application
	Setup struct {
		Version uint
		flags   []flagDefinition
		fields  []fieldDefinition
	}

	// bitMask describes a node state or state mask. It represents a subset
	// of node flags with each bit assigned to a flag index (LSB represents flag 0).
	bitMask uint64

	// StateCallback is a subscription callback which is called when one of the
	// state flags that is included in the subscription state mask is changed.
	// Note: oldState and newState are also masked with the subscription mask so only
	// the relevant bits are included.
	// 状态发生变化时的回调函数
	// oldState和newState中只有被订阅的那些比特位有意义
	// 代表此时发生了从oldState到newState的状态变化
	StateCallback func(n *enode.Node, oldState, newState Flags)

	// FieldCallback is a subscription callback which is called when the value of
	// a specific field is changed.
	// 字段发生变化时的回调函数
	// state表示字段发生变化时的状态,字段从oldValue变成了newValue
	FieldCallback func(n *enode.Node, state Flags, oldValue, newValue interface{})

	// nodeInfo contains node state, fields and state timeouts
	// 保存了一个节点的相关信息,当前的状态还有各个字段的值
	nodeInfo struct {
		node       *enode.Node
		state      bitMask
		timeouts   []*nodeStateTimeout
		fields     []interface{}
		fieldCount int
		// db为true代表这个nodeInfo对象保存在数据库中
		// dirty代表当前nodeInfo是否发生了变动,导致与数据库中不一致
		db, dirty bool
	}

	// 编码到数据库中的节点记录格式
	nodeInfoEnc struct {
		Enr     enr.Record
		Version uint
		State   bitMask
		Fields  [][]byte
	}

	// 代表一个state的订阅
	// 保存了订阅的比特位和回调函数
	stateSub struct {
		mask     bitMask
		callback StateCallback
	}

	// 超时事件,里面的计时器到时间的时候会重置哪些位
	nodeStateTimeout struct {
		mask  bitMask
		timer mclock.Timer
	}

	fieldInfo struct {
		fieldDefinition
		subs []FieldCallback
	}

	offlineCallback struct {
		node   *nodeInfo
		state  bitMask
		fields []interface{}
	}
)

// offlineState is a special state that is assumed to be set before a node is loaded from
// the database and after it is shut down.
// offlineState是一个特殊的状态,代表节点从数据库加载之前或者停止以后的状态
// offline一定保存在Setup.flags数组的最开始位置,所以这个mask直接就是1
const offlineState = bitMask(1)

// NewFlag creates a new node state flag
// 在Setup.flags中新增一个flagDefinition对象,其中persistent为false
// 返回的Flags中有一位是1,具体位置取决于Setup之前已经有多少个flags
func (s *Setup) NewFlag(name string) Flags {
	// 默认有一个flag是offline
	if s.flags == nil {
		s.flags = []flagDefinition{{name: "offline"}}
	}
	f := Flags{mask: bitMask(1) << uint(len(s.flags)), setup: s}
	s.flags = append(s.flags, flagDefinition{name: name})
	return f
}

// NewPersistentFlag creates a new persistent node state flag
// 在Setup.flags中新增一个flagDefinition对象,其中persistent为true
// 返回的Flags中有一位是1,具体位置取决于Setup之前已经有多少个flags
func (s *Setup) NewPersistentFlag(name string) Flags {
	if s.flags == nil {
		s.flags = []flagDefinition{{name: "offline"}}
	}
	f := Flags{mask: bitMask(1) << uint(len(s.flags)), setup: s}
	s.flags = append(s.flags, flagDefinition{name: name, persistent: true})
	return f
}

// OfflineFlag returns the system-defined offline flag belonging to the given setup
// 获得offline的Flags对象
// 它的mask就是1,相当于左移0位,因为offline保存在Setup.flags的最开始位置
func (s *Setup) OfflineFlag() Flags {
	return Flags{mask: offlineState, setup: s}
}

// NewField creates a new node state field
// 在Setup.fields中新增一个fieldDefinition对象,其中encode和decode为nil
func (s *Setup) NewField(name string, ftype reflect.Type) Field {
	f := Field{index: len(s.fields), setup: s}
	s.fields = append(s.fields, fieldDefinition{
		name:  name,
		ftype: ftype,
	})
	return f
}

// NewPersistentField creates a new persistent node field
// 在Setup.fields中新增一个fieldDefinition对象,参数中指定了其中的encode和decode
func (s *Setup) NewPersistentField(name string, ftype reflect.Type, encode func(interface{}) ([]byte, error), decode func([]byte) (interface{}, error)) Field {
	f := Field{index: len(s.fields), setup: s}
	s.fields = append(s.fields, fieldDefinition{
		name:   name,
		ftype:  ftype,
		encode: encode,
		decode: decode,
	})
	return f
}

// flagOp implements binary flag operations and also checks whether the operands belong to the same setup
// 生成一个新的Flags对象,其中的mask由a和b计算出来
// trueIfA指a中位为1,b中位为0的设置结果为1
// trueIfA指a中位为0,b中位为1的设置结果为1
// trueIfBoth指a中位为1,b中位为1的设置结果为1
// 这三种只要有一种设置为1,最终mask的那个位就是1
func flagOp(a, b Flags, trueIfA, trueIfB, trueIfBoth bool) Flags {
	// 如果setup为nil,使用另一个的setup
	if a.setup == nil {
		if a.mask != 0 {
			panic("Node state flags have no setup reference")
		}
		a.setup = b.setup
	}
	if b.setup == nil {
		if b.mask != 0 {
			panic("Node state flags have no setup reference")
		}
		b.setup = a.setup
	}
	// 两者的setup必须一致
	if a.setup != b.setup {
		panic("Node state flags belong to a different setup")
	}
	res := Flags{setup: a.setup}
	// 根据方式,设置mask
	if trueIfA {
		res.mask |= a.mask & ^b.mask
	}
	if trueIfB {
		res.mask |= b.mask & ^a.mask
	}
	if trueIfBoth {
		res.mask |= a.mask & b.mask
	}
	return res
}

// And returns the set of flags present in both a and b
// 将a和b的mask按位与
func (a Flags) And(b Flags) Flags { return flagOp(a, b, false, false, true) }

// AndNot returns the set of flags present in a but not in b
// a中为1但是b中为0的为设置为1
func (a Flags) AndNot(b Flags) Flags { return flagOp(a, b, true, false, false) }

// Or returns the set of flags present in either a or b
// a和b的mask按位或
func (a Flags) Or(b Flags) Flags { return flagOp(a, b, true, true, true) }

// Xor returns the set of flags present in either a or b but not both
// a和b按位异或
func (a Flags) Xor(b Flags) Flags { return flagOp(a, b, true, true, false) }

// HasAll returns true if b is a subset of a
// b所有置1的位,a都是1
func (a Flags) HasAll(b Flags) bool { return flagOp(a, b, false, true, false).mask == 0 }

// HasNone returns true if a and b have no shared flags
// a和b没有同时是1的位
func (a Flags) HasNone(b Flags) bool { return flagOp(a, b, false, false, true).mask == 0 }

// Equals returns true if a and b have the same flags set
// a和b所有位都相同
func (a Flags) Equals(b Flags) bool { return flagOp(a, b, true, true, false).mask == 0 }

// IsEmpty returns true if a has no flags set
// a的所有位都是0
func (a Flags) IsEmpty() bool { return a.mask == 0 }

// MergeFlags merges multiple sets of state flags
// 将所有输入的Flags的mask进行或运算,得到最终结果
func MergeFlags(list ...Flags) Flags {
	if len(list) == 0 {
		return Flags{}
	}
	res := list[0]
	for i := 1; i < len(list); i++ {
		res = res.Or(list[i])
	}
	return res
}

// String returns a list of the names of the flags specified in the bit mask
// 将Flags转换成 "[name, name, name]" 这种格式
// name代表了mask中指定的flag的名字
func (f Flags) String() string {
	if f.mask == 0 {
		return "[]"
	}
	s := "["
	comma := false
	// 找到mask为1的比特位
	// 将这些flag的名称加入到返回的字符串中
	for index, flag := range f.setup.flags {
		if f.mask&(bitMask(1)<<uint(index)) != 0 {
			if comma {
				s = s + ", "
			}
			s = s + flag.name
			comma = true
		}
	}
	s = s + "]"
	return s
}

// NewNodeStateMachine creates a new node state machine.
// If db is not nil then the node states, fields and active timeouts are persisted.
// Persistence can be enabled or disabled for each state flag and field.
func NewNodeStateMachine(db ethdb.KeyValueStore, dbKey []byte, clock mclock.Clock, setup *Setup) *NodeStateMachine {
	if setup.flags == nil {
		panic("No state flags defined")
	}
	// 用uint64来表示所有状态,每个状态用一位,所以总共flags的个数不能超过64个
	if len(setup.flags) > 8*int(unsafe.Sizeof(bitMask(0))) {
		panic("Too many node state flags")
	}
	ns := &NodeStateMachine{
		db:        db,
		dbNodeKey: dbKey,
		clock:     clock,
		setup:     setup,
		nodes:     make(map[enode.ID]*nodeInfo),
		// 初始化为setup.fields的长度,下面的循环中与setup.fields中的每一项一一对应
		fields: make([]*fieldInfo, len(setup.fields)),
	}
	// 使用NodeStateMachine中自动初始化的锁来生成sync.Cond对象
	ns.opWait = sync.NewCond(&ns.lock)
	// 接下来的循环用来设置ns.saveFlags,找到persistent为true的flags在对应位设置为1
	// 记录flags.name到在setup.flags的下标的映射,目的在于避免出现名称重复的flags
	stateNameMap := make(map[string]int)
	for index, flag := range setup.flags {
		if _, ok := stateNameMap[flag.name]; ok {
			panic("Node state flag name collision: " + flag.name)
		}
		stateNameMap[flag.name] = index
		if flag.persistent {
			ns.saveFlags |= bitMask(1) << uint(index)
		}
	}
	// 接下来的循环用来保存ns.fields,每一项生成一个fieldInfo对象
	// 这个也是用来避免出现重复名称的field
	fieldNameMap := make(map[string]int)
	for index, field := range setup.fields {
		if _, ok := fieldNameMap[field.name]; ok {
			panic("Node field name collision: " + field.name)
		}
		ns.fields[index] = &fieldInfo{fieldDefinition: field}
		fieldNameMap[field.name] = index
	}
	return ns
}

// stateMask checks whether the set of flags belongs to the same setup and returns its internal bit mask
// 判断NodeStateMachine与输入的Flags是否属于同一个setup
// 如果属于同一个setup,返回这个Flags的mask
func (ns *NodeStateMachine) stateMask(flags Flags) bitMask {
	if flags.setup != ns.setup && flags.mask != 0 {
		panic("Node state flags belong to a different setup")
	}
	return flags.mask
}

// fieldIndex checks whether the field belongs to the same setup and returns its internal index
// 判断NodeStateMachine与输入的Field是否属于同一个setup
// 如果属于同一个setup,返回这个Field的index
func (ns *NodeStateMachine) fieldIndex(field Field) int {
	if field.setup != ns.setup {
		panic("Node field belongs to a different setup")
	}
	return field.index
}

// SubscribeState adds a node state subscription. The callback is called while the state
// machine mutex is not held and it is allowed to make further state updates using the
// non-blocking SetStateSub/SetFieldSub functions. All callbacks of an operation are running
// from the thread/goroutine of the initial caller and parallel operations are not permitted.
// Therefore the callback is never called concurrently. It is the responsibility of the
// implemented state logic to avoid deadlocks and to reach a stable state in a finite amount
// of steps.
// State subscriptions should be installed before loading the node database or making the
// first state update.
// 该函数必须在Start函数之前调用
// 输入的Flags中比特位为1的位置是被订阅的位置,当这些位置发生变动的时候会调用回调函数
func (ns *NodeStateMachine) SubscribeState(flags Flags, callback StateCallback) {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if ns.started {
		panic("state machine already started")
	}
	// 在ns.stateSubs中添加一项
	ns.stateSubs = append(ns.stateSubs, stateSub{ns.stateMask(flags), callback})
}

// SubscribeField adds a node field subscription. Same rules apply as for SubscribeState.
// 该函数必须在Start函数之前调用
// 将回调函数记录到指定的field下
// 也就是ns.fields[index].subs中增加一项,index是这个field所在的下标,保存在Field对象中
func (ns *NodeStateMachine) SubscribeField(field Field, callback FieldCallback) {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if ns.started {
		panic("state machine already started")
	}
	// 往ns.fields[index].subs中增加回调函数
	f := ns.fields[ns.fieldIndex(field)]
	f.subs = append(f.subs, callback)
}

// newNode creates a new nodeInfo
// 新建一个nodeInfo对象
func (ns *NodeStateMachine) newNode(n *enode.Node) *nodeInfo {
	return &nodeInfo{node: n, fields: make([]interface{}, len(ns.fields))}
}

// checkStarted checks whether the state machine has already been started and panics otherwise.
// 检查是否调用了Start函数,如果调用过Start直接panic
func (ns *NodeStateMachine) checkStarted() {
	if !ns.started {
		panic("state machine not started yet")
	}
}

// Start starts the state machine, enabling state and field operations and disabling
// further subscriptions.
// 启动状态机,执行Start后不再允许订阅状态或者字段
func (ns *NodeStateMachine) Start() {
	ns.lock.Lock()
	if ns.started {
		panic("state machine already started")
	}
	ns.started = true
	if ns.db != nil {
		ns.loadFromDb()
	}

	ns.opStart()
	ns.offlineCallbacks(true)
	ns.opFinish()
	ns.lock.Unlock()
}

// Stop stops the state machine and saves its state if a database was supplied
func (ns *NodeStateMachine) Stop() {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if !ns.opStart() {
		panic("already closed")
	}
	// 更新offlineCallbackList,用于接下来调用ns.offlineCallbacks
	for _, node := range ns.nodes {
		fields := make([]interface{}, len(node.fields))
		copy(fields, node.fields)
		ns.offlineCallbackList = append(ns.offlineCallbackList, offlineCallback{node, node.state, fields})
	}
	if ns.db != nil {
		ns.saveToDb()
	}
	ns.offlineCallbacks(false)
	ns.closed = true
	ns.opFinish()
}

// loadFromDb loads persisted node states from the database
// 数据库中保存着节点的信息 key是dbNodeKey+nodeid
func (ns *NodeStateMachine) loadFromDb() {
	it := ns.db.NewIterator(ns.dbNodeKey, nil)
	for it.Next() {
		var id enode.ID
		if len(it.Key()) != len(ns.dbNodeKey)+len(id) {
			log.Error("Node state db entry with invalid length", "found", len(it.Key()), "expected", len(ns.dbNodeKey)+len(id))
			continue
		}
		copy(id[:], it.Key()[len(ns.dbNodeKey):])
		ns.decodeNode(id, it.Value())
	}
}

type dummyIdentity enode.ID

func (id dummyIdentity) Verify(r *enr.Record, sig []byte) error { return nil }
func (id dummyIdentity) NodeAddr(r *enr.Record) []byte          { return id[:] }

// decodeNode decodes a node database entry and adds it to the node set if successful
// 输入的是数据库中记录的rlp编码,将它解码成nodeInfo对象
func (ns *NodeStateMachine) decodeNode(id enode.ID, data []byte) {
	var enc nodeInfoEnc
	// 先解码成nodeInfoEnc对象
	if err := rlp.DecodeBytes(data, &enc); err != nil {
		log.Error("Failed to decode node info", "id", id, "error", err)
		return
	}
	n, _ := enode.New(dummyIdentity(id), &enc.Enr)
	node := ns.newNode(n)
	node.db = true

	// 数据库中的版本与现在的版本不一致,放弃解码并且从数据库中删除这个记录
	if enc.Version != ns.setup.Version {
		log.Debug("Removing stored node with unknown version", "current", ns.setup.Version, "stored", enc.Version)
		ns.deleteNode(id)
		return
	}
	// 数据库中的字段多于现在的字段,报错
	if len(enc.Fields) > len(ns.setup.fields) {
		log.Error("Invalid node field count", "id", id, "stored", len(enc.Fields))
		return
	}
	// Resolve persisted node fields
	for i, encField := range enc.Fields {
		// 长度为0说明是没有持久化字段
		if len(encField) == 0 {
			continue
		}
		if decode := ns.fields[i].decode; decode != nil {
			// 解码字段并保存起来
			if field, err := decode(encField); err == nil {
				node.fields[i] = field
				node.fieldCount++
			} else {
				log.Error("Failed to decode node field", "id", id, "field name", ns.fields[i].name, "error", err)
				return
			}
		} else {
			log.Error("Cannot decode node field", "id", id, "field name", ns.fields[i].name)
			return
		}
	}
	// It's a compatible node record, add it to set.
	// 将恢复出来的nodeInfo保存到NodeStateMachine中
	ns.nodes[id] = node
	node.state = enc.State
	fields := make([]interface{}, len(node.fields))
	copy(fields, node.fields)
	ns.offlineCallbackList = append(ns.offlineCallbackList, offlineCallback{node, node.state, fields})
	log.Debug("Loaded node state", "id", id, "state", Flags{mask: enc.State, setup: ns.setup})
}

// saveNode saves the given node info to the database
// 将节点的信息保存到数据库中
func (ns *NodeStateMachine) saveNode(id enode.ID, node *nodeInfo) error {
	if ns.db == nil {
		return nil
	}

	// 只保存那些需要持久化的状态
	storedState := node.state & ns.saveFlags
	// 设置了超时时间的那些位设置为0,因为他们过一会就超时了,没有必要保存成1,直接保存为0
	for _, t := range node.timeouts {
		storedState &= ^t.mask
	}
	enc := nodeInfoEnc{
		Enr:     *node.node.Record(),
		Version: ns.setup.Version,
		State:   storedState,
		// 只有那些需要持久化的字段会保存到这里
		// 不需要保存的字段在这个数组中也会占一个空位置
		Fields: make([][]byte, len(ns.fields)),
	}
	log.Debug("Saved node state", "id", id, "state", Flags{mask: enc.State, setup: ns.setup})
	lastIndex := -1
	for i, f := range node.fields {
		if f == nil {
			continue
		}
		// 没有编码函数直接跳过,说明这个字段不需要保存到数据库
		encode := ns.fields[i].encode
		if encode == nil {
			continue
		}
		blob, err := encode(f)
		if err != nil {
			return err
		}
		// 按照与nodeInfo.fields相同的位置保存的nodeInfoEnc.Fields中
		enc.Fields[i] = blob
		lastIndex = i
	}
	// 没有需要保存的内容
	if storedState == 0 && lastIndex == -1 {
		// 这个节点之前在数据库中,由于没有要保存的内容直接删除
		if node.db {
			node.db = false
			ns.deleteNode(id)
		}
		node.dirty = false
		return nil
	}
	enc.Fields = enc.Fields[:lastIndex+1]
	// 生成rlp编码
	data, err := rlp.EncodeToBytes(&enc)
	if err != nil {
		return err
	}
	// 保存到数据库中,key是dbNodeKey+id, value是nodeInfoEnc的rlp编码
	if err := ns.db.Put(append(ns.dbNodeKey, id[:]...), data); err != nil {
		return err
	}
	// 刚刚写入了数据库,显然要设置dirty为false
	// 现在节点保存到数据库中了所以db设置为true
	node.dirty, node.db = false, true

	// 将节点保存到数据库的时候的回调,只是在测试中使用
	if ns.saveNodeHook != nil {
		ns.saveNodeHook(node)
	}
	return nil
}

// deleteNode removes a node info from the database
// 从数据库中删除指定节点的记录
func (ns *NodeStateMachine) deleteNode(id enode.ID) {
	ns.db.Delete(append(ns.dbNodeKey, id[:]...))
}

// saveToDb saves the persistent flags and fields of all nodes that have been changed
func (ns *NodeStateMachine) saveToDb() {
	for id, node := range ns.nodes {
		if node.dirty {
			err := ns.saveNode(id, node)
			if err != nil {
				log.Error("Failed to save node", "id", id, "error", err)
			}
		}
	}
}

// updateEnode updates the enode entry belonging to the given node if it already exists
// 如果输入的Node对象的Seq更大,就对原有的记录进行更新
func (ns *NodeStateMachine) updateEnode(n *enode.Node) (enode.ID, *nodeInfo) {
	id := n.ID()
	node := ns.nodes[id]
	if node != nil && n.Seq() > node.node.Seq() {
		node.node = n
		node.dirty = true
	}
	return id, node
}

// Persist saves the persistent state and fields of the given node immediately
func (ns *NodeStateMachine) Persist(n *enode.Node) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if id, node := ns.updateEnode(n); node != nil && node.dirty {
		err := ns.saveNode(id, node)
		if err != nil {
			log.Error("Failed to save node", "id", id, "error", err)
		}
		return err
	}
	return nil
}

// SetState updates the given node state flags and blocks until the operation is finished.
// If a flag with a timeout is set again, the operation removes or replaces the existing timeout.
// 将setFlags中位修改为1,resetFlags中的位修改为0
// 如果指定了timeout,那么超时后setFlags中的位会被重置为0
func (ns *NodeStateMachine) SetState(n *enode.Node, setFlags, resetFlags Flags, timeout time.Duration) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if !ns.opStart() {
		return ErrClosed
	}
	ns.setState(n, setFlags, resetFlags, timeout)
	ns.opFinish()
	return nil
}

// SetStateSub updates the given node state flags without blocking (should be called
// from a subscription/operation callback).
// 这个函数用于SubscribeState,SubscribeField或者Operation的回调函数中调用
func (ns *NodeStateMachine) SetStateSub(n *enode.Node, setFlags, resetFlags Flags, timeout time.Duration) {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.opCheck()
	ns.setState(n, setFlags, resetFlags, timeout)
}

func (ns *NodeStateMachine) setState(n *enode.Node, setFlags, resetFlags Flags, timeout time.Duration) {
	ns.checkStarted()
	set, reset := ns.stateMask(setFlags), ns.stateMask(resetFlags)
	id, node := ns.updateEnode(n)
	if node == nil {
		if set == 0 {
			return
		}
		node = ns.newNode(n)
		ns.nodes[id] = node
	}
	oldState := node.state
	// 计算出来要转移成什么状态
	newState := (node.state & (^reset)) | set
	changed := oldState ^ newState
	// 将状态修改为转移后的状态
	node.state = newState

	// Remove the timeout callbacks for all reset and set flags,
	// even they are not existent(it's noop).
	ns.removeTimeouts(node, set|reset)

	// Register the timeout callback if required
	// 设置超时时间,超时时间到达后将会把set中的位设置为0
	if timeout != 0 && set != 0 {
		ns.addTimeout(n, set, timeout)
	}
	if newState == oldState {
		return
	}
	// 没有状态也没有字段,删除
	if newState == 0 && node.fieldCount == 0 {
		delete(ns.nodes, id)
		if node.db {
			ns.deleteNode(id)
		}
	} else {
		// 修改了要持久化的位,那么就设置dirty为true
		if changed&ns.saveFlags != 0 {
			node.dirty = true
		}
	}
	callback := func() {
		for _, sub := range ns.stateSubs {
			// 如果修改了订阅的位,调用回调函数
			if changed&sub.mask != 0 {
				sub.callback(n, Flags{mask: oldState & sub.mask, setup: ns.setup}, Flags{mask: newState & sub.mask, setup: ns.setup})
			}
		}
	}
	ns.opPending = append(ns.opPending, callback)
}

// opCheck checks whether an operation is active
// 检查opFlag是不是true,如果是false直接恐慌
func (ns *NodeStateMachine) opCheck() {
	if !ns.opFlag {
		panic("Operation has not started")
	}
}

// opStart waits until other operations are finished and starts a new one
// opStart一直等待其他的操作完成,然后再开始一个新的
// 一直阻塞到opFlag变为false,然后再修改opFlag为true
// 返回值为true代表修改opFlag成功,为false说明NodeStateMachine.closed为true
// opStart的调用与opFinish一一对应
func (ns *NodeStateMachine) opStart() bool {
	for ns.opFlag {
		ns.opWait.Wait()
	}
	if ns.closed {
		return false
	}
	ns.opFlag = true
	return true
}

// opFinish finishes the current operation by running all pending callbacks.
// Callbacks resulting from a state/field change performed in a previous callback are always
// put at the end of the pending list and therefore processed after all callbacks resulting
// from the previous state/field change.
// 调用一个操作的所有回调函数,然后启动一个新的操作
// opFinish与opStart的调用一一对应
func (ns *NodeStateMachine) opFinish() {
	// 循环执行回调,直到所有回调函数都执行完成
	for len(ns.opPending) != 0 {
		list := ns.opPending
		ns.lock.Unlock()
		for _, cb := range list {
			cb()
		}
		ns.lock.Lock()
		// 循环执行回调的过程中去掉了锁,所以回调可能在这期间增加了
		ns.opPending = ns.opPending[len(list):]
	}
	ns.opPending = nil
	ns.opFlag = false
	ns.opWait.Broadcast()
}

// Operation calls the given function as an operation callback. This allows the caller
// to start an operation with multiple initial changes. The same rules apply as for
// subscription callbacks.
// 执行一个自定义的操作
func (ns *NodeStateMachine) Operation(fn func()) error {
	ns.lock.Lock()
	started := ns.opStart()
	ns.lock.Unlock()
	if !started {
		return ErrClosed
	}
	fn()
	ns.lock.Lock()
	ns.opFinish()
	ns.lock.Unlock()
	return nil
}

// offlineCallbacks calls state update callbacks at startup or shutdown
// 在Start和Stop函数中调用,输入参数用来标记是在Start中调用还是在Stop中调用
// 该函数用于在启动和停止的时候生成回调函数,因为启动和停止也造成了状态转移
func (ns *NodeStateMachine) offlineCallbacks(start bool) {
	for _, cb := range ns.offlineCallbackList {
		cb := cb
		callback := func() {
			for _, sub := range ns.stateSubs {
				// 这两个状态都和sub.mask进行按位与,是因为输入回调函数的状态只包括订阅的状态位
				offState := offlineState & sub.mask
				onState := cb.state & sub.mask
				// 状态没有变化不调用
				if offState == onState {
					continue
				}
				// start时是从offState转移到onState
				// stop时是从onState转移到offState
				if start {
					sub.callback(cb.node.node, Flags{mask: offState, setup: ns.setup}, Flags{mask: onState, setup: ns.setup})
				} else {
					sub.callback(cb.node.node, Flags{mask: onState, setup: ns.setup}, Flags{mask: offState, setup: ns.setup})
				}
			}
			// start时字段是从nil变为记录中内容
			// stop时字段是从记录中内容变为nil
			for i, f := range cb.fields {
				// f==nil说明字段没有变化,不调用回调
				// 这个字段没有回调函数也不调用回调
				if f == nil || ns.fields[i].subs == nil {
					continue
				}
				for _, fsub := range ns.fields[i].subs {
					if start {
						fsub(cb.node.node, Flags{mask: offlineState, setup: ns.setup}, nil, f)
					} else {
						fsub(cb.node.node, Flags{mask: offlineState, setup: ns.setup}, f, nil)
					}
				}
			}
		}
		// 添加到等待执行的函数列表中
		ns.opPending = append(ns.opPending, callback)
	}
	// 清空offlineCallbackList
	ns.offlineCallbackList = nil
}

// AddTimeout adds a node state timeout associated to the given state flag(s).
// After the specified time interval, the relevant states will be reset.
// 针对某节点的某个状态设置超时时间,达到时间后重置这个状态
func (ns *NodeStateMachine) AddTimeout(n *enode.Node, flags Flags, timeout time.Duration) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if ns.closed {
		return ErrClosed
	}
	ns.addTimeout(n, ns.stateMask(flags), timeout)
	return nil
}

// addTimeout adds a node state timeout associated to the given state flag(s).
// 超时后将mask中为1的位设置为零
func (ns *NodeStateMachine) addTimeout(n *enode.Node, mask bitMask, timeout time.Duration) {
	_, node := ns.updateEnode(n)
	if node == nil {
		return
	}
	mask &= node.state
	// 没有需要超时重置的位,直接返回
	if mask == 0 {
		return
	}
	// 将这些位原来的超时时间删除掉
	ns.removeTimeouts(node, mask)
	t := &nodeStateTimeout{mask: mask}
	t.timer = ns.clock.AfterFunc(timeout, func() {
		ns.lock.Lock()
		defer ns.lock.Unlock()

		if !ns.opStart() {
			return
		}
		ns.setState(n, Flags{}, Flags{mask: t.mask, setup: ns.setup}, 0)
		ns.opFinish()
	})
	node.timeouts = append(node.timeouts, t)
	// 节点的持久化状态有的被修改了,将会与数据库不一致
	if mask&ns.saveFlags != 0 {
		node.dirty = true
	}
}

// removeTimeout removes node state timeouts associated to the given state flag(s).
// If a timeout was associated to multiple flags which are not all included in the
// specified remove mask then only the included flags are de-associated and the timer
// stays active.
// 移除mask中指定的位的定时器
func (ns *NodeStateMachine) removeTimeouts(node *nodeInfo, mask bitMask) {
	for i := 0; i < len(node.timeouts); i++ {
		t := node.timeouts[i]
		match := t.mask & mask
		// match==0代表这一项nodeStateTimeout完全不匹配,跳过
		if match == 0 {
			continue
		}
		// t.mask-match==0说明完全匹配,需要停止计时器
		// t.mask-match!=0说明不完全,不停止计时器但是删除这些匹配的位
		t.mask -= match
		if t.mask != 0 {
			continue
		}
		// 到这里说明完全匹配,停止计时器
		t.timer.Stop()
		node.timeouts[i] = node.timeouts[len(node.timeouts)-1]
		node.timeouts = node.timeouts[:len(node.timeouts)-1]
		i--
		if match&ns.saveFlags != 0 {
			node.dirty = true
		}
	}
}

// GetField retrieves the given field of the given node. Note that when used in a
// subscription callback the result can be out of sync with the state change represented
// by the callback parameters so extra safety checks might be necessary.
func (ns *NodeStateMachine) GetField(n *enode.Node, field Field) interface{} {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if ns.closed {
		return nil
	}
	if _, node := ns.updateEnode(n); node != nil {
		return node.fields[ns.fieldIndex(field)]
	}
	return nil
}

// GetState retrieves the current state of the given node. Note that when used in a
// subscription callback the result can be out of sync with the state change represented
// by the callback parameters so extra safety checks might be necessary.
func (ns *NodeStateMachine) GetState(n *enode.Node) Flags {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if ns.closed {
		return Flags{}
	}
	if _, node := ns.updateEnode(n); node != nil {
		return Flags{mask: node.state, setup: ns.setup}
	}
	return Flags{}
}

// SetField sets the given field of the given node and blocks until the operation is finished
func (ns *NodeStateMachine) SetField(n *enode.Node, field Field, value interface{}) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	if !ns.opStart() {
		return ErrClosed
	}
	err := ns.setField(n, field, value)
	ns.opFinish()
	return err
}

// SetFieldSub sets the given field of the given node without blocking (should be called
// from a subscription/operation callback).
// 这个函数用于SubscribeState,SubscribeField或者Operation的回调函数中调用
func (ns *NodeStateMachine) SetFieldSub(n *enode.Node, field Field, value interface{}) error {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.opCheck()
	return ns.setField(n, field, value)
}

func (ns *NodeStateMachine) setField(n *enode.Node, field Field, value interface{}) error {
	ns.checkStarted()
	id, node := ns.updateEnode(n)
	if node == nil {
		if value == nil {
			return nil
		}
		node = ns.newNode(n)
		ns.nodes[id] = node
	}
	fieldIndex := ns.fieldIndex(field)
	f := ns.fields[fieldIndex]
	if value != nil && reflect.TypeOf(value) != f.ftype {
		log.Error("Invalid field type", "type", reflect.TypeOf(value), "required", f.ftype)
		return ErrInvalidField
	}
	oldValue := node.fields[fieldIndex]
	if value == oldValue {
		return nil
	}
	if oldValue != nil {
		node.fieldCount--
	}
	if value != nil {
		node.fieldCount++
	}
	node.fields[fieldIndex] = value
	if node.state == 0 && node.fieldCount == 0 {
		delete(ns.nodes, id)
		if node.db {
			ns.deleteNode(id)
		}
	} else {
		if f.encode != nil {
			node.dirty = true
		}
	}
	state := node.state
	callback := func() {
		for _, cb := range f.subs {
			cb(n, Flags{mask: state, setup: ns.setup}, oldValue, value)
		}
	}
	ns.opPending = append(ns.opPending, callback)
	return nil
}

// ForEach calls the callback for each node having all of the required and none of the
// disabled flags set.
// Note that this callback is not an operation callback but ForEach can be called from an
// Operation callback or Operation can also be called from a ForEach callback if necessary.
// 针对所有符合要求的节点调用回调函数
// 也就是requireFlags中为1全为1,disableFlags中为1的全为0
func (ns *NodeStateMachine) ForEach(requireFlags, disableFlags Flags, cb func(n *enode.Node, state Flags)) {
	ns.lock.Lock()
	ns.checkStarted()
	type callback struct {
		node  *enode.Node
		state bitMask
	}
	require, disable := ns.stateMask(requireFlags), ns.stateMask(disableFlags)
	var callbacks []callback
	// 找到所有符合要求的节点
	for _, node := range ns.nodes {
		if node.state&require == require && node.state&disable == 0 {
			callbacks = append(callbacks, callback{node.node, node.state & (require | disable)})
		}
	}
	ns.lock.Unlock()
	// 为所有符合要求的节点,调用回调函数
	for _, c := range callbacks {
		cb(c.node, Flags{mask: c.state, setup: ns.setup})
	}
}

// GetNode returns the enode currently associated with the given ID
// 找到指定ID的节点
func (ns *NodeStateMachine) GetNode(id enode.ID) *enode.Node {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	ns.checkStarted()
	if node := ns.nodes[id]; node != nil {
		return node.node
	}
	return nil
}

// AddLogMetrics adds logging and/or metrics for nodes entering, exiting and currently
// being in a given set specified by required and disabled state flags
// 当有节点进入或退出指定的范围的时候进行记录
// 指定的范围指requireFlags中为1的全为1,disableFlags为1的全为0
// inMeter统计节点进入范围的次数,outMeter统计节点退出范围的次数,gauge记录进出范围的总次数
func (ns *NodeStateMachine) AddLogMetrics(requireFlags, disableFlags Flags, name string, inMeter, outMeter metrics.Meter, gauge metrics.Gauge) {
	var count int64
	ns.SubscribeState(requireFlags.Or(disableFlags), func(n *enode.Node, oldState, newState Flags) {
		oldMatch := oldState.HasAll(requireFlags) && oldState.HasNone(disableFlags)
		newMatch := newState.HasAll(requireFlags) && newState.HasNone(disableFlags)
		// 之前之后都匹配或者都不匹配说明没有退出或进入范围,不进行记录
		if newMatch == oldMatch {
			return
		}

		// 原来不匹配,现在匹配 说明该节点进入
		if newMatch {
			count++
			if name != "" {
				log.Debug("Node entered", "set", name, "id", n.ID(), "count", count)
			}
			if inMeter != nil {
				inMeter.Mark(1)
			}
			// 原来匹配,现在不匹配 说明该节点退出
		} else {
			count--
			if name != "" {
				log.Debug("Node left", "set", name, "id", n.ID(), "count", count)
			}
			if outMeter != nil {
				outMeter.Mark(1)
			}
		}
		// gauge统计节点进出的次数
		if gauge != nil {
			gauge.Update(count)
		}
	})
}
