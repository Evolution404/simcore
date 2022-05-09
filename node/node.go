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

package node

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/Evolution404/simcore/accounts"
	"github.com/Evolution404/simcore/core/rawdb"
	"github.com/Evolution404/simcore/ethdb"
	"github.com/Evolution404/simcore/event"
	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p"
	"github.com/Evolution404/simcore/rpc"
	"github.com/prometheus/tsdb/fileutil"
)

// Node is a container on which services can be registered.
// n:=New(config)
// n.RegisterLifecycle(lifecycle)
// n.Start()
// n.Close()

// 一个node.Node对象内部运行了p2p服务和RPC服务
// p2p服务使用p2p.Server实现
// RPC服务实现了四种连接方式,分别是进程内,进程间,http,websocket
type Node struct {
	eventmux      *event.TypeMux
	config        *Config
	accman        *accounts.Manager
	log           log.Logger
	keyDir        string            // key store directory
	keyDirTemp    bool              // If true, key directory will be removed by Stop
	// 避免并发访问节点的专属文件夹,访问结束要调用dirLock.Release()释放锁
	dirLock       fileutil.Releaser // prevents concurrent use of instance directory
	stop          chan struct{}     // Channel to wait for termination notifications
	server        *p2p.Server       // Currently running P2P networking layer
	// Start和Close函数中使用,避免这两个函数并发执行
	startStopLock sync.Mutex        // Start/Stop are protected by an additional lock
	// 节点当前的状态,总共有三种
	state         int               // Tracks state of node lifecycle

	lock          sync.Mutex
	// 所有通过RegisterLifecycle注册的服务
	lifecycles    []Lifecycle // All registered backends, services, and auxiliary services that have a lifecycle
	// rpcAPIs保存了当前节点能够提供的所有RPC调用
	rpcAPIs       []rpc.API   // List of APIs currently provided by the node
	// http协议的rpc通信服务
	http          *httpServer //
	// websocket协议的rpc通信服务
	ws            *httpServer //
	// 进程间rpc通信的服务
	ipc           *ipcServer  // Stores information about the ipc http server
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	// 保存节点打开的所有数据库
	// 封装成closeTrackingDB是为了只需要对数据库对象调用Close方法就能从databases字段中删除
	databases map[*closeTrackingDB]struct{} // All open databases
}

const (
	initializingState = iota
	runningState
	closedState
)

// New creates a new P2P node, ready for protocol registration.
// 创建一个p2p节点,等待注册协议
// 创建一个node.Node主要包括以下步骤
// 处理配置信息,数据文件夹路径转换成绝对路径,节点名称合法
// 初始化Node对象,主要创建了p2p.Server对象,在rpcAPIs中添加内置方法
// 创建四个rpc服务对象,但是没有启动 进程内是rpc.Server,进程间是ipcServer,http和websocket都是httpServer
func New(conf *Config) (*Node, error) {
	// Copy config and resolve the datadir so future changes to the current
	// working directory don't affect the node.
	// 这里把Config对象复制了一份,每个节点单独有一个Config对象
	// 这样调用New的时候输入的Config可以重复使用,不用担心DataDir被修改了
	confCopy := *conf
	conf = &confCopy
	if conf.DataDir != "" {
		absdatadir, err := filepath.Abs(conf.DataDir)
		if err != nil {
			return nil, err
		}
		conf.DataDir = absdatadir
	}
	if conf.Logger == nil {
		conf.Logger = log.New()
	}

	// Ensure that the instance name doesn't cause weird conflicts with
	// other files in the data directory.
	// 确保节点的名称不是奇奇怪怪的内容
	// 不能包括斜杠,反斜杠
	if strings.ContainsAny(conf.Name, `/\`) {
		return nil, errors.New(`Config.Name must not contain '/' or '\'`)
	}
	// 不能和keystore一样
	if conf.Name == datadirDefaultKeyStore {
		return nil, errors.New(`Config.Name cannot be "` + datadirDefaultKeyStore + `"`)
	}
	// 不能和ipc文件一样有这个后缀
	if strings.HasSuffix(conf.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}

	// 创建Node对象
	node := &Node{
		config: conf,
		// 启动的时候就创建一个线程内的rpc.server
		inprocHandler: rpc.NewServer(),
		eventmux:      new(event.TypeMux),
		log:           conf.Logger,
		stop:          make(chan struct{}),
		// 这个节点内部运行的p2p服务对象
		server:    &p2p.Server{Config: conf.P2P},
		databases: make(map[*closeTrackingDB]struct{}),
	}

	// Register built-in APIs.
	// 保存内置的RPC APIs
	node.rpcAPIs = append(node.rpcAPIs, node.apis()...)

	// Acquire the instance directory lock.
	if err := node.openDataDir(); err != nil {
		return nil, err
	}
	keyDir, isEphem, err := getKeyStoreDir(conf)
	if err != nil {
		return nil, err
	}
	node.keyDir = keyDir
	node.keyDirTemp = isEphem
	// Creates an empty AccountManager with no backends. Callers (e.g. cmd/geth)
	// are required to add the backends later on.
	node.accman = accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: conf.InsecureUnlockAllowed})

	// Initialize the p2p server. This creates the node key and discovery databases.
	// 为刚刚创建的p2p.Server指定一些必要的信息
	// 指定节点私钥
	node.server.Config.PrivateKey = node.config.NodeKey()
	// 指定节点的标识符
	node.server.Config.Name = node.config.NodeName()
	node.server.Config.Logger = node.log
	if node.server.Config.StaticNodes == nil {
		node.server.Config.StaticNodes = node.config.StaticNodes()
	}
	if node.server.Config.TrustedNodes == nil {
		node.server.Config.TrustedNodes = node.config.TrustedNodes()
	}
	// 节点发现数据库的路径
	if node.server.Config.NodeDatabase == "" {
		node.server.Config.NodeDatabase = node.config.NodeDB()
	}

	// Check HTTP/WS prefixes are valid.
	if err := validatePrefix("HTTP", conf.HTTPPathPrefix); err != nil {
		return nil, err
	}
	if err := validatePrefix("WebSocket", conf.WSPathPrefix); err != nil {
		return nil, err
	}

	// Configure RPC servers.
	// 处理http,ws,ipc请求
	node.http = newHTTPServer(node.log, conf.HTTPTimeouts)
	node.ws = newHTTPServer(node.log, rpc.DefaultHTTPTimeouts)
	node.ipc = newIPCServer(node.log, conf.IPCEndpoint())

	return node, nil
}

// Start starts all registered lifecycles, RPC services and p2p networking.
// Node can only be started once.
// 只有刚初始化完成的节点才能调用Start也就是initializingState状态才能启动
// 启动一个节点,包括三个部分
// 调用所有服务Start方法
// 启动四种RPC服务
// 启动p2p网络
func (n *Node) Start() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()
	n.lock.Lock()
	if n.stop == nil {
		n.stop = make(chan struct{})
	}
	if n.inprocHandler == nil{
		n.inprocHandler = rpc.NewServer()
	}
	// 调用Start时节点的状态必须是initializingState
	switch n.state {
	case runningState:
		n.lock.Unlock()
		return ErrNodeRunning
		//case closedState:
		//	n.lock.Unlock()
		//	return ErrNodeStopped
	}
	// 修改运行状态
	n.state = runningState
	// open networking and RPC endpoints
	// 启动p2p网络和四种RPC服务
	err := n.openEndpoints()
	// 下面就执行所有注册服务的Start方法
	lifecycles := make([]Lifecycle, len(n.lifecycles))
	copy(lifecycles, n.lifecycles)
	n.lock.Unlock()

	// Check if endpoint startup failed.
	if err != nil {
		n.doClose(nil)
		return err
	}
	// Start all registered lifecycles.
	// started保存所有调用过Start方法且没有错误的服务
	var started []Lifecycle
	for _, lifecycle := range lifecycles {
		// 顺序执行所有服务,遇到错误就停止下来的所有服务
		if err = lifecycle.Start(); err != nil {
			break
		}
		started = append(started, lifecycle)
	}
	// Check if any lifecycle failed to start.
	// 遇到错误,关闭刚才执行成功的服务
	if err != nil {
		n.stopServices(started)
		n.doClose(nil)
	}
	return err
}

// Close stops the Node and releases resources acquired in
// Node constructor New.
// 关闭一个节点,处于以下三种状态的不同处理方式
// 初始化状态: doClose
// 运行状态: 停止所有服务,doClose
// 关闭状态: 报错
func (n *Node) Close() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()
	n.lock.Lock()
	state := n.state
	n.lock.Unlock()
	switch state {
	case initializingState:
		// The node was never started.
		return n.doClose(nil)
	case runningState:
		// The node was started, release resources acquired by Start().
		var errs []error
		// 释放Start占用的资源
		if err := n.stopServices(n.lifecycles); err != nil {
			errs = append(errs, err)
		}
		return n.doClose(errs)
	case closedState:
		return ErrNodeStopped
	default:
		panic(fmt.Sprintf("node is in unknown state %d", state))
	}
}

// doClose releases resources acquired by New(), collecting errors.
// 释放New()中使用的资源
// 关闭所有数据库,关闭账户管理,删除临时私钥,释放专属文件夹
func (n *Node) doClose(errs []error) error {
	// Close databases. This needs the lock because it needs to
	// synchronize with OpenDatabase*.
	n.lock.Lock()
	// 修改状态到关闭
	n.state = closedState
	// 关闭所有数据库
	errs = append(errs, n.closeDatabases()...)
	n.lock.Unlock()

	// 关闭账户管理
	if n.accman != nil {
		if err := n.accman.Close(); err != nil {
			errs = append(errs, err)
		}
		n.accman = nil
	}
	// 删除临时私钥
	if n.keyDirTemp {
		if err := os.RemoveAll(n.keyDir); err != nil {
			errs = append(errs, err)
		}
	}

	// Release instance directory lock.
	// 释放节点专属文件夹
	n.closeDataDir()

	// Unblock n.Wait.
	close(n.stop)
	n.stop = nil
	// Report any errors that might have occurred.
	// 将错误列表合并成一个错误
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return fmt.Errorf("%v", errs)
	}
}

// openEndpoints starts all network and RPC endpoints.
// 启动p2p网络和四种RPC服务
func (n *Node) openEndpoints() error {
	// start networking endpoints
	n.log.Info("Starting peer-to-peer node", "instance", n.server.Name)
	// 启动p2p网络
	if err := n.server.Start(); err != nil {
		return convertFileLockError(err)
	}
	// start RPC endpoints
	// 启动RPC服务
	err := n.startRPC()
	if err != nil {
		n.stopRPC()
		n.server.Stop()
	}
	return err
}

// containsLifecycle checks if 'lfs' contains 'l'.
// 检查lfs中是否包括l
func containsLifecycle(lfs []Lifecycle, l Lifecycle) bool {
	for _, obj := range lfs {
		if obj == l {
			return true
		}
	}
	return false
}

// stopServices terminates running services, RPC and p2p networking.
// It is the inverse of Start.
// 关闭所有的服务,分为三个过程
// stopRPC()
// 所有输入的正在运行的服务调用Stop()
// n.server.Stop() 关闭p2p网络
func (n *Node) stopServices(running []Lifecycle) error {
	n.stopRPC()

	// Stop running lifecycles in reverse order.
	// failure记录所有服务调用Stop发生的错误
	failure := &StopError{Services: make(map[reflect.Type]error)}
	// 倒序执行Stop方法
	for i := len(running) - 1; i >= 0; i-- {
		if err := running[i].Stop(); err != nil {
			failure.Services[reflect.TypeOf(running[i])] = err
		}
	}

	// Stop p2p networking.
	n.server.Stop()

	if len(failure.Services) > 0 {
		return failure
	}
	return nil
}

// 为专属文件夹生成锁
func (n *Node) openDataDir() error {
	if n.config.DataDir == "" {
		return nil // ephemeral
	}

	// 节点的专属文件夹,DataDir与节点名称拼起来
	instdir := filepath.Join(n.config.DataDir, n.config.name())
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return err
	}
	// Lock the instance directory to prevent concurrent use by another instance as well as
	// accidental use of the instance directory as a database.
	// 生成占用这个文件夹的锁
	release, _, err := fileutil.Flock(filepath.Join(instdir, "LOCK"))
	if err != nil {
		return convertFileLockError(err)
	}
	n.dirLock = release
	return nil
}

// 释放专属文件夹的锁
func (n *Node) closeDataDir() {
	// Release instance directory lock.
	if n.dirLock != nil {
		if err := n.dirLock.Release(); err != nil {
			n.log.Error("Can't release datadir lock", "err", err)
		}
		n.dirLock = nil
	}
}

// configureRPC is a helper method to configure all the various RPC endpoints during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
// 启动各个RPC服务,包括ipc,http,ws以及进程内
func (n *Node) startRPC() error {
	// 启动进程内通信
	if err := n.startInProc(); err != nil {
		return err
	}

	// Configure IPC.
	// 启动进程间通信
	if n.ipc.endpoint != "" {
		if err := n.ipc.start(n.rpcAPIs); err != nil {
			return err
		}
	}

	// Configure HTTP.
	// 配置http协议
	if n.config.HTTPHost != "" {
		config := httpConfig{
			CorsAllowedOrigins: n.config.HTTPCors,
			Vhosts:             n.config.HTTPVirtualHosts,
			Modules:            n.config.HTTPModules,
			prefix:             n.config.HTTPPathPrefix,
		}
		if err := n.http.setListenAddr(n.config.HTTPHost, n.config.HTTPPort); err != nil {
			return err
		}
		if err := n.http.enableRPC(n.rpcAPIs, config); err != nil {
			return err
		}
	}

	// Configure WebSocket.
	// 配置websocket协议
	if n.config.WSHost != "" {
		// 这里如果websocket和http共用一个端口或者http没有启动,就使用同一个httpServer对象
		server := n.wsServerForPort(n.config.WSPort)
		config := wsConfig{
			Modules: n.config.WSModules,
			Origins: n.config.WSOrigins,
			prefix:  n.config.WSPathPrefix,
		}
		if err := server.setListenAddr(n.config.WSHost, n.config.WSPort); err != nil {
			return err
		}
		if err := server.enableWS(n.rpcAPIs, config); err != nil {
			return err
		}
	}

	// 启动http
	if err := n.http.start(); err != nil {
		return err
	}
	// 启动websocket
	return n.ws.start()
}

// 这里如果websocket和http共用一个端口或者http没有启动,就使用同一个httpServer对象
func (n *Node) wsServerForPort(port int) *httpServer {
	if n.config.HTTPHost == "" || n.http.port == port {
		return n.http
	}
	return n.ws
}

// 调用四种类型通信的stop方法
func (n *Node) stopRPC() {
	n.http.stop()
	n.ws.stop()
	n.ipc.stop()
	n.stopInProc()
}

// startInProc registers all RPC APIs on the inproc server.
// 为inprocHandler注册n.rpcAPIs中保存的服务
func (n *Node) startInProc() error {
	for _, api := range n.rpcAPIs {
		if err := n.inprocHandler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
	}
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
func (n *Node) stopInProc() {
	n.inprocHandler.Stop()
	n.inprocHandler = nil
}

// Wait blocks until the node is closed.
func (n *Node) Wait() {
	<-n.stop
}

// RegisterLifecycle registers the given Lifecycle on the node.
// 为节点注册服务,注册服务时节点必须在初始化状态
func (n *Node) RegisterLifecycle(lifecycle Lifecycle) {
	n.lock.Lock()
	defer n.lock.Unlock()

	// 必须是初始化状态
	if n.state != initializingState {
		panic("can't register lifecycle on running/stopped node")
	}
	// 不能重复注册
	if containsLifecycle(n.lifecycles, lifecycle) {
		panic(fmt.Sprintf("attempt to register lifecycle %T more than once", lifecycle))
	}
	n.lifecycles = append(n.lifecycles, lifecycle)
}

// RegisterProtocols adds backend's protocols to the node's p2p server.
func (n *Node) RegisterProtocols(protocols []p2p.Protocol) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register protocols on running/stopped node")
	}
	n.server.Protocols = append(n.server.Protocols, protocols...)
}

// RegisterAPIs registers the APIs a service provides on the node.
func (n *Node) RegisterAPIs(apis []rpc.API) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register APIs on running/stopped node")
	}
	n.rpcAPIs = append(n.rpcAPIs, apis...)
}

// RegisterHandler mounts a handler on the given path on the canonical HTTP server.
//
// The name of the handler is shown in a log message when the HTTP server starts
// and should be a descriptive term for the service provided by the handler.
// 为节点注册某个路径下的处理函数
// 这个方法必须在节点启动前调用
func (n *Node) RegisterHandler(name, path string, handler http.Handler) {
	n.lock.Lock()
	defer n.lock.Unlock()

	// 不是initializingState状态,不能注册处理函数
	if n.state != initializingState {
		panic("can't register HTTP handler on running/stopped node")
	}

	// 在mux中注册处理函数
	n.http.mux.Handle(path, handler)
	// httpServer中记录下来路径和名称
	n.http.handlerNames[path] = name
}

// Attach creates an RPC client attached to an in-process API handler.
// 获取一个rpc.Client对象
// 通信过程是内存中直接通信
func (n *Node) Attach() (*rpc.Client, error) {
	return rpc.DialInProc(n.inprocHandler), nil
}

// RPCHandler returns the in-process RPC request handler.
// 获取处理进程内请求的rpc.Server对象
func (n *Node) RPCHandler() (*rpc.Server, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state == closedState {
		return nil, ErrNodeStopped
	}
	return n.inprocHandler, nil
}

// Config returns the configuration of node.
// 获取节点配置
func (n *Node) Config() *Config {
	return n.config
}

// Server retrieves the currently running P2P network layer. This method is meant
// only to inspect fields of the currently running server. Callers should not
// start or stop the returned server.
func (n *Node) Server() *p2p.Server {
	n.lock.Lock()
	defer n.lock.Unlock()

	return n.server
}

// DataDir retrieves the current datadir used by the protocol stack.
// Deprecated: No files should be stored in this directory, use InstanceDir instead.
func (n *Node) DataDir() string {
	return n.config.DataDir
}

// InstanceDir retrieves the instance directory used by the protocol stack.
func (n *Node) InstanceDir() string {
	return n.config.instanceDir()
}

// KeyStoreDir retrieves the key directory
func (n *Node) KeyStoreDir() string {
	return n.keyDir
}

// AccountManager retrieves the account manager used by the protocol stack.
func (n *Node) AccountManager() *accounts.Manager {
	return n.accman
}

// IPCEndpoint retrieves the current IPC endpoint used by the protocol stack.
func (n *Node) IPCEndpoint() string {
	return n.ipc.endpoint
}

// HTTPEndpoint returns the URL of the HTTP server. Note that this URL does not
// contain the JSON-RPC path prefix set by HTTPPathPrefix.
// 获取http服务的地址
func (n *Node) HTTPEndpoint() string {
	return "http://" + n.http.listenAddr()
}

// WSEndpoint returns the current JSON-RPC over WebSocket endpoint.
func (n *Node) WSEndpoint() string {
	if n.http.wsAllowed() {
		return "ws://" + n.http.listenAddr() + n.http.wsConfig.prefix
	}
	return "ws://" + n.ws.listenAddr() + n.ws.wsConfig.prefix
}

// EventMux retrieves the event multiplexer used by all the network services in
// the current protocol stack.
func (n *Node) EventMux() *event.TypeMux {
	return n.eventmux
}

// OpenDatabase opens an existing database with the given name (or creates one if no
// previous can be found) from within the node's instance directory. If the node is
// ephemeral, a memory database is returned.
func (n *Node) OpenDatabase(name string, cache, handles int, namespace string, readonly bool) (ethdb.Database, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.state == closedState {
		return nil, ErrNodeStopped
	}

	var db ethdb.Database
	var err error
	if n.config.DataDir == "" {
		db = rawdb.NewMemoryDatabase()
	} else {
		db, err = rawdb.NewLevelDBDatabase(n.ResolvePath(name), cache, handles, namespace, readonly)
	}

	if err == nil {
		db = n.wrapDatabase(db)
	}
	return db, err
}

// OpenDatabaseWithFreezer opens an existing database with the given name (or
// creates one if no previous can be found) from within the node's data directory,
// also attaching a chain freezer to it that moves ancient chain data from the
// database to immutable append-only files. If the node is an ephemeral one, a
// memory database is returned.
func (n *Node) OpenDatabaseWithFreezer(name string, cache, handles int, freezer, namespace string, readonly bool) (ethdb.Database, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.state == closedState {
		return nil, ErrNodeStopped
	}

	var db ethdb.Database
	var err error
	if n.config.DataDir == "" {
		db = rawdb.NewMemoryDatabase()
	} else {
		root := n.ResolvePath(name)
		switch {
		case freezer == "":
			freezer = filepath.Join(root, "ancient")
		case !filepath.IsAbs(freezer):
			freezer = n.ResolvePath(freezer)
		}
		db, err = rawdb.NewLevelDBDatabaseWithFreezer(root, cache, handles, freezer, namespace, readonly)
	}

	if err == nil {
		db = n.wrapDatabase(db)
	}
	return db, err
}

// ResolvePath returns the absolute path of a resource in the instance directory.
func (n *Node) ResolvePath(x string) string {
	return n.config.ResolvePath(x)
}

// closeTrackingDB wraps the Close method of a database. When the database is closed by the
// service, the wrapper removes it from the node's database map. This ensures that Node
// won't auto-close the database if it is closed by the service that opened it.
// 针对ethdb.Database的Close方法进行了封装
// Close会额外从Node.databases中删除对应的项
type closeTrackingDB struct {
	ethdb.Database
	n *Node
}

func (db *closeTrackingDB) Close() error {
	db.n.lock.Lock()
	delete(db.n.databases, db)
	db.n.lock.Unlock()
	return db.Database.Close()
}

// wrapDatabase ensures the database will be auto-closed when Node is closed.
// 将数据库对象封装成closeTrackingDB,然后加入到databases字段中
func (n *Node) wrapDatabase(db ethdb.Database) ethdb.Database {
	wrapper := &closeTrackingDB{db, n}
	n.databases[wrapper] = struct{}{}
	return wrapper
}

// closeDatabases closes all open databases.
// 关闭所有数据库
func (n *Node) closeDatabases() (errors []error) {
	for db := range n.databases {
		delete(n.databases, db)
		if err := db.Database.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	return errors
}
