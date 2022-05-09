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

package node

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/rpc"
	"github.com/rs/cors"
)

// httpConfig is the JSON-RPC/HTTP configuration.
// 使用http协议的RPC的控制选项
type httpConfig struct {
	// 需要注册的服务名称
	Modules []string
	// 允许跨域来自哪些域名 http://xxx.xxx
	CorsAllowedOrigins []string
	// 抵抗dns重绑定攻击 允许哪些http的Host字段的域名 xxx.xx
	Vhosts []string
	// 以这个前缀的请求还被发送到这里处理
	prefix string // path prefix on which to mount http handler
}

// wsConfig is the JSON-RPC/Websocket configuration
// 使用websocket协议的RPC的控制选项
type wsConfig struct {
	Origins []string
	Modules []string
	prefix  string // path prefix on which to mount ws handler
}

// rpc的处理器,可以是http类型也可能是websocket类型
// rpc.Server保存注册的服务
// http.Handler封装了rpc.Server里的ServeHTTP方法,增加了一些额外功能
type rpcHandler struct {
	// http类型通过NewHTTPHandlerStack创建
	// websocket类型是server.WebsocketHandler
	http.Handler
	server *rpc.Server
}

// 这里有两种类型的rpc服务端,分别是httpServer,ipcServer
// httpServer使用http协议提供服务
// ipcServer使用unix进程通信提供服务

// httpServer对象用来处理http和websocket类型的RPC请求
// 使用的过程
// h:=newHTTPServer(log,timeouts)
// h.setListenAddr(host,port)
// h.enableRPC(apis,config)
// h.enableWS(apis,config)
// h.start()
// h.stop()
type httpServer struct {
	log      log.Logger
	timeouts rpc.HTTPTimeouts
	mux      http.ServeMux // registered handlers go here

	mu sync.Mutex
	// 最终向外暴露的http服务
	server *http.Server
	// 当服务器正在运行的时候是一个非nil的值
	listener net.Listener // non-nil when server is running

	// HTTP RPC handler things.

	// 以下两个字段在enableRPC中设置
	// http使用的配置信息,比如所有http请求都必须有哪个前缀
	httpConfig  httpConfig
	httpHandler atomic.Value // *rpcHandler

	// WebSocket handler things.
	// 以下两个字段在enableWS中设置
	// websocket使用的配置信息,比如所有websocket请求都必须有哪个前缀
	wsConfig  wsConfig
	wsHandler atomic.Value // *rpcHandler

	// These are set by setListenAddr.
	// 以下三个值在setListenAddr中设置
	// endpoint的格式是 host:port
	endpoint string
	host     string
	port     int

	// 保存了path->name映射
	// path是请求的路由,name是handler的名字
	handlerNames map[string]string
}

func newHTTPServer(log log.Logger, timeouts rpc.HTTPTimeouts) *httpServer {
	h := &httpServer{log: log, timeouts: timeouts, handlerNames: make(map[string]string)}

	h.httpHandler.Store((*rpcHandler)(nil))
	h.wsHandler.Store((*rpcHandler)(nil))
	return h
}

// setListenAddr configures the listening address of the server.
// The address can only be set while the server isn't running.
// 设置服务器监听的host和port,只能在服务器还没启动的时候调用
// 该函数修改endpoint,host,port三个字段
func (h *httpServer) setListenAddr(host string, port int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 服务器已经启动了,而且输入的值相对于运行中的值进行了修改,需要报错
	if h.listener != nil && (host != h.host || port != h.port) {
		return fmt.Errorf("HTTP server already running on %s", h.endpoint)
	}

	// 修改三个值
	h.host, h.port = host, port
	h.endpoint = fmt.Sprintf("%s:%d", host, port)
	return nil
}

// listenAddr returns the listening address of the server.
// 返回服务器的监听地址
func (h *httpServer) listenAddr() string {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 服务器正在运行时使用listener的地址
	if h.listener != nil {
		return h.listener.Addr().String()
	}
	// 不在运行的时候使用endpoint
	return h.endpoint
}

// start starts the HTTP server if it is enabled and not already running.
// 启动监听http请求,如果已经启动过了就跳过
func (h *httpServer) start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 还没设置监听的地址,或者已经启动过了直接返回
	if h.endpoint == "" || h.listener != nil {
		return nil // already running or not configured
	}

	// Initialize the server.
	// 生成一个http.Server对象,请求Handler就是h
	// 也就是h.ServeHTTP()处理h.server接收到的请求
	h.server = &http.Server{Handler: h}
	// 如果httpServer对象设置了超时时间,也对htpp.Server对象设置超时时间
	if h.timeouts != (rpc.HTTPTimeouts{}) {
		// 如果有不合理的超时时间进行修正
		// 就是超时时间不能小于一秒
		CheckTimeouts(&h.timeouts)
		h.server.ReadTimeout = h.timeouts.ReadTimeout
		h.server.WriteTimeout = h.timeouts.WriteTimeout
		h.server.IdleTimeout = h.timeouts.IdleTimeout
	}

	// Start the server.
	// 启动监听tcp端口
	listener, err := net.Listen("tcp", h.endpoint)
	if err != nil {
		// If the server fails to start, we need to clear out the RPC and WS
		// configuration so they can be configured another time.
		h.disableRPC()
		h.disableWS()
		return err
	}
	h.listener = listener
	// 处理http请求
	go h.server.Serve(listener)

	// 启用了websocket,打印出来websocket监听地址
	if h.wsAllowed() {
		url := fmt.Sprintf("ws://%v", listener.Addr())
		if h.wsConfig.prefix != "" {
			url += h.wsConfig.prefix
		}
		h.log.Info("WebSocket enabled", "url", url)
	}
	// if server is websocket only, return after logging
	// 只启用了websocket可以返回了
	if !h.rpcAllowed() {
		return nil
	}
	// Log http endpoint.
	h.log.Info("HTTP server started",
		"endpoint", listener.Addr(),
		"prefix", h.httpConfig.prefix,
		"cors", strings.Join(h.httpConfig.CorsAllowedOrigins, ","),
		"vhosts", strings.Join(h.httpConfig.Vhosts, ","),
	)

	// Log all handlers mounted on server.
	// 打印所有服务的名称以及访问的路径
	var paths []string
	for path := range h.handlerNames {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	logged := make(map[string]bool, len(paths))
	for _, path := range paths {
		name := h.handlerNames[path]
		if !logged[name] {
			log.Info(name+" enabled", "url", "http://"+listener.Addr().String()+path)
			logged[name] = true
		}
	}
	return nil
}

// 处理h.server启动后接收到的http请求
// 1. 判断是不是websocket,如果是使用wsHandler处理请求
// 2. 判断是不是使用RegisterHandler在node.mux中注册了路由,如果是使用注册的函数处理请求
// 3. 最后尝试使用httpHandler来处理请求
func (h *httpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check if ws request and serve if ws enabled
	// 如果这是一个websocket请求而且wsHandler不是nil
	// 使用wsHandler来处理这个请求
	ws := h.wsHandler.Load().(*rpcHandler)
	if ws != nil && isWebsocket(r) {
		// 是不是使用了这个wsHandler的前缀
		if checkPath(r, h.wsConfig.prefix) {
			ws.ServeHTTP(w, r)
		}
		return
	}
	// if http-rpc is enabled, try to serve request
	rpc := h.httpHandler.Load().(*rpcHandler)
	if rpc != nil {
		// First try to route in the mux.
		// Requests to a path below root are handled by the mux,
		// which has all the handlers registered via Node.RegisterHandler.
		// These are made available when RPC is enabled.
		// 首先使用mux进行路由
		muxHandler, pattern := h.mux.Handler(r)
		if pattern != "" {
			muxHandler.ServeHTTP(w, r)
			return
		}

		if checkPath(r, h.httpConfig.prefix) {
			rpc.ServeHTTP(w, r)
			return
		}
	}
	// 没有websocket也没有http,所以返回404
	w.WriteHeader(http.StatusNotFound)
}

// checkPath checks whether a given request URL matches a given path prefix.
// 判断请求r的路径是不是以path为前缀
// 如果path是空字符串,要求请求r必须是请求根路径
func checkPath(r *http.Request, path string) bool {
	// if no prefix has been specified, request URL must be on root
	// 空字符串必须是根路径
	if path == "" {
		return r.URL.Path == "/"
	}
	// otherwise, check to make sure prefix matches
	// 判断请求路径是不是以path为前缀
	return len(r.URL.Path) >= len(path) && r.URL.Path[:len(path)] == path
}

// validatePrefix checks if 'path' is a valid configuration value for the RPC prefix option.
func validatePrefix(what, path string) error {
	if path == "" {
		return nil
	}
	if path[0] != '/' {
		return fmt.Errorf(`%s RPC path prefix %q does not contain leading "/"`, what, path)
	}
	if strings.ContainsAny(path, "?#") {
		// This is just to avoid confusion. While these would match correctly (i.e. they'd
		// match if URL-escaped into path), it's not easy to understand for users when
		// setting that on the command line.
		return fmt.Errorf("%s RPC path prefix %q contains URL meta-characters", what, path)
	}
	return nil
}

// stop shuts down the HTTP server.
func (h *httpServer) stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.doStop()
}

// 完全关闭所有服务
func (h *httpServer) doStop() {
	if h.listener == nil {
		return // not running
	}

	// Shut down the server.
	// 清空httpHandler,wsHandler并对rpc.Server都调用Stop
	httpHandler := h.httpHandler.Load().(*rpcHandler)
	wsHandler := h.wsHandler.Load().(*rpcHandler)
	if httpHandler != nil {
		h.httpHandler.Store((*rpcHandler)(nil))
		httpHandler.server.Stop()
	}
	if wsHandler != nil {
		h.wsHandler.Store((*rpcHandler)(nil))
		wsHandler.server.Stop()
	}
	// 停止监听请求
	h.server.Shutdown(context.Background())
	h.listener.Close()
	h.log.Info("HTTP server stopped", "endpoint", h.listener.Addr())

	// Clear out everything to allow re-configuring it later.
	h.host, h.port, h.endpoint = "", 0, ""
	h.server, h.listener = nil, nil
}

// enableRPC turns on JSON-RPC over HTTP on the server.
// 启用http请求
// 设置h.httpConfig和h.httpHandler
func (h *httpServer) enableRPC(apis []rpc.API, config httpConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.rpcAllowed() {
		return fmt.Errorf("JSON-RPC over HTTP is already enabled")
	}

	// Create RPC server and handler.
	srv := rpc.NewServer()
	if err := RegisterApis(apis, config.Modules, srv, false); err != nil {
		return err
	}
	h.httpConfig = config
	h.httpHandler.Store(&rpcHandler{
		// 输入srv作为原始http.Handler,增加了跨域,抗dns重绑定,gzip三个功能
		Handler: NewHTTPHandlerStack(srv, config.CorsAllowedOrigins, config.Vhosts),
		server:  srv,
	})
	return nil
}

// disableRPC stops the HTTP RPC handler. This is internal, the caller must hold h.mu.
// 设置httpHandler为nil
func (h *httpServer) disableRPC() bool {
	handler := h.httpHandler.Load().(*rpcHandler)
	if handler != nil {
		h.httpHandler.Store((*rpcHandler)(nil))
		handler.server.Stop()
	}
	return handler != nil
}

// enableWS turns on JSON-RPC over WebSocket on the server.
// 启用websocket请求
// 设置wsConfig和wsHandler
func (h *httpServer) enableWS(apis []rpc.API, config wsConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.wsAllowed() {
		return fmt.Errorf("JSON-RPC over WebSocket is already enabled")
	}

	// Create RPC server and handler.
	srv := rpc.NewServer()
	if err := RegisterApis(apis, config.Modules, srv, false); err != nil {
		return err
	}
	h.wsConfig = config
	h.wsHandler.Store(&rpcHandler{
		Handler: srv.WebsocketHandler(config.Origins),
		server:  srv,
	})
	return nil
}

// stopWS disables JSON-RPC over WebSocket and also stops the server if it only serves WebSocket.
// 停止websocket
// 如果没有其他服务了就把rpc服务都停止
func (h *httpServer) stopWS() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.disableWS() {
		if !h.rpcAllowed() {
			h.doStop()
		}
	}
}

// disableWS disables the WebSocket handler. This is internal, the caller must hold h.mu.
// 清空wsHandler,并调用wsHandler.server.Stop()
func (h *httpServer) disableWS() bool {
	ws := h.wsHandler.Load().(*rpcHandler)
	if ws != nil {
		h.wsHandler.Store((*rpcHandler)(nil))
		ws.server.Stop()
	}
	return ws != nil
}

// rpcAllowed returns true when JSON-RPC over HTTP is enabled.
// http请求是否被启用,httpHandler不为nil
func (h *httpServer) rpcAllowed() bool {
	return h.httpHandler.Load().(*rpcHandler) != nil
}

// wsAllowed returns true when JSON-RPC over WebSocket is enabled.
// websocket请求是否被启动,wsHandler不为nil
func (h *httpServer) wsAllowed() bool {
	return h.wsHandler.Load().(*rpcHandler) != nil
}

// isWebsocket checks the header of an http request for a websocket upgrade request.
// 判断请求r是不是websocket请求
// websocket请求头中包括两个字段
// Connection: Upgrade  代表这次http请求需要进行升级
// Upgrade: websocket   http请求升级后可以支持哪些协议
func isWebsocket(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// NewHTTPHandlerStack returns wrapped http-related handlers
// 将输入http.Handler对象封装成支持cors,gzip并能抵抗dns重绑定攻击的http.Handler对象
// cors代表允许跨域的域名 http://xxx.xx 这种格式的列表,支持*通配符
// vhosts代表允许请求头Host字段的域名 xxx.xx 格式,没有http://这一段头,支持*通配符
func NewHTTPHandlerStack(srv http.Handler, cors []string, vhosts []string) http.Handler {
	// Wrap the CORS-handler within a host-handler
	handler := newCorsHandler(srv, cors)
	handler = newVHostHandler(vhosts, handler)
	return newGzipHandler(handler)
}

// 将http.Handler封装成支持跨域的请求,allowedOrigins代表允许的列表
func newCorsHandler(srv http.Handler, allowedOrigins []string) http.Handler {
	// disable CORS support if user has not specified a custom CORS configuration
	if len(allowedOrigins) == 0 {
		return srv
	}
	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{http.MethodPost, http.MethodGet},
		AllowedHeaders: []string{"*"},
		MaxAge:         600,
	})
	return c.Handler(srv)
}

// virtualHostHandler is a handler which validates the Host-header of incoming requests.
// Using virtual hosts can help prevent DNS rebinding attacks, where a 'random' domain name points to
// the service ip address (but without CORS headers). By verifying the targeted virtual host, we can
// ensure that it's a destination that the node operator has defined.
// 用于抵抗dns重绑定攻击,vhosts保存了http请求Host字段允许的域名
// 只有Host在vhosts列表中的域名才会被继续处理,vhosts中如果包括*(星号),表示所有域名都接收不抵抗dns重绑定
type virtualHostHandler struct {
	vhosts map[string]struct{}
	next   http.Handler
}

// 将输入的http.Handler封装成可以抵抗dns重绑定攻击的http.Handler
// 本质是校验http请求的Host字段是不是在输入的vhosts的列表中
func newVHostHandler(vhosts []string, next http.Handler) http.Handler {
	vhostMap := make(map[string]struct{})
	for _, allowedHost := range vhosts {
		vhostMap[strings.ToLower(allowedHost)] = struct{}{}
	}
	return &virtualHostHandler{vhostMap, next}
}

// ServeHTTP serves JSON-RPC requests over HTTP, implements http.Handler
// 校验来源的域名是不是在允许的列表中
func (h *virtualHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// if r.Host is not set, we can continue serving since a browser would set the Host header
	// 如果浏览器发送的请求Host不会为空,所以为空一定不是浏览器发送的请求
	// 不用担心dns重绑定攻击,直接继续处理
	if r.Host == "" {
		h.next.ServeHTTP(w, r)
		return
	}
	// 去掉端口号
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// Either invalid (too many colons) or no port specified
		host = r.Host
	}
	// 现在host可能是域名或者ip地址
	// 如果是ip地址直接处理,不用担心dns重绑定
	if ipAddr := net.ParseIP(host); ipAddr != nil {
		// It's an IP address, we can serve that
		h.next.ServeHTTP(w, r)
		return

	}
	// Not an IP address, but a hostname. Need to validate
	// 如果允许的域名保存了*,代表允许所有域名,直接处理
	if _, exist := h.vhosts["*"]; exist {
		h.next.ServeHTTP(w, r)
		return
	}
	// 如果域名在允许的列表,继续处理
	if _, exist := h.vhosts[host]; exist {
		h.next.ServeHTTP(w, r)
		return
	}
	http.Error(w, "invalid host specified", http.StatusForbidden)
}

var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(ioutil.Discard)
		return w
	},
}

// 实现http.ResponseWriter接口
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

// 由于io.Writer和http.ResponseWriter都实现了Write方法
// 所以这里重新实现Write方法,特别指明使用io.Writer中的Write方法
func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// 将一个http.Handler对象转换成支持gzip的http.Handler
func newGzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果客户端不支持gzip,那么就直接调用next.ServeHTTP
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// 到这里说明客户端支持gzip
		w.Header().Set("Content-Encoding", "gzip")

		gz := gzPool.Get().(*gzip.Writer)
		defer gzPool.Put(gz)

		// 将压缩后的结果写入到w中
		gz.Reset(w)
		defer gz.Close()

		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
	})
}

// 建立使用unix进程通信的链路
type ipcServer struct {
	log log.Logger
	// 这个endpoint应该是文件的路径
	endpoint string

	mu       sync.Mutex
	listener net.Listener
	srv      *rpc.Server
}

// 创建ipcServer对象
func newIPCServer(log log.Logger, endpoint string) *ipcServer {
	return &ipcServer{log: log, endpoint: endpoint}
}

// Start starts the httpServer's http.Server
// 启动ipc类型的RPC服务
// 本质是调用rpc.StartIPCEndpoint构造ipcServer.listener和ipcServer.src
func (is *ipcServer) start(apis []rpc.API) error {
	is.mu.Lock()
	defer is.mu.Unlock()

	if is.listener != nil {
		return nil // already running
	}
	listener, srv, err := rpc.StartIPCEndpoint(is.endpoint, apis)
	if err != nil {
		is.log.Warn("IPC opening failed", "url", is.endpoint, "error", err)
		return err
	}
	is.log.Info("IPC endpoint opened", "url", is.endpoint)
	is.listener, is.srv = listener, srv
	return nil
}

// 停止ipcServer,包括两步
// ipcServer.listener.Close()
// ipcServer.srv.Stop()
func (is *ipcServer) stop() error {
	is.mu.Lock()
	defer is.mu.Unlock()

	if is.listener == nil {
		return nil // not running
	}
	err := is.listener.Close()
	is.srv.Stop()
	is.listener, is.srv = nil, nil
	is.log.Info("IPC endpoint closed", "url", is.endpoint)
	return err
}

// RegisterApis checks the given modules' availability, generates an allowlist based on the allowed modules,
// and then registers all of the APIs exposed by the services.
// apis包括了所有支持的服务,modules是允许注册的服务
// 在srv上注册所有modules和apis都有的服务
// exposeAll用来控制是不是要直接注册所有apis中的服务
func RegisterApis(apis []rpc.API, modules []string, srv *rpc.Server, exposeAll bool) error {
	// 检查modules中是不是有apis里面不支持的
	if bad, available := checkModuleAvailability(modules, apis); len(bad) > 0 {
		log.Error("Unavailable modules in HTTP API list", "unavailable", bad, "available", available)
	}
	// Generate the allow list based on the allowed modules
	allowList := make(map[string]bool)
	for _, module := range modules {
		allowList[module] = true
	}
	// Register all the APIs exposed by the services
	// 接下来注册所有在modules里的服务
	for _, api := range apis {
		if exposeAll || allowList[api.Namespace] || (len(allowList) == 0 && api.Public) {
			if err := srv.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
		}
	}
	return nil
}
