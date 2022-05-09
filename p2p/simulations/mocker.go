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

// Package simulations simulates p2p networks.
// A mocker simulates starting and stopping real nodes in a network.
package simulations

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/Evolution404/simcore/log"
	"github.com/Evolution404/simcore/p2p/enode"
	"github.com/Evolution404/simcore/p2p/simulations/adapters"
)

//a map of mocker names to its function
// 保存了所有mocker的名称和它的函数的映射
var mockerList = map[string]func(net *Network, quit chan struct{}, nodeCount int){
	"startStop":     startStop,
	"probabilistic": probabilistic,
	"boot":          boot,
}

//Lookup a mocker by its name, returns the mockerFn
// 通过mocker的名称查询它的函数
func LookupMocker(mockerType string) func(net *Network, quit chan struct{}, nodeCount int) {
	return mockerList[mockerType]
}

//Get a list of mockers (keys of the map)
//Useful for frontend to build available mocker selection
// 获取现有的mocker的名称的列表
func GetMockerList() []string {
	list := make([]string, 0, len(mockerList))
	for k := range mockerList {
		list = append(list, k)
	}
	return list
}

//The boot mockerFn only connects the node in a ring and doesn't do anything else
// 这个模式直接启动指定个数的节点建立一个环状网络
func boot(net *Network, quit chan struct{}, nodeCount int) {
	_, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		panic("Could not startup node network for mocker")
	}
}

//The startStop mockerFn stops and starts nodes in a defined period (ticker)
// 这个模式启动指定个数的节点建立环状网络,然后每十秒随机停止一个节点三秒后让这个节点重新运行
func startStop(net *Network, quit chan struct{}, nodeCount int) {
	nodes, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		panic("Could not startup node network for mocker")
	}
	// 接下来的循环每十秒执行一次
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-quit:
			log.Info("Terminating simulation loop")
			return
		case <-tick.C:
			// 随机找到一个节点,让他停止运行
			id := nodes[rand.Intn(len(nodes))]
			log.Info("stopping node", "id", id)
			if err := net.Stop(id); err != nil {
				log.Error("error stopping node", "id", id, "err", err)
				return
			}

			// 然后等待三秒重新启动这个节点
			select {
			case <-quit:
				log.Info("Terminating simulation loop")
				return
			case <-time.After(3 * time.Second):
			}

			log.Debug("starting node", "id", id)
			if err := net.Start(id); err != nil {
				log.Error("error starting node", "id", id, "err", err)
				return
			}
		}
	}
}

//The probabilistic mocker func has a more probabilistic pattern
//(the implementation could probably be improved):
//nodes are connected in a ring, then a varying number of random nodes is selected,
//mocker then stops and starts them in random intervals, and continues the loop
func probabilistic(net *Network, quit chan struct{}, nodeCount int) {
	// 创建环状网络
	nodes, err := connectNodesInRing(net, nodeCount)
	if err != nil {
		select {
		case <-quit:
			//error may be due to abortion of mocking; so the quit channel is closed
			return
		default:
			panic("Could not startup node network for mocker")
		}
	}
	for {
		select {
		case <-quit:
			log.Info("Terminating simulation loop")
			return
		default:
		}
		var lowid, highid int
		var wg sync.WaitGroup
		// 随机等待一段时间 [1-6)秒
		randWait := time.Duration(rand.Intn(5000)+1000) * time.Millisecond
		rand1 := rand.Intn(nodeCount - 1)
		rand2 := rand.Intn(nodeCount - 1)
		if rand1 <= rand2 {
			lowid = rand1
			highid = rand2
		} else if rand1 > rand2 {
			highid = rand1
			lowid = rand2
		}
		var steps = highid - lowid
		wg.Add(steps)
		for i := lowid; i < highid; i++ {
			select {
			case <-quit:
				log.Info("Terminating simulation loop")
				return
			case <-time.After(randWait):
			}
			log.Debug(fmt.Sprintf("node %v shutting down", nodes[i]))
			err := net.Stop(nodes[i])
			if err != nil {
				log.Error("Error stopping node", "node", nodes[i])
				wg.Done()
				continue
			}
			go func(id enode.ID) {
				time.Sleep(randWait)
				err := net.Start(id)
				if err != nil {
					log.Error("Error starting node", "node", id)
				}
				wg.Done()
			}(nodes[i])
		}
		wg.Wait()
	}

}

//connect nodeCount number of nodes in a ring
// 创建nodeCount个节点,并让这些节点组成一个环状的网络
func connectNodesInRing(net *Network, nodeCount int) ([]enode.ID, error) {
	// 首先在仿真网络中随机创建nodeCount个节点
	ids := make([]enode.ID, nodeCount)
	for i := 0; i < nodeCount; i++ {
		conf := adapters.RandomNodeConfig()
		node, err := net.NewNodeWithConfig(conf)
		if err != nil {
			log.Error("Error creating a node!", "err", err)
			return nil, err
		}
		ids[i] = node.ID()
	}

	// 然后启动新创建的这些节点
	for _, id := range ids {
		if err := net.Start(id); err != nil {
			log.Error("Error starting a node!", "err", err)
			return nil, err
		}
		log.Debug(fmt.Sprintf("node %v starting up", id))
	}
	// 将这些节点依次建立连接,组成一个环
	for i, id := range ids {
		peerID := ids[(i+1)%len(ids)]
		if err := net.Connect(id, peerID); err != nil {
			log.Error("Error connecting a node to a peer!", "err", err)
			return nil, err
		}
	}

	return ids, nil
}
