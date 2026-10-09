// Copyright 2021 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sub

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

type ServerInfo struct {
	Address  string `json:"address"`
	OnlyIPv4 bool   `json:"only_ipv4"`
	OnlyIPv6 bool   `json:"only_ipv6"`
	TTL      int    `json:"ttl"`
}

type NetProxy struct {
	mutex       sync.RWMutex
	proxyURLV4  string
	proxyURLV6  string
	listenerV4  net.Listener
	listenerV6  net.Listener
	guideOnce   sync.Once
	guideAddr   string
	guideNet    string
	guideCancel context.CancelFunc
	maxCompat   bool
	fetchFlags  uint32
}

func NewNetProxy() *NetProxy {
	return &NetProxy{}
}

func (np *NetProxy) SetGuideURL(guideURL string) bool {
	if _, err := url.Parse(guideURL); nil != err {
		log.Warnf("[HTTP Proxy] invalid guide URL: %v", err)
		return false
	}

	np.guideOnce.Do(func() {
		var ctx context.Context
		ctx, np.guideCancel = context.WithCancel(context.Background())

		atomic.StoreUint32(&np.fetchFlags, 0x2)

		go func() {
			interval := np.fetchServers(guideURL)
			timer := time.NewTimer(interval)
			defer timer.Stop()

			for {
				select {
				case <-timer.C:
					interval = np.fetchServers(guideURL)
					timer.Reset(interval)
				case <-ctx.Done():
					return
				}
			}
		}()
	})

	return true
}

func (np *NetProxy) StopGuide() {
	if nil != np.guideCancel {
		np.guideCancel()
	}
	np.mutex.Lock()
	np.guideAddr, np.guideNet = "", ""
	np.mutex.Unlock()
}

func (np *NetProxy) SetMaxCompatible(maxCompatible bool) {
	np.mutex.Lock()
	defer np.mutex.Unlock()
	np.maxCompat = maxCompatible
}

func (np *NetProxy) StartHTTPProxy(flags ...bool) string {
	var proxyURL *string
	var proxyLs *net.Listener
	var network string

	onlyIPv4 := true

	for _, item := range flags {
		if item {
			onlyIPv4 = false
			break
		}
	}

	if onlyIPv4 {
		proxyURL = &np.proxyURLV4
		proxyLs = &np.listenerV4
		network = "tcp4"
	} else {
		proxyURL = &np.proxyURLV6
		proxyLs = &np.listenerV6
		network = "tcp6"
	}

	np.mutex.Lock()
	defer np.mutex.Unlock()

	if "" == *proxyURL {
		if l, err := net.ListenTCP("tcp4", &net.TCPAddr{
			IP: net.IPv4(127, 0, 0, 1),
		}); nil == err {
			if addr, ok := l.Addr().(*net.TCPAddr); ok {
				*proxyLs = l
				go np.handleLoop(l, network)
				*proxyURL = fmt.Sprintf("http://127.0.0.1:%d/", addr.Port)
			} else {
				l.Close()
				log.Warnf("[HTTP Proxy(%s)] get listener addr failed: not *net.TCPAddr", network)
			}
		} else {
			log.Warnf("[HTTP Proxy(%s)] tcp listen failed: %v", network, err)
		}
	}

	return *proxyURL
}

func (np *NetProxy) StopHTTPProxy() {
	np.mutex.Lock()
	defer np.mutex.Unlock()

	if nil != np.listenerV4 {
		np.listenerV4.Close()
		np.listenerV4 = nil
	}

	if nil != np.listenerV6 {
		np.listenerV6.Close()
		np.listenerV6 = nil
	}

	np.proxyURLV4 = ""
	np.proxyURLV6 = ""
}

func (np *NetProxy) fetchServers(guideURL string) time.Duration {
	if !atomic.CompareAndSwapUint32(&np.fetchFlags, 0x0, 0x1) &&
		!atomic.CompareAndSwapUint32(&np.fetchFlags, 0x2, 0x1) {
		return 10 * time.Second
	}

	defer atomic.StoreUint32(&np.fetchFlags, 0x0)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(guideURL)
	if nil != err {
		log.Warnf("[HTTP Proxy] fetch guide URL failed: %v", err)
		return 10 * time.Second
	}
	defer resp.Body.Close()

	var servers map[string]ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&servers); nil != err {
		log.Warnf("[HTTP Proxy] parse guide JSON failed: %v", err)
		return 10 * time.Second
	}

	available := make([]ServerInfo, 0, len(servers))
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	for name, info := range servers {
		if conn, err := dialer.Dial("tcp", info.Address); nil == err {
			conn.Close()
			available = append(available, info)
		} else {
			log.Warnf("[HTTP Proxy] server %s (%s) unreachable: %v", name, info.Address, err)
		}
	}

	if 0 == len(available) {
		log.Warnf("[HTTP Proxy] no available servers from guide")
		return 10 * time.Second
	}

	addr := available[rand.Intn(len(available))]
	np.mutex.Lock()
	np.guideAddr = addr.Address
	switch {
	default:
		if addr.OnlyIPv4 != addr.OnlyIPv6 {
			if addr.OnlyIPv4 {
				np.guideNet = "tcp4"
			} else {
				np.guideNet = "tcp6"
			}
			break
		}
		np.guideNet = "tcp"
	}
	np.mutex.Unlock()

	if 10 <= addr.TTL {
		return time.Duration(addr.TTL) * time.Second
	}
	return 10 * time.Second
}

func (np *NetProxy) getGuideAddr() (string, string) {
	np.mutex.RLock()
	defer np.mutex.RUnlock()
	return np.guideAddr, np.guideNet
}

func (np *NetProxy) handleLoop(l net.Listener, network string) {
	var m sync.Map

	for {
		if conn, err := l.Accept(); nil == err {
			if 0x0 != atomic.LoadUint32(&np.fetchFlags) {
				log.Warnf(
					"[HTTP Proxy(%s)] guide server is being fetched, reject new connection from %s",
					network,
					conn.RemoteAddr().String(),
				)
				conn.Close()
				continue
			}
			m.Store(conn.RemoteAddr().String(), conn)
			go np.handleClient(&m, network, conn)
		} else {
			log.Warnf("[HTTP Proxy(%s)] tcp accept failed: %v", network, err)
			break
		}
	}

	np.mutex.Lock()

	if "tcp4" == network {
		np.proxyURLV4 = ""
		np.listenerV4 = nil
	} else {
		np.proxyURLV6 = ""
		np.listenerV6 = nil
	}

	np.mutex.Unlock()

	m.Range(func(_, v any) bool {
		if c, ok := v.(net.Conn); ok {
			c.Close()
		}
		return true
	})

	l.Close()
}

func (np *NetProxy) handleClient(m *sync.Map, network string, c net.Conn) {
	token := c.RemoteAddr().String()

	defer func() {
		m.Delete(token)
		c.Close()
	}()

	method, target, err := parseHead(bufio.NewReader(c))
	if nil != err {
		log.Warnf("[HTTP Proxy(%s)] parse header failed: %v", network, err)
		return
	}

	if "CONNECT" != method {
		log.Warnf("[HTTP Proxy(%s)] invalid http method: %s", network, method)
		return
	}

	if guideAddr, guideNet := np.getGuideAddr(); guideAddr != "" {
		target = guideAddr
		if "tcp" != guideNet {
			network = guideNet
		} else {
			np.mutex.RLock()
			if np.maxCompat {
				network = "tcp"
			}
			np.mutex.RUnlock()
		}
		log.Infof("[HTTP Proxy(%s)] redirect to guide server: %s", network, target)
	}

	addr, err := net.ResolveTCPAddr(network, target)
	if nil != err {
		log.Warnf("[HTTP Proxy(%s)] resolve address failed: %v", network, err)
		return
	}

	dialer := net.Dialer{
		Timeout: 30 * time.Second,
	}

	if conn, err := dialer.Dial(network, addr.String()); nil == err {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		ioCopy(conn, c)
	} else {
		log.Warnf("[HTTP Proxy(%s)] dial failed: %v", network, err)
	}
}

func ioCopy(conn1, conn2 net.Conn) {
	exit := make(chan struct{})

	go func(conn1, conn2 net.Conn, exit chan struct{}) {
		buffer := make([]byte, 32*1024)
		io.CopyBuffer(conn2, conn1, buffer)
		conn2.Close()
		close(exit)
	}(conn1, conn2, exit)

	buffer := make([]byte, 32*1024)
	io.CopyBuffer(conn1, conn2, buffer)
	conn1.Close()

	<-exit
}

func parseHead(b *bufio.Reader) (string, string, error) {
	if line, _, err := b.ReadLine(); nil == err {
		if ss := strings.Split(string(line), " "); 3 <= len(ss) {
			for {
				if line, _, err := b.ReadLine(); nil == err {
					if 0 == len(line) {
						break
					}
				} else {
					return "", "", err
				}
			}
			return ss[0], ss[1], nil
		} else {
			return "", "", fmt.Errorf("invalid http header: %s", line)
		}
	} else {
		return "", "", err
	}
}
