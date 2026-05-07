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
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

var (
	gMutex      sync.Mutex
	gProxyURLV4 string
	gProxyURLV6 string
	gListenerV4 net.Listener
	gListenerV6 net.Listener
)

func StartHTTPProxy(flags ...bool) string {
	var proxyURL *string
	var network string

	onlyIPv4 := true

	for _, item := range flags {
		if item {
			onlyIPv4 = false
			break
		}
	}

	if onlyIPv4 {
		proxyURL = &gProxyURLV4
		network = "tcp4"
	} else {
		proxyURL = &gProxyURLV6
		network = "tcp6"
	}

	gMutex.Lock()
	defer gMutex.Unlock()

	if "" == *proxyURL {
		if l, err := net.ListenTCP("tcp4", &net.TCPAddr{
			IP: net.IPv4(127, 0, 0, 1),
		}); nil == err {
			if addr, ok := l.Addr().(*net.TCPAddr); ok {
				go handleLoop(l, network)
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

func StopHTTPProxy() {
	gMutex.Lock()
	defer gMutex.Unlock()

	if nil != gListenerV4 {
		gListenerV4.Close()
		gListenerV4 = nil
	}

	if nil != gListenerV6 {
		gListenerV6.Close()
		gListenerV6 = nil
	}

	gProxyURLV4 = ""
	gProxyURLV6 = ""
}

func handleLoop(l net.Listener, network string) {
	var m sync.Map

	for {
		if conn, err := l.Accept(); nil == err {
			m.Store(conn.RemoteAddr().String(), conn)
			go handleClient(&m, network, conn)
		} else {
			log.Warnf("[HTTP Proxy(%s)] tcp accept failed: %v", network, err)
			break
		}
	}

	gMutex.Lock()

	if "tcp4" == network {
		gProxyURLV4 = ""
		gListenerV4 = nil
	} else {
		gProxyURLV6 = ""
		gListenerV6 = nil
	}

	gMutex.Unlock()

	m.Range(func(_, v any) bool {
		if c, ok := v.(net.Conn); ok {
			c.Close()
		}
		return true
	})

	l.Close()
}

func handleClient(m *sync.Map, network string, c net.Conn) {
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
