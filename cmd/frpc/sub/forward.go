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
	"crypto/md5"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
	"gopkg.in/ini.v1"
)

var (
	gFlagExit    uint32
	gForwardList []*udpWarp

	gUDPPacketSize   = 64 * 1024
	gConnReadTimeout = 5 * time.Minute
	gLogLevel        = "info"
)

type xorKeyBuffer struct {
	data []byte

	length int
}

func (x *xorKeyBuffer) SetKey(key string) {
	if "" != key {
		data := md5.Sum([]byte(key))
		x.length = len(data)
		x.data = make([]byte, x.length)
		copy(x.data, data[:x.length])
	}
}

func (x *xorKeyBuffer) Translate(data []byte, n int) []byte {
	if 0 < x.length {
		for i := 0; n > i; i++ {
			data[i] ^= x.data[i%x.length]
		}
	}
	return data[:n]
}

type udpWarp struct {
	sync.Mutex

	*net.UDPConn

	*sync.WaitGroup

	flags uint32

	remote *net.UDPAddr

	key xorKeyBuffer

	clients map[string]net.Conn

	udpsize int

	timeout time.Duration
}

func (u *udpWarp) SetKey(key string) {
	u.key.SetKey(key)
}

func (u *udpWarp) Loop() {
	defer u.Close()
	buffer := make([]byte, u.udpsize)
	for {
		if n, local, err := u.UDPConn.ReadFromUDP(buffer); nil == err {
			u.forward(local, buffer, n)
		} else {
			log.Errorf("read from udp error: %v", err)
			break
		}
	}
}

func (u *udpWarp) Close() error {
	if atomic.CompareAndSwapUint32(&u.flags, 0x0, 0x1) {
		u.WaitGroup.Done()
		u.Lock()
		for token, conn := range u.clients {
			conn.Close()
			delete(u.clients, token)
		}
		u.Unlock()
		return u.UDPConn.Close()
	}
	return nil
}

func (u *udpWarp) forward(local *net.UDPAddr, data []byte, n int) {
	var conn net.Conn
	var ok bool
	token := local.String()
	u.Lock()
	conn, ok = u.clients[token]
	if !ok {
		if c, err := net.DialUDP("udp", nil, u.remote); nil == err {
			u.clients[token] = c
			u.WaitGroup.Add(1)
			go u.recv(c, local)
			conn = c
		} else {
			u.Unlock()
			log.Warnf("dial udp error: %v", err)
			return
		}
	}
	u.Unlock()
	if !ok {
		log.Infof("new udp client [%s] for target [%s]", token, u.remote.String())
	}
	if _, err := conn.Write(u.key.Translate(data, n)); nil != err {
		u.Lock()
		delete(u.clients, token)
		u.Unlock()
		conn.Close()
		log.Warnf("write to udp error: %v", err)
	}
}

func (u *udpWarp) recv(conn net.Conn, local *net.UDPAddr) {
	defer func() {
		u.Lock()
		delete(u.clients, local.String())
		u.Unlock()
		conn.Close()
		u.WaitGroup.Done()
	}()
	buffer := make([]byte, u.udpsize)
	for {
		conn.SetReadDeadline(time.Now().Add(u.timeout))
		if n, err := conn.Read(buffer); nil == err {
			if _, err = u.UDPConn.WriteTo(u.key.Translate(buffer, n), local); nil != err {
				log.Warnf("write to udp error: %v", err)
				return
			}
		} else {
			log.Warnf("read from udp error: %v", err)
			return
		}
	}
}

func ForwardInit(wg *sync.WaitGroup, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	f, err := ini.Load(b)
	if err != nil {
		return err
	}

	if f.HasSection("common") {
		s := f.Section("common")
		gUDPPacketSize = s.Key("udp_packet_size").MustInt(gUDPPacketSize)
		gConnReadTimeout = s.Key("conn_read_timeout").MustDuration(gConnReadTimeout)
		gLogLevel = s.Key("log_level").MustString(gLogLevel)
	}

	log.InitLogger("console", gLogLevel, 0, true)

	for _, s := range f.Sections() {
		switch s.Name() {
		case "common":
		default:
			if s.HasKey("target") {
				if addr, err := net.ResolveUDPAddr(
					"udp",
					s.Key("target").String(),
				); nil == err {
					if err = forwardService(
						wg,
						s.Key("key").String(),
						addr,
						s.Key("port").MustInt(addr.Port),
					); nil != err {
						return err
					}
				} else {
					return err
				}
			}
		}
	}

	return nil
}

func ForwardExit(wg *sync.WaitGroup, flags ...bool) {
	if atomic.CompareAndSwapUint32(&gFlagExit, 0x0, 0x1) {
		breakExit := false
		if len(flags) > 0 {
			breakExit = flags[0]
		}
		if breakExit {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
			log.Infof("frpc forward service is running, press Ctrl+C to exit")
			<-ch
		} else {
			log.Infof("frpc forward service is exiting")
		}
		for _, c := range gForwardList {
			if err := c.Close(); nil != err {
				log.Errorf("error closing forward service: %v", err)
			}
		}
		gForwardList = gForwardList[:0]
		log.Infof("frpc forward service waiting for all connections to close")
		wg.Wait()
	}
}

func forwardService(wg *sync.WaitGroup, key string, remote *net.UDPAddr, port int) error {
	if 0 >= port || 65535 < port {
		port = remote.Port
	}
	if conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: port,
	}); nil == err {
		log.Infof("start frpc forward service for target [%s] on port [%d]", remote.String(), port)
		wg.Add(1)
		c := &udpWarp{
			UDPConn:   conn,
			WaitGroup: wg,
			remote:    remote,
			clients:   make(map[string]net.Conn),
			udpsize:   gUDPPacketSize,
			timeout:   gConnReadTimeout,
		}
		c.SetKey(key)
		go c.Loop()
		gForwardList = append(gForwardList, c)
	} else {
		return err
	}
	return nil
}
