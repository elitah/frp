// Copyright 2018 fatedier, fatedier@gmail.com
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
	"context"
	"crypto/md5"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/featuregate"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

var (
	xorToken         string
	xorListenPort    int
	xorAddress       string
	cfgFile          string
	cfgDir           string
	showVersion      bool
	strictConfigMode bool
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&xorToken, "xor_token", "x", "", "token for XOR encryption")
	rootCmd.PersistentFlags().IntVarP(&xorListenPort, "xor_listen_port", "p", 0, "listen port for XOR encryption")
	rootCmd.PersistentFlags().StringVarP(&xorAddress, "xor_address", "a", "", "address for XOR encryption")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "./frpc.ini", "config file of frpc")
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one frpc service for each file in config directory")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frpc")
	rootCmd.PersistentFlags().BoolVarP(&strictConfigMode, "strict_config", "", true, "strict config parsing mode, unknown fields will cause an errors")
}

var rootCmd = &cobra.Command{
	Use:   "frpc",
	Short: "frpc is the client of frp (https://github.com/fatedier/frp)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(version.Full())
			return nil
		}

		if "" != xorToken {
			if "" == xorAddress {
				fmt.Println("XOR token provided without XOR address, exiting!!!")
				return nil
			}
			remote, err := net.ResolveUDPAddr("udp", xorAddress)
			if nil != err {
				fmt.Printf("invalid XOR address provided: error: %v\n", err)
				return nil
			}
			if 0 >= xorListenPort || 65535 < xorListenPort {
				xorListenPort = remote.Port
			}
			if connLocal, err := net.ListenUDP("udp", &net.UDPAddr{
				Port: xorListenPort,
			}); nil == err {
				var clients sync.Map
				defer connLocal.Close()
				xorKey := md5.Sum([]byte(xorToken))
				xorLen := len(xorKey)
				xorData := func(data []byte, n int) []byte {
					for i := 0; n > i; i++ {
						data[i] ^= xorKey[i%xorLen]
					}
					return data[:n]
				}
				clientHandler := func(connRemote *net.UDPConn, addr *net.UDPAddr) {
					defer func() {
						clients.Delete(addr.String())
						connRemote.Close()
					}()
					buffer := make([]byte, 64*1024)
					for {
						connRemote.SetReadDeadline(time.Now().Add(5 * time.Minute))
						if n, err := connRemote.Read(buffer); nil == err {
							if _, err = connLocal.WriteTo(xorData(buffer, n), addr); nil != err {
								fmt.Printf("failed to write to UDP connection, error: %v\n", err)
								return
							}
						} else {
							fmt.Printf("failed to read from UDP connection, error: %v\n", err)
							return
						}
					}
				}
				clientWriter := func(addr *net.UDPAddr, data []byte, n int) {
					var conn *net.UDPConn
					if c, ok := clients.Load(addr.String()); ok {
						if _conn, ok := c.(*net.UDPConn); ok {
							conn = _conn
						} else {
							fmt.Printf("invalid connection type for %s\n", addr.String())
							return
						}
					} else {
						if _conn, err := net.DialUDP("udp", nil, remote); nil == err {
							fmt.Printf("new XOR connection from %s\n", addr.String())
							clients.Store(addr.String(), _conn)
							go clientHandler(_conn, addr)
							conn = _conn
						} else {
							fmt.Printf("failed to connect to XOR address, error: %v\n", err)
							return
						}
					}
					if _, err := conn.Write(xorData(data, n)); nil != err {
						fmt.Printf("failed to write to UDP connection, error: %v\n", err)
						clients.Delete(addr.String())
						conn.Close()
					}
				}
				buffer := make([]byte, 64*1024)
				fmt.Printf("XOR encryption enabled, listening on UDP port %d, forwarding to %s\n", xorListenPort, xorAddress)
				for {
					if n, addr, err := connLocal.ReadFromUDP(buffer); nil == err {
						clientWriter(addr, buffer, n)
					} else {
						fmt.Printf("failed to read from UDP connection, error: %v\n", err)
						return nil
					}
				}
			} else {
				fmt.Printf("failed to listen on UDP port %d, error: %v\n", xorListenPort, err)
				return nil
			}
		}

		// If cfgDir is not empty, run multiple frpc service for each config file in cfgDir.
		// Note that it's only designed for testing. It's not guaranteed to be stable.
		if cfgDir != "" {
			_ = runMultipleClients(cfgDir)
			return nil
		}

		// Do not show command usage here.
		err := runClient(cfgFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func runMultipleClients(cfgDir string) error {
	var wg sync.WaitGroup
	err := filepath.WalkDir(cfgDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		wg.Add(1)
		time.Sleep(time.Millisecond)
		go func() {
			defer wg.Done()
			err := runClient(path)
			if err != nil {
				fmt.Printf("frpc service error for config file [%s]\n", path)
			}
		}()
		return nil
	})
	wg.Wait()
	return err
}

func Execute() {
	rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleTermSignal(svr *client.Service) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	svr.GracefulClose(500 * time.Millisecond)
}

func runClient(cfgFilePath string) error {
	cfg, proxyCfgs, visitorCfgs, isLegacyFormat, err := config.LoadClientConfig(cfgFilePath, strictConfigMode)
	if err != nil {
		return err
	}
	if isLegacyFormat {
		fmt.Printf("WARNING: ini format is deprecated and the support will be removed in the future, " +
			"please use yaml/json/toml format instead!\n")
	}

	if len(cfg.FeatureGates) > 0 {
		if err := featuregate.SetFromMap(cfg.FeatureGates); err != nil {
			return err
		}
	}

	warning, err := validation.ValidateAllClientConfig(cfg, proxyCfgs, visitorCfgs)
	if warning != nil {
		fmt.Printf("WARNING: %v\n", warning)
	}
	if err != nil {
		return err
	}
	return startService(cfg, proxyCfgs, visitorCfgs, cfgFilePath)
}

func startService(
	cfg *v1.ClientCommonConfig,
	proxyCfgs []v1.ProxyConfigurer,
	visitorCfgs []v1.VisitorConfigurer,
	cfgFile string,
) error {
	log.InitLogger(cfg.Log.To, cfg.Log.Level, int(cfg.Log.MaxDays), cfg.Log.DisablePrintColor)

	if cfgFile != "" {
		log.Infof("start frpc service for config file [%s]", cfgFile)
		defer log.Infof("frpc service for config file [%s] stopped", cfgFile)
	}
	svr, err := client.NewService(client.ServiceOptions{
		Common:         cfg,
		ProxyCfgs:      proxyCfgs,
		VisitorCfgs:    visitorCfgs,
		ConfigFilePath: cfgFile,
	})
	if err != nil {
		return err
	}

	shouldGracefulClose := cfg.Transport.Protocol == "kcp" || cfg.Transport.Protocol == "quic"
	// Capture the exit signal if we use kcp or quic.
	if shouldGracefulClose {
		go handleTermSignal(svr)
	}
	return svr.Run(context.Background())
}
