package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/taodev/godns"
	"github.com/taodev/stcp/key"
	"gopkg.in/yaml.v3"
)

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	opts, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	// 判断 StcpKey 是否设置
	log.Printf("StcpKey: %v", len(opts.StcpKey))
	if len(opts.StcpKey) == 0 {
		stcpKeyPath := filepath.Join(filepath.Dir(*configPath), "stcp.key")
		slog.Info("generate stcp key", "path", stcpKeyPath)
		if stcpKey, err := key.Generate(stcpKeyPath); err == nil {
			opts.StcpKey = stcpKey.String()
		}
	}
	privateKey, err := key.Base64(opts.StcpKey)
	if err != nil {
		slog.Error("parse stcp key error", "err", err)
		os.Exit(1)
	}
	publicKey, err := key.PublicKey(privateKey)
	if err != nil {
		slog.Error("parse stcp key error", "err", err)
		os.Exit(1)
	}
	slog.Info("STCP", "publicKey", publicKey.String())

	server := godns.NewDnsServer(opts, nil)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve()
	}()

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		os.Interrupt,    // Ctrl+C
		syscall.SIGTERM, // kill 默认
		syscall.SIGINT,  // kill -2
		syscall.SIGQUIT, // kill -3
	)
	select {
	case err = <-errCh:
		slog.Error("dns server serve error", "err", err)
	case <-quit:
	}

	log.Println("Shutting down server...")
	// 关闭 server
	if err = server.Shutdown(); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(name string) (*godns.Options, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var opts godns.Options
	if err = opts.Default(); err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(data, &opts); err != nil {
		return nil, err
	}
	return &opts, nil
}
