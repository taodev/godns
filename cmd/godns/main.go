package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/taodev/godns"
	"gopkg.in/yaml.v3"
)

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	opts, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

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
	if err = yaml.Unmarshal(data, &opts); err != nil {
		return nil, err
	}
	return &opts, nil
}
