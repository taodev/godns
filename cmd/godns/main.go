package main

import (
	"flag"
	"log"
	"os"

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
	if err = server.Serve(); err != nil {
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
