package main

import (
	"flag"
	"fmt"
)

func main() {
	configPath := flag.String("config", "", "Path to config YAML (default: configs/default.yaml)")
	fmt.Println(*configPath)
}
