package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	RootCA struct {
		Cert string `yaml:"Cert"`
		Key  string `yaml:"Key"`
	} `yaml:"RootCA"`
	DumpDir      string `yaml:"DumpDir"`
	ListenIPAddr string `yaml:"ListenIPAddr"`
}

func LoadConfig(path string) (*Config, error) {
	// ファイルを開く
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 設定ファイルをパースする
	var conf Config
	err = yaml.Unmarshal(buf, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}
