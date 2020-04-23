package config

import (
	"github.com/BurntSushi/toml"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// Config Structure
type Config struct {
	LDAP   ldap.Settings
	Log    LogCfg
	Server ServerCfg
}

// LogCfg related to log output/config
type LogCfg struct {
	Level string `toml:"level"`
	Mode  string `toml:"mode"`
	File  string `toml:"file"`
}

// ServerCfg related to server listen
type ServerCfg struct {
	IP   string `toml:"ip"`
	Port int    `toml:"port"`
}

// LoadConfiguration File
func LoadConfiguration(configurationFile string) (*Config, error) {
	var confData *Config

	_, err := toml.DecodeFile(configurationFile, &confData)
	if err != nil {
		// WARNING: For some reason sometimes the error output is not displayed
		log.Errorf("There was an error: %v", err)
		return nil, err
	}

	return confData, nil
}
