package conf

import (
	"errors"
	"net"

	"github.com/BurntSushi/toml"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// Config Structure
type Config struct {
	LDAP   ldap.Source
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

	err = validateConfigurationArgs(confData)
	if err != nil {
		return nil, err
	}

	return confData, nil
}

func validateConfigurationArgs(confData *Config) error {

	// Server IP
	if net.ParseIP(confData.Server.IP) == nil {
		return errors.New("Invalid Server IP Address. Must be a valid IPV4")
	}

	// Server Port
	if confData.Server.Port < 1 || confData.Server.Port > 65535 {
		return errors.New("Invalid Server Port number. Must be between 1-65535")
	}

	return nil
}
