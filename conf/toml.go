package conf

import (
	"github.com/BurntSushi/toml"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// Config Structure
type Config struct {
	LDAP ldap.Source
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
	return nil
}
