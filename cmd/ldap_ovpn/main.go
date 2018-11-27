package main

import (
	"flag"
	"os"

	"github.com/marcotuna/GoLDAPOpenVPN/conf"
	"github.com/marcotuna/GoLDAPOpenVPN/logger"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

// Config File Structure
type Config struct {
	LDAP ldap.Source
}

var (
	configurationFile = flag.String("config", "config.toml", "Configuration file location")
)

func main() {

	flag.Parse()

	// Load Configuration File
	configData, err := conf.LoadConfiguration(*configurationFile)
	if err != nil {
		log.Errorf("%v", err.Error())
		os.Exit(1)
	}

	initLogger, err := logger.NewRunner(configData)

	if err != nil {
		log.Error(2, "%v", err.Error())
	}

	initLogger.Initialize()

	searchUsername := os.Getenv("username")
	searchPassword := os.Getenv("password")

	ls := ldap.Initialize(configData.LDAP)
	startAuthentication := ls.LdapSearch(searchUsername, searchPassword)

	os.Exit(startAuthentication)
}
