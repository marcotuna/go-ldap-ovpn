package main

import (
	"flag"
	"os"

	"github.com/marcotuna/GoLDAPOpenVPN/config"
	"github.com/marcotuna/GoLDAPOpenVPN/logger"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "github.com/sirupsen/logrus"
)

var (
	configurationFile = flag.String("config", "config.toml", "Configuration file location")
)

func main() {

	flag.Parse()

	// Load Configuration File
	configData, err := config.LoadConfiguration(*configurationFile)
	if err != nil {
		log.Errorf("%v", err.Error())
		os.Exit(1)
	}

	initLogger, err := logger.NewRunner(configData)

	if err != nil {
		log.Error(2, "%v", err.Error())
	}

	initLogger.Initialize()

	ls := ldap.New(ldap.LDAP{
		Settings:   &configData.LDAP,
		Connection: nil,
	})

	searchUsername := os.Getenv("username")
	searchPassword := os.Getenv("password")

	startAuthentication := ls.LdapSearch(searchUsername, searchPassword)

	os.Exit(startAuthentication)
}
