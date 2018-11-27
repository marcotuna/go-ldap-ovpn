package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/marcotuna/GoLDAPOpenVPN/pkg/auth/ldap"
	log "gopkg.in/clog.v1"
)

var conf *Config

// Config File Structure
type Config struct {
	LDAP ldap.Source
}

func main() {

	configurationFile := flag.String("config", "config.toml", "Configuration file location")
	flag.Parse()

	searchUsername := os.Getenv("username")
	searchPassword := os.Getenv("password")

	// Load Configuration File
	if _, err := toml.DecodeFile(*configurationFile, &conf); err != nil {
		fmt.Printf("Could not load or decode the configuration file.\n")
		os.Exit(1)
	}

	err := log.New(log.CONSOLE, log.ConsoleConfig{})
	if err != nil {
		fmt.Printf("Fail to create new logger: %v\n", err)
		os.Exit(1)
	}

	ls := ldap.Initialize(conf.LDAP)
	startAuthentication := ls.LdapSearch(searchUsername, searchPassword)

	os.Exit(startAuthentication)
}
