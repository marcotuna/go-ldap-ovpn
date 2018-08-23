package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	log "gopkg.in/clog.v1"
)

// SecurityProtocol Exported Type
type SecurityProtocol int

// Note: new type must be added at the end of list to maintain compatibility.
const (
	securityProtocolUnencrypted SecurityProtocol = iota
	securityProtocolLdaps
	securityProtocolStartTLS
)

var conf *Config

// Config File Structure
type Config struct {
	LDAP LdapConfig
}

// LdapConfig Structure
type LdapConfig struct {
	Host              string `toml:"host,omitempty"` // LDAP host
	Port              int    `toml:"port,omitempty"` // Port number
	SecurityProtocol  SecurityProtocol
	SkipVerify        bool
	BindDN            string `toml:"bind_dn,omitempty"`            // DN to bind with
	BindPassword      string `toml:"bind_password,omitempty"`      // Bind DN password
	UserBase          string `toml:"user_base,omitempty"`          // Base search path for users
	UserDN            string `toml:"user_dn,omitempty"`            // Template for the DN of the user for simple auth
	AttributeUsername string `toml:"attribute_username,omitempty"` // Username attribute
	AttributeName     string `toml:"attribute_name,omitempty"`     // First name attribute
	AttributeSurname  string `toml:"attribute_surname,omitempty"`  // Surname attribute
	AttributeMail     string `toml:"attribute_mail,omitempty"`     // E-mail attribute
	AttributesInBind  bool   `toml:"attributes_in_bind,omitempty"` // fetch attributes in bind context (not user)
	Filter            string `toml:"filter,omitempty"`             // Query filter to validate entry
	AdminFilter       string // Query filter to check if user is admin
	GroupEnabled      bool   `toml:"group_enabled,omitempty"`    // if the group checking is enabled
	GroupDN           string `toml:"group_dn,omitempty"`         // Group Search Base
	GroupFilter       string `toml:"group_filter,omitempty"`     // Group Name Filter
	GroupMemberUID    string `toml:"group_member_uid,omitempty"` // Group Attribute containing array of UserUID
	UserUID           string `toml:"user_uid,omitempty"`         // User Attribute listed in Group
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

	startAuthentication := ldapSearch(searchUsername, searchPassword)

	os.Exit(startAuthentication)
}
