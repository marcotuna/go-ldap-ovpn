package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"regexp"

	"github.com/BurntSushi/toml"
	log "gopkg.in/clog.v1"
	ldap "gopkg.in/ldap.v2"
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

	searchUsername := "test"
	searchPassword := "test"

	// Load Configuration File
	if _, err := toml.DecodeFile("./config.toml", &conf); err != nil {
		log.Error(2, "Could not Decode config file.")
		return
	}

	err := log.New(log.CONSOLE, log.ConsoleConfig{})
	if err != nil {
		fmt.Printf("Fail to create new logger: %v\n", err)
		os.Exit(1)
	}

	// No TLS, not recommended
	ldapConn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", conf.LDAP.Host, conf.LDAP.Port), &tls.Config{InsecureSkipVerify: true})

	err = bindUser(ldapConn, conf.LDAP.BindDN, conf.LDAP.BindPassword)
	if err != nil {
		log.Error(2, "Could not Bind to LDAP.")
		return
	}

	defer ldapConn.Close()

	userFilter, ok := conf.LDAP.sanitizedUserQuery(searchUsername)
	if ok {
		log.Error(2, "Could not Sanitize User Query.")
		return
	}

	searchRequest := ldap.NewSearchRequest(
		conf.LDAP.UserBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		[]string{conf.LDAP.AttributeName, conf.LDAP.AttributeSurname, conf.LDAP.AttributeMail, conf.LDAP.AttributeUsername, conf.LDAP.UserUID},
		nil)

	sr, err := ldapConn.Search(searchRequest)
	if err != nil || len(sr.Entries) < 1 {
		log.Error(2, "LDAP: Failed search using filter '%s': %v", userFilter, err)
		return
	} else if len(sr.Entries) > 1 {
		log.Error(2, "LDAP: Filter '%s' returned more than one user", userFilter)
		return
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		log.Error(2, "LDAP: Search was successful, but found no DN!")
		return
	}

	//fmt.Printf("TestSearch: %s -> num of entries = %d\n", searchRequest.Filter, len(sr.Entries))

	attributeUsername := sr.Entries[0].GetAttributeValue(conf.LDAP.AttributeUsername)
	//attributeFirstname := sr.Entries[0].GetAttributeValue(conf.LDAP.AttributeName)
	//attributeSurname := sr.Entries[0].GetAttributeValue(conf.LDAP.AttributeSurname)
	//attributeMail := sr.Entries[0].GetAttributeValue(conf.LDAP.AttributeMail)
	//attributeUID := sr.Entries[0].GetAttributeValue(conf.LDAP.UserUID)

	// Check group membership

	if conf.LDAP.GroupEnabled {
		groupFilter, ok := conf.LDAP.sanitizedGroupFilter(conf.LDAP.GroupFilter)
		if !ok {
			return
		}
		groupDN, ok := conf.LDAP.sanitizedGroupDN(conf.LDAP.GroupDN)
		if !ok {
			return
		}

		log.Trace("LDAP: Fetching groups '%v' with filter '%s' and base '%s'", conf.LDAP.GroupMemberUID, groupFilter, groupDN)
		groupSearch := ldap.NewSearchRequest(
			groupDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter,
			[]string{conf.LDAP.GroupMemberUID},
			nil)

		srg, err := ldapConn.Search(groupSearch)
		if err != nil {
			log.Error(2, "LDAP: Group search failed: %v", err)
			return
		} else if len(sr.Entries) < 1 {
			log.Error(2, "LDAP: Group search failed: 0 entries")
			return
		}

		isMember := false
		for _, group := range srg.Entries {
			for _, member := range group.GetAttributeValues(conf.LDAP.GroupMemberUID) {

				re := regexp.MustCompile("^uid=[a-z0-9_.-][^,]*")
				match := re.FindStringSubmatch(member)

				if match[0] == "uid="+attributeUsername {
					isMember = true
				}
			}
		}

		if !isMember {
			log.Error(2, "LDAP: Group membership test failed [username: %s, group_member_uid: %s", attributeUsername, conf.LDAP.GroupMemberUID)
			return
		}
	}

	// Check Username, Password
	err = bindUser(ldapConn, userDN, searchPassword)
	if err != nil {
		log.Error(2, "Could not Bind to LDAP.")
		return
	}

	log.Trace("LDAP: User %s is authorized.", attributeUsername)

}
