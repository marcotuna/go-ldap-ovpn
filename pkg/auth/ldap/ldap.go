package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

// SecurityProtocol Exported Type
type SecurityProtocol int

// Note: new type must be added at the end of list to maintain compatibility.
const (
	SECURITY_PROTOCOL_UNENCRYPTED SecurityProtocol = iota
	SECURITY_PROTOCOL_LDAPS
	SECURITY_PROTOCOL_START_TLS
)

// LDAP Structure
type LDAP struct {
	Connection *ldap.Conn
	Settings   *Settings
}

// Settings ...
type Settings struct {
	URI               string           `toml:"uri,omitempty"`
	Host              string           `toml:"host,omitempty"` // LDAP host
	Port              int              `toml:"port,omitempty"` // Port number
	SecurityProtocol  SecurityProtocol `toml:"security_protocol,omitempty"`
	SkipVerify        bool             `toml:"skip_verify,omitempty"`
	BindDN            string           `toml:"bind_dn,omitempty"`            // DN to bind with
	BindPassword      string           `toml:"bind_password,omitempty"`      // Bind DN password
	UserBase          string           `toml:"user_base,omitempty"`          // Base search path for users
	UserDN            string           `toml:"user_dn,omitempty"`            // Template for the DN of the user for simple auth
	AttributeCN       string           `toml:"attribute_cn,omitempty"`       // Common Name attribute
	AttributeUsername string           `toml:"attribute_username,omitempty"` // Username attribute
	AttributeName     string           `toml:"attribute_name,omitempty"`     // First name attribute
	AttributeSurname  string           `toml:"attribute_surname,omitempty"`  // Surname attribute
	AttributeMail     string           `toml:"attribute_mail,omitempty"`     // E-mail attribute
	AttributesInBind  bool             `toml:"attributes_in_bind,omitempty"` // fetch attributes in bind context (not user)
	Filter            string           `toml:"filter,omitempty"`             // Query filter to validate entry
	AdminFilter       string           // Query filter to check if user is admin
	GroupEnabled      bool             `toml:"group_enabled,omitempty"`    // if the group checking is enabled
	GroupDN           string           `toml:"group_dn,omitempty"`         // Group Search Base
	GroupFilter       string           `toml:"group_filter,omitempty"`     // Group Name Filter
	GroupMemberUID    string           `toml:"group_member_uid,omitempty"` // Group Attribute containing array of UserUID
	UserUID           string           `toml:"user_uid,omitempty"`         // User Attribute listed in Group
}

// New ...
func New(cfg LDAP) *LDAP {
	return &cfg
}

func (l *LDAP) sanitizedUserQuery(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00()*\\"
	if strings.ContainsAny(username, badCharacters) {
		log.Errorf("LDAP: Username contains invalid query characters: %s", username)
		return "", false
	}

	return strings.Replace(l.Settings.Filter, "%s", username, -1), true
}

func (l *LDAP) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<>"
	if strings.ContainsAny(username, badCharacters) || strings.HasPrefix(username, " ") || strings.HasSuffix(username, " ") {
		log.Errorf("LDAP: Username contains invalid query characters: %s", username)
		return "", false
	}

	return strings.Replace(l.Settings.UserDN, "%s", username, -1), true
}

func (l *LDAP) sanitizedGroupFilter(group string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00*\\"
	if strings.ContainsAny(group, badCharacters) {
		log.Errorf("LDAP: Group filter invalid query characters: %s", group)
		return "", false
	}

	return group, true
}

func (l *LDAP) sanitizedGroupDN(groupDn string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\'\"#+;<>"
	if strings.ContainsAny(groupDn, badCharacters) || strings.HasPrefix(groupDn, " ") || strings.HasSuffix(groupDn, " ") {
		log.Errorf("LDAP: Group DN contains invalid query characters: %s", groupDn)
		return "", false
	}

	return groupDn, true
}

func (l *LDAP) findUserDN(name string) (string, bool) {
	log.Tracef("Search for LDAP user: %s", name)
	if len(l.Settings.BindDN) > 0 && len(l.Settings.BindPassword) > 0 {
		// Replace placeholders with username
		bindDN := strings.Replace(l.Settings.BindDN, "%s", name, -1)
		err := l.Connection.Bind(bindDN, l.Settings.BindPassword)
		if err != nil {
			log.Tracef("LDAP: Failed to bind as BindDN '%s': %v", bindDN, err)
			return "", false
		}
		log.Tracef("LDAP: Bound as BindDN: %s", bindDN)
	} else {
		log.Trace("LDAP: Proceeding with anonymous LDAP search")
	}

	// A search for the user.
	userFilter, ok := l.sanitizedUserQuery(name)
	if !ok {
		return "", false
	}

	log.Tracef("LDAP: Searching for DN using filter '%s' and base '%s'", userFilter, l.Settings.UserBase)
	search := ldap.NewSearchRequest(
		l.Settings.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0,
		false, userFilter, []string{}, nil)

	// Ensure we found a user
	sr, err := l.Connection.Search(search)
	if err != nil || len(sr.Entries) < 1 {
		log.Tracef("LDAP: Failed search using filter '%s': %v", userFilter, err)
		return "", false
	} else if len(sr.Entries) > 1 {
		log.Tracef("LDAP: Filter '%s' returned more than one user", userFilter)
		return "", false
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		log.Error("LDAP: Search was successful, but found no DN!")
		return "", false
	}

	return userDN, true
}

func (l *LDAP) dial() (*ldap.Conn, error) {
	log.Tracef("LDAP: Dialing with security protocol '%v' without verifying: %v", l.Settings.SecurityProtocol, l.Settings.SkipVerify)

	var err error
	tlsCfg := &tls.Config{
		InsecureSkipVerify: l.Settings.SkipVerify,
	}

	l.Connection, err = ldap.DialURL(l.Settings.URI)

	if err != nil {
		return nil, err
	}

	if l.Settings.SecurityProtocol == SECURITY_PROTOCOL_START_TLS || l.Settings.SecurityProtocol == SECURITY_PROTOCOL_LDAPS {
		log.Tracef("Using TLS options")
		err = l.Connection.StartTLS(tlsCfg)
		if err != nil {
			return nil, err
		}
	}

	return l.Connection, nil
}

func (l *LDAP) bindUser(userDN, password string) error {
	log.Tracef("Binding with userDN: %s", userDN)

	err := l.Connection.Bind(userDN, password)
	if err != nil {
		log.Errorf("LDAP authentication failed for '%s': %v", userDN, err)
		return err
	}
	log.Tracef("Bound successfully with userDN: %s", userDN)
	return err
}

// UserEntry ...
type UserEntry struct {
	UID        string
	DN         string
	CommonName string
	Username   string
	FirstName  string
	SurName    string
	Mail       string
	IsAdmin    bool
}

// SearchEntry search an LDAP source if an entry (name, passwd) is valid and in the specific filter
func (l *LDAP) SearchEntry(name, passwd string, directBind bool) (*UserEntry, error) {
	// See https://tools.ietf.org/search/rfc4513#section-5.1.2
	if len(passwd) == 0 {
		return nil, fmt.Errorf("authentication failed for '%s' with empty password", name)
	}

	_, err := l.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap connect failed for '%s': %v", l.Settings.URI, err)
	}

	if l == nil {
		return nil, errors.New("connection is not available or ready")
	}

	if l.Connection == nil {
		return nil, fmt.Errorf("ldap connection is not ready")
	}

	defer l.Connection.Close()

	var userDN string
	if directBind {
		log.Tracef("LDAP will bind directly via UserDN template: %s", l.Settings.UserDN)

		var ok bool
		userDN, ok = l.sanitizedUserDN(name)
		if !ok {
			return nil, errors.New("could not sanitize userDN")
		}
	} else {
		log.Trace("LDAP will use BindDN")

		var found bool
		userDN, found = l.findUserDN(name)
		if !found {
			return nil, errors.New("could not find userDN")
		}
	}

	if directBind || !l.Settings.AttributesInBind {
		// Binds user (checking password) before looking-up attributes in user context
		err = l.bindUser(userDN, passwd)
		if err != nil {
			return nil, fmt.Errorf("bindUser with %s. No results", userDN)
		}
	}

	userFilter, ok := l.sanitizedUserQuery(name)
	if !ok {
		return nil, fmt.Errorf("could not sanitize user query from %s", name)
	}

	log.Tracef("Fetching attributes '%v', '%v', '%v', '%v', '%v', '%v' with filter '%s' and base '%s'",
		l.Settings.AttributeCN, l.Settings.AttributeUsername, l.Settings.AttributeName, l.Settings.AttributeSurname, l.Settings.AttributeMail, l.Settings.UserUID, userFilter, userDN)

	search := ldap.NewSearchRequest(
		userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, userFilter,
		[]string{l.Settings.AttributeCN, l.Settings.AttributeUsername, l.Settings.AttributeName, l.Settings.AttributeSurname, l.Settings.AttributeMail, l.Settings.UserUID},
		nil)

	sr, err := l.Connection.Search(search)
	if err != nil {
		return nil, fmt.Errorf("LDAP: User search failed: %v", err)
	} else if len(sr.Entries) < 1 {
		return nil, errors.New("LDAP: No entries found")
	}

	userEntry := UserEntry{
		UID:        sr.Entries[0].GetAttributeValue(l.Settings.UserUID),
		DN:         sr.Entries[0].DN,
		CommonName: sr.Entries[0].GetAttributeValue(l.Settings.AttributeCN),
		Username:   sr.Entries[0].GetAttributeValue(l.Settings.AttributeUsername),
		FirstName:  sr.Entries[0].GetAttributeValue(l.Settings.AttributeName),
		SurName:    sr.Entries[0].GetAttributeValue(l.Settings.AttributeSurname),
		Mail:       sr.Entries[0].GetAttributeValue(l.Settings.AttributeMail),
		IsAdmin:    false,
	}

	// Check group membership
	if l.Settings.GroupEnabled {
		groupFilter, ok := l.sanitizedGroupFilter(l.Settings.GroupFilter)
		if !ok {
			return nil, errors.New("could not sanitze groupFilter")
		}
		groupDN, ok := l.sanitizedGroupDN(l.Settings.GroupDN)
		if !ok {
			return nil, errors.New("could not sanitize groupDN")
		}

		log.Tracef("LDAP: Fetching groups '%v' with filter '%s' and base '%s'", l.Settings.GroupMemberUID, groupFilter, groupDN)
		groupSearch := ldap.NewSearchRequest(
			groupDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter,
			[]string{l.Settings.GroupMemberUID},
			nil)

		srg, err := l.Connection.Search(groupSearch)
		if err != nil {
			return nil, fmt.Errorf("LDAP: Group search failed: %v", err)
		} else if len(srg.Entries) < 1 {
			return nil, errors.New("LDAP: Group search failed: 0 entries")
		}

		isMember := false
		if l.Settings.UserUID == "dn" {
			for _, group := range srg.Entries {
				for _, member := range group.GetAttributeValues(l.Settings.GroupMemberUID) {
					if member == userEntry.DN {
						isMember = true
					}
				}
			}
		} else {
			for _, group := range srg.Entries {
				for _, member := range group.GetAttributeValues(l.Settings.GroupMemberUID) {

					log.Tracef("Member: '%v', Uid: '%v'", member, userEntry.UID)

					re := regexp.MustCompile("^uid=[a-z0-9_.-][^,]*")
					match := re.FindStringSubmatch(member)

					if match[0] == "uid="+userEntry.Username {
						isMember = true
					}
				}
			}
		}

		if !isMember {
			return nil, fmt.Errorf("LDAP: Group membership test failed [username: %s, group_member_uid: %s, user_uid: %s", userEntry.Username, l.Settings.GroupMemberUID, userEntry.UID)
		}
	}

	userEntry.IsAdmin = false
	if len(l.Settings.AdminFilter) > 0 {
		log.Tracef("Checking admin with filter '%s' and base '%s'", l.Settings.AdminFilter, userDN)
		search = ldap.NewSearchRequest(
			userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, l.Settings.AdminFilter,
			[]string{l.Settings.AttributeName},
			nil)

		sr, err = l.Connection.Search(search)
		if err != nil {
			log.Errorf("LDAP: Admin search failed: %v", err)
		} else if len(sr.Entries) < 1 {
			log.Errorf("LDAP: Admin search failed: 0 entries")
		} else {
			userEntry.IsAdmin = true
		}
	}

	if !directBind && l.Settings.AttributesInBind {
		// Binds user (checking password) after looking-up attributes in BindDN context
		err = l.bindUser(userDN, passwd)
		if err != nil {
			return nil, err
		}
	}

	return &userEntry, nil
}

// LdapSearch Finds user by Username and Password
func (l *LDAP) LdapSearch(searchUsername string, searchPassword string) int {
	// Start LDAP Connection
	_, err := l.dial()

	if err != nil {
		log.Errorf("Could not Establish Connection to LDAP.")
		return 1
	}

	err = l.bindUser(l.Settings.BindDN, l.Settings.BindPassword)
	if err != nil {
		log.Errorf("Could not Bind to LDAP.")
		return 1
	}

	defer l.Connection.Close()

	userFilter, ok := l.sanitizedUserQuery(searchUsername)
	if !ok {
		log.Errorf("Could not Sanitize User Query.")
		return 1
	}

	searchRequest := ldap.NewSearchRequest(
		l.Settings.UserBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		[]string{l.Settings.AttributeName, l.Settings.AttributeSurname, l.Settings.AttributeMail, l.Settings.AttributeUsername, l.Settings.UserUID},
		nil)

	sr, err := l.Connection.Search(searchRequest)
	if err != nil || len(sr.Entries) < 1 {
		log.Errorf("LDAP: Failed search using filter '%s': %v", userFilter, err)
		return 1
	} else if len(sr.Entries) > 1 {
		log.Errorf("LDAP: Filter '%s' returned more than one user", userFilter)
		return 1
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		log.Errorf("LDAP: Search was successful, but found no DN!")
		return 1
	}

	// Username
	attributeUsername := sr.Entries[0].GetAttributeValue(l.Settings.AttributeUsername)

	// Check group membership
	if l.Settings.GroupEnabled {
		groupFilter, ok := l.sanitizedGroupFilter(l.Settings.GroupFilter)
		if !ok {
			return 1
		}
		groupDN, ok := l.sanitizedGroupDN(l.Settings.GroupDN)
		if !ok {
			return 1
		}

		log.Tracef("LDAP: Fetching groups '%v' with filter '%s' and base '%s'", l.Settings.GroupMemberUID, groupFilter, groupDN)
		groupSearch := ldap.NewSearchRequest(
			groupDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter,
			[]string{l.Settings.GroupMemberUID},
			nil)

		srg, err := l.Connection.Search(groupSearch)
		if err != nil {
			log.Errorf("LDAP: Group search failed: %v", err)
			return 1
		} else if len(sr.Entries) < 1 {
			log.Errorf("LDAP: Group search failed: 0 entries")
			return 1
		}

		isMember := false
		for _, group := range srg.Entries {
			for _, member := range group.GetAttributeValues(l.Settings.GroupMemberUID) {

				re := regexp.MustCompile("^uid=[a-z0-9_.-][^,]*")
				match := re.FindStringSubmatch(member)

				if match[0] == "uid="+attributeUsername {
					isMember = true
				}
			}
		}

		if !isMember {
			log.Errorf("LDAP: Group membership test failed [username: %s, group_member_uid: %s", attributeUsername, l.Settings.GroupMemberUID)
			return 1
		}
	}

	// Check Username, Password
	err = l.bindUser(userDN, searchPassword)
	if err != nil {
		log.Error("Could not Bind to LDAP.")
		return 1
	}

	log.Tracef("LDAP: User %s is authorized.", attributeUsername)

	return 0
}
