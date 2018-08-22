package main

import (
	"fmt"
	"log"
	"strings"

	ldap "gopkg.in/ldap.v2"
)

func (ls *LdapConfig) sanitizedUserQuery(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00()*\\"
	if strings.ContainsAny(username, badCharacters) {
		return fmt.Sprintf("LDAP: Username contains invalid query characters: %s", username), true
	}

	return strings.Replace(ls.Filter, "%s", username, -1), false
}

func (ls *LdapConfig) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<>"
	if strings.ContainsAny(username, badCharacters) || strings.HasPrefix(username, " ") || strings.HasSuffix(username, " ") {
		return fmt.Sprintf("LDAP: Username contains invalid query characters: %s", username), false
	}

	return strings.Replace(ls.UserDN, "%s", username, -1), true
}

func (ls *LdapConfig) sanitizedGroupFilter(group string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00*\\"
	if strings.ContainsAny(group, badCharacters) {
		return fmt.Sprintf("LDAP: Group filter invalid query characters: %s", group), false
	}

	return group, true
}

func (ls *LdapConfig) sanitizedGroupDN(groupDn string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\'\"#+;<>"
	if strings.ContainsAny(groupDn, badCharacters) || strings.HasPrefix(groupDn, " ") || strings.HasSuffix(groupDn, " ") {
		return fmt.Sprintf("LDAP: Group DN contains invalid query characters: %s", groupDn), false
	}

	return groupDn, true
}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	log.Printf("Binding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		log.Printf("LDAP authentication failed for '%s': %v", userDN, err)
		return err
	}
	log.Printf("Bound successfully with userDN: %s", userDN)
	return err
}
