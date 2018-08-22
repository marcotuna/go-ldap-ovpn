package main

import (
	"fmt"
	"strings"

	log "gopkg.in/clog.v1"
	ldap "gopkg.in/ldap.v2"
)

func (ls *LdapConfig) sanitizedUserQuery(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00()*\\"
	if strings.ContainsAny(username, badCharacters) {
		log.Error(2, fmt.Sprintf("LDAP: Username contains invalid query characters: %s", username))
		return "", true
	}

	return strings.Replace(ls.Filter, "%s", username, -1), false
}

func (ls *LdapConfig) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<>"
	if strings.ContainsAny(username, badCharacters) || strings.HasPrefix(username, " ") || strings.HasSuffix(username, " ") {
		log.Error(2, fmt.Sprintf("LDAP: Username contains invalid query characters: %s", username))
		return "", false
	}

	return strings.Replace(ls.UserDN, "%s", username, -1), true
}

func (ls *LdapConfig) sanitizedGroupFilter(group string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00*\\"
	if strings.ContainsAny(group, badCharacters) {
		log.Error(2, fmt.Sprintf("LDAP: Group filter invalid query characters: %s", group))
		return "", false
	}

	return group, true
}

func (ls *LdapConfig) sanitizedGroupDN(groupDn string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\'\"#+;<>"
	if strings.ContainsAny(groupDn, badCharacters) || strings.HasPrefix(groupDn, " ") || strings.HasSuffix(groupDn, " ") {
		log.Error(2, fmt.Sprintf("LDAP: Group DN contains invalid query characters: %s", groupDn))
		return "", false
	}

	return groupDn, true
}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	log.Trace("Binding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		log.Error(2, "LDAP authentication failed for '%s': %v", userDN, err)
		return err
	}
	log.Trace("Bound successfully with userDN: %s", userDN)
	return err
}
