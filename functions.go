package main

import (
	"crypto/tls"
	"fmt"
	"regexp"
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

func ldapSearch(searchUsername string, searchPassword string) int {
	// Start LDAP Connection
	ldapConn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", conf.LDAP.Host, conf.LDAP.Port), &tls.Config{InsecureSkipVerify: true})

	err = bindUser(ldapConn, conf.LDAP.BindDN, conf.LDAP.BindPassword)
	if err != nil {
		log.Error(2, "Could not Bind to LDAP.")
		return 1
	}

	defer ldapConn.Close()

	userFilter, ok := conf.LDAP.sanitizedUserQuery(searchUsername)
	if ok {
		log.Error(2, "Could not Sanitize User Query.")
		return 1
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
		return 1
	} else if len(sr.Entries) > 1 {
		log.Error(2, "LDAP: Filter '%s' returned more than one user", userFilter)
		return 1
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		log.Error(2, "LDAP: Search was successful, but found no DN!")
		return 1
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
			return 1
		}
		groupDN, ok := conf.LDAP.sanitizedGroupDN(conf.LDAP.GroupDN)
		if !ok {
			return 1
		}

		log.Trace("LDAP: Fetching groups '%v' with filter '%s' and base '%s'", conf.LDAP.GroupMemberUID, groupFilter, groupDN)
		groupSearch := ldap.NewSearchRequest(
			groupDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, groupFilter,
			[]string{conf.LDAP.GroupMemberUID},
			nil)

		srg, err := ldapConn.Search(groupSearch)
		if err != nil {
			log.Error(2, "LDAP: Group search failed: %v", err)
			return 1
		} else if len(sr.Entries) < 1 {
			log.Error(2, "LDAP: Group search failed: 0 entries")
			return 1
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
			return 1
		}
	}

	// Check Username, Password
	err = bindUser(ldapConn, userDN, searchPassword)
	if err != nil {
		log.Error(2, "Could not Bind to LDAP.")
		return 1
	}

	log.Trace("LDAP: User %s is authorized.", attributeUsername)

	return 0
}
