# GoLDAPOpenVPN
GoLang Tool for OpenVPN User Authentication from LDAP

## How to use?

OpenVPN contains the auth-user-pass-verify method which allows to call an external tool to perform authentication validation  

Download the ldap_ovpn and place it in a folder where the openvpn service has permissions to execute it.  

```
auth-user-pass-verify "/etc/openvpn/scripts/GoLDAPOpenVPN -config /etc/openvpn/scripts/vpn.toml" via-env
```

Create the configuration file where it will contain the ldap connection details.
The following example connects to the Jumpcloud LDAP as a Service and looks for users that belong to the group VPN-USER

```
[ldap]
uri = "ldaps://ldap.jumpcloud.com:636"
host = "ldap.jumpcloud.com"
port = 636
bind_dn = "uid=service,ou=Users,o=ORGANIZATION_ID,dc=jumpcloud,dc=com"
bind_password = "PASSWORD"
user_base = "ou=Users,o=ORGANIZATION_ID,dc=jumpcloud,dc=com"
user_dn = "uid=%s,ou=Users,o=ORGANIZATION_ID,dc=jumpcloud,dc=com"
user_uid="uidNumber"
filter="(&(objectClass=inetOrgPerson)(|(uid=%s)))"
attribute_username="uid"
attribute_name="givenName"
attribute_surname="sn"
attribute_mail="mail"
attributes_in_bind=true
group_enabled=true
group_dn="ou=Users,o=ORGANIZATION_ID,dc=jumpcloud,dc=com"
group_filter="(&(objectClass=groupOfNames)(|(cn=VPN-USER)))"
group_member_uid="member"

[log]
# Can be "console" and "file", default is "console"
# Use comma to separate multiple modes, e.g. "console, file"
mode = "console"
# Either "Trace", "Info", "Warn", "Error", "Fatal", default is "Trace"
level = "Trace"
```