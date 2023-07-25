# LDAP Identity Provider

LDAP is the best IDP choice as it allows to take advantage of all Vulture's feature regarding SSO, SSO Forward and User management APIs.

## Connection settings

`Name`: This is a friendly name to refer to the LDAP IDP. It has to be unique

`Host`: IP Address or hostname (must be resolvable by Vulture) to reach your LDAP directory

`Port` : Corresponding TCP port to reach your LDAP repository

`Protocol`: LDAP protocol version to use 

`Encryption Scheme`: Select the appropriate encryption scheme to contact your LDAP directory

`Service Account DN`: The DN of the service account used by Vulture to contact your LDAP directory. This account **MUST** have write access if you want to take advantage of features such as lock a user, reset it's password, use TOTP, automatically add to a group...

`Service account password`: The corresponding password

`Base DN`: The LDAP base DN used to connect to your LDAP directory (ex: DC=myDomain, DC=ORG)

## User settings

From this tab you will have to configure settings related to user authentication. Basically it consist of defining where are located your users branches within your LDAP directory.

`User search scope`: The LDAP search scope to use when searching for a user (base, one level or all subtree) in your LDAP directory

`User DN`: The starting point of your LDAP server to use when searching for users authentication (ex: OU=Users)

`User Object classes`: The list of LDAP Object Classes (schemas) to assign to new User entries, when created through Vulture (leave defaults unless you know what you do)

`User attribute`: The LDAP user's identifier. This attribute will be mapped to the Vulture's login on Authentication portal.

`User search filter`: The LDAP filter to use when searching for a user in your LDAP directory

`Account locked filter`: The LDAP filter that Vulture should use to detect if a user account is locked or not in your LDAP directory. 

Example: 
```
(lockoutTime>=1)
```

`Need change password filter`: The LDAP filter that Vulture should use to detect if a user must change its password. 

Example: 
```
(pwdLastSet=0)
```

`Group attribute`: LDAP attribute which contains the user's group list (example: memberOf)

`Mobile attribute`: LDAP attribute which contains the user's telephone number. This will be used by OTP features

`Email attribute`: LDAP attribute which contains the user's email address. This will be used by OTP features

## Group settings

From this tab you will have to configure settings related to user groups. Basically it consist of defining where are located your groups branches within your LDAP directory.

`Group search scope`: The LDAP search scope to use when searching for a group (base, one level or all subtree) in your LDAP directory

`Group DN`: The starting point of your LDAP server to use when searching for groups (ex: OU=Groups) in your LDAP directory

`Group Object classes`: The list of LDAP Object Classes (schemas) to assign to new Group entries, when created through Vulture (leave defaults unless you know what you do)

`Group attribute`: The LDAP group's identifier

`Group search filter`: The LDAP filter to use when searching for a group in your LDAP directory

`Member attribute`: LDAP attribute used to reference a user DN within a LDAP group (example: member)