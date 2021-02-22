## LDAP

### Overview

LDAP or Active Directory can be used to authenticate users.

- `Repository Name`: Friendly name that will be display in the GUI.
- `Host`: IP address or hostname of the LDAP server.
- `Port`: LDAP TCP port number.
- `Protocol`: LDAPv2 or LDAPv3 - depending of your LDAP server version.
- `Encryption scheme`: Can be none, LDAPS or start-TLS.
- `Service account DN`: The service account DN to use to bind to LDAP server;
- `Service account Password`: The associated password.
- `Base DN`: The search suffix.


The `service account DN` is used by Vulture to perform a full bind onto the LDAP server. This account will be used by Vulture to look for users as well as for 'special' operation such as password reset.

You cannot save your LDAP configuration without clicking on "TEST LDAP connection". This ensures that Vulture can bind onto your LDAP server using the provided login and password. In case of a failure during the test process, please check:
 - Network filtering: Check that Vulture can contact you LDAP server on the provided IP address and port.
 - Wrong DN or password.
 - TLS issue: The LDAP server certificate may not been trusted by Vulture.

### User settings

This tab is used to tell Vulture where it can find users for authentication.


*   `User search scope` : This is the starting point of an LDAP user search and the depth from the base DN to which the search should occur.
    *   **subtree**: Search of all entries at all levels under and including the specified base DN.
    *   **one**: Search of all entries one level under the base DN - but not including the base DN and not including any entries under that one level under the base DN.
    *   **base**: Search only the entry at the base DN, resulting in only that entry being returned.
*   `User DN` : This is the starting point of the users LDAP search. Base DN is automatically added after it.
*   `User attribute` : LDAP **attribute** that references a user, typically this is `cn` or `uid` or `SamAccountName` depending of your LDAP type and configuration. When you try to login on Vulture, the login attribute of the user will be mapped to this LDAP attribute.
*   `User search filter` : LDAP **filter** that is used during the LDAP search to find users. Try to make a restrictive LDAP filter to improve security. For example: `(objectclass=person)`
*   `Account locked filter` : LDAP **filter** used by Vulture to check if a user account is locked.
*   `Need change password filter` : LDAP **Filter** used by Vulture to check if a user must change its password.
*   `Group attribute` : LDAP **attribute** used by Vulture to retrieve the groups whose user belongs to. For example: `memberOf`.
*   `Mobile attribute` : LDAP **attribute** used by Vulture to get the user's phone number. This is used by the One Time Password authentication feature.
*   `Email attribute` : LDAP **attribute** used by Vulture to get the user's email address. This is used by the One Time Password authentication feature.

When clicking on "Test User authentication settings", you can test if your settings are good. Vulture will prompt for a login and a password and will try to fetch user's group, email and phone number.
If authentication is unsuccessful, the error message should indicates the reason. Usually this is because of an authentication failure or wrong LDAP filters / attributes.

### Groups settings

*   `Group search scope` : This is the starting point of an LDAP group search and the depth from the base DN to which the search should occur.
    *   **subtree**: Search of all entries at all levels under and including the specified base DN
    *   **one**: Search of all entries one level under the base DN - but not including the base DN and not including any entries under that one level under the base DN
    *   **base**: Search only the entry at the base DN, resulting in only that entry being returned
*   `Group DN` : This is the starting point of the groups LDAP search. Base DN is automatically added after it.
*   `Group attribute` :  LDAP **attribute** that references a group, typically this is `cn` or `gid` depending of your LDAP type and configuration.
*   `Group search filter` : LDAP **filter** that is used during the LDAP search to find groups. Try to make a restrictive LDAP filter to improve security. For example: `(objectclass=groupOfNames)`
*   `Members attribute` : LDAP **attribute** that is used to get members of a given groups. For example: `member`

When clicking on "Test group settings", you can test if your settings are good. Vulture will prompt for a group name and, if found, will return the users contained in the group