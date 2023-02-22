# Kerberos Repository

## Overall operation

Vulture is able to authenticate a user against a Kerberos server, via its username and password. 

The feature, implemented into Vulture's portal, relies on the **PyKerberos** Python package: "This package is a high-level wrapper for Kerberos (GSSAPI) operations. The goal is to avoid having to build a module that wraps the entire Kerberos.framework, and instead offer a limited set of functions that do what is needed for client/server Kerberos authentication based on http://www.ietf.org/rfc/rfc4559.txt".

When connecting to the portal, the user will be prompted to enter its login and password. Authentication may be transparent (no user prompt) if proper configuration has been done in your IT infrastructure. Indeed, Vulture is able to deal with HTTP header "Autorization: Negotiate" to automatically retrieve the kerberos ticket from the client's web browser.


## Settings

`Name`: A friendly name to identify the repository. It has to be unique.

`Kerberos realm`: Name of the domain over which your Kerberos authentication server has the authority to authenticate user.

`Kerberos domain realm`:  DNS domain name related to your Kerberos realm.

`KDC(s)`: IP Address or hostname (must be resolvable by Vulture) of your Kerberos KDCs.

`Admin server`: IP Address or hostname (must be resolvable by Vulture) of your Kerberos admin server.

`KRB5 Service name`: This is the **Kerberos service principal name** used by your KDC.

`Service keytab`: This is the keytab file provided by your KDC.
