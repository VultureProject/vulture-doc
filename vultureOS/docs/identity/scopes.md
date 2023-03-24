# Users' Scopes

From this menu you can declare policies to manage claims returned by external OpenId Providers or generated from internal authentication repositories.

`Name` is a unique friendly name that refers to the policy.

You can click on "Add an entry" to add rules that will alter claims returned by your OpenID Provider. Using a WISIWIG interface you can add `IF` conditions on existing claims and `THEN` trigger actions to set or append values to the user's scope.

You have several sources available to get data and match conditions from:

 - `Constant` allows to define constant text taken verbatim from configuration to match on or to be set in returned claims
 - `Claim Attribute` will apply to claims recovered from Users' tokens returning from successful IDP authentication. Those claims attributes will depend on the external IDP's configuration
 - `Repository Attribute` will apply to attributes recovered from internal repositories' successful authentication (LDAP, Kerberos...). Those claims attributes will depend on the internal repository's configuration


You'll also be able to do advanced things like merging values together in a list, taking values conditionaly from external IDPs or internal repositories (if your portal supports both), and so on...
