# WebGUI - Menu "Identity Providers"

From this menu you can manage IDentity Providers (IDP) for Vulture. Identity providers are used by Vulture's [Authentication Portals](../portal/portal.md) to authenticate users.

Vulture supports the following identity providers :

 - **[LDAP](ldap.md)** : To authenticate users against an LDAP / Active Directory server
 - **[Kerberos](kerberos.md)** : To authenticate users using the Kerberos protocol
 - **[Radius](radius.md)** : To authenticate users using the Radius protocol
 - **[OpenID federation](openid.md)** : Vulture IDP can rely on an external OpenID compliant provider. From this menu you can create a IDP that will verify user authentication against one of the supported OpenID providers : Google, Azure, Facebook, Github, Keycloak, Gitlab, LinkedIn, Microsoft Azure AD, Generic OpenID Connect, Login.gov, Nexcloud, DigitalOcean, Bitbucket, Gitea, Digital Pass

From this menu, you will also be able to manage various settings and features related to user authentication and security enforcement :

 - **[MFA & OTP](mfa.md)** : From this menu you can configure MFA in Vulture. This will be use by Authentication Portal as an additional identity verification
 - **[Time-based OTP profiles](totp.md)** : From this menu you can manage TOTP profiles of registered users
 - **[Users' scopes](scopes.md)** : From this menu you can manage attributes ("scopes") associated to authenticated users, via a rule builder. These attributes may be passed by Vulture to the application beckend (via an HTTP Header for example)
 - **[SSO Profiles](sso_profiles.md)** : From this menu you can manage SSO learning profiles stored by Vulture
