# WebGUI - Menu "Identity Providers"

From this menu you can manage IDentity Providers repositories for Vulture. Identity providers are used by Vulture's [Authentication Portals](../portal/portal.md) to serve as authentication sources to authenticate users.

Vulture supports the following repository types :

 - **[LDAP](ldap.md)** : To authenticate users against an LDAP / Active Directory server
 - **[Kerberos](kerberos.md)** : To authenticate users using the Kerberos protocol
 - **[Radius](radius.md)** : To authenticate users using the Radius protocol
 - **[OpenID federation](openid.md)** : Vulture IDP can rely on an external OpenID compliant provider. From this menu you can create a IDP that will verify user authentication against one of the supported OpenID providers : Google, Azure, Facebook, Github, Keycloak, Gitlab, LinkedIn, Microsoft Azure AD, Generic OpenID Connect, Login.gov, Nexcloud, DigitalOcean, Bitbucket, Gitea, or Digital Pass

From this menu, you will also be able to manage various settings and features related to user authentication and security enforcement :

 - **[MFA & OTP](mfa.md)** : From this menu you can configure MFA policies in Vulture. They will be used by Authentication Portals as an additional identity verification
 - **[Time-based OTP profiles](totp.md)** : From this menu you'll be able to visualize and manage TOTP profiles for registered users
 - **[Users' scopes](scopes.md)** : From this menu you can manage attributes ("scopes" and "claims") associated with authenticated users, via a rule builder. These attributes may be passed by Vulture to the application backend (via an HTTP Header for example) or be contained in the User's Oauth tokens.
 - **[SSO Profiles](sso_profiles.md)** : From this menu you can manage SSO learning profiles stored by Vulture
