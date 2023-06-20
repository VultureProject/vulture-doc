# OpenID Identity Provider

## Overall operation

You can configure an authentication portal that will authenticate users against an external OpenID compliant provider. Vulture has been tested with the following providers, but any other OpenID compliant provider should works :

- Google
- Azure
- Facebook
- Github
- Keycloak
- Gitlab
- LinkedIn
- Microsoft Azure AD
- Generic OpenID Connect
- Login.gov
- Nexcloud
- DigitalOcean
- Bitbucket
- Gitea
- Digital Pass


**Note** : After you create a OpenID repository, it will appear in the OpenID Repository list. You will have **important informations** in the "Additional infos" columns, such as the **Callback URL**. The Callback URL has to be configured in your OpenID Provider' settings so it can redirect the user back to the Vulture portal after authentication.

## Settings

Settings are the same for any provider :

`Name`: A friendly name to refer to the OpenID repository. It has to be unique.

`Provider`: This field is not used by Vulture. You can use the selector to categorize your OpenID provider so it will be easier for you to read and retrieve your OpenID IDP within the OpenID repository list.

`Provider URL`: The FQDN / URL of your OpenID provider. Vulture will redirect the user to this URL to authenticate the user from the portal.

`Provider Client ID`: The client ID that Vulture will use to contact your OpenID Provider.

`Provider Client Secret`: The client Secret that Vulture will use to contact your OpenID Provider.

`Token scope`: Declare here the claims type you want to retrieve from your OpenId Provider (example: "openid" or "profile")

`User's scope`: 

This selector allows you to choose the way Vulture will extract and use/modify/delete the claims obtained from the OpenID provider. Vulture provides a default "Retrieve all claims" which will retrieve all existing claims obtained from the provider. You may define custom rules to alter these claims from the [User's Scope](scopes.md) settings.

Note that in the [Portal Configuration](../../portal/portal/#main-settings) you may use another User's Scope settings to alter claims a second time. This offers you a lots of possibility to alter claims that will be sent to application backends.