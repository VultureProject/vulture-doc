# WebGUI - Menu "Authentication Portal / Portal"

From this view you can manage authentication portals on Vulture. An authentication portal is responsible for user authentication on Web sites protected by Vulture.

Before creating an authentication portal you need to configure at least one [Authentication repository](../identity/repository.md)

## How to Use
Vulture Portals are divided into 2 different types, those types are explained below.

### Authentication Portals
Authentication portals allow the admin to assign authentication policies to **Workflows**, those policies allow to restrict from a single to multiple endpoints, by associating them to Workflows.  
Those Portals are purely specific to Vulture and cannot be used outside of them, they simply define authentication rules to apply associated with specific Workflows/endpoints. They allow to define authentication repositories, session durations, access policies and user rights, Single Sign-On and much more.  
Authenticated sessions are handled between Vulture and Users with a portal cookie, this cookie's name is defined in the [Global Cluster's Config](../global_config/cluster.md/#sso) and can be changed. The cookie is mapped on the endpoint's **domain**, meaning that several workflows configured on the same domain or subdomain. For example, *www.app1.mydomain.com*, *www.app2.mydomain.com*, *test.mydomain.com* will all have the same portal cookie session with Vulture, mapped on `.mydomain.com`, . This *lax* mapping of cookie allows to profit from SSO and cross-Workflow authentication, meaning that a user authenticated through a specific repository allowed by an Authentication Portal A will be able to connect seamlessly to the Authentication Portal B provided the same Repository is also allowed by this Portal : Authentication B will be able to use the global session's cookie to get the User's authentication data and automatically connect them to Workflow B without asking for their credentials again!  

Authentication Portals are configurable to allow one or more [Authentication Repositories](../identity/repository.md), There are several configuration possibilities:

- Portal allows **one internal Repository** -> an authentication form is available on the Portal, this form will try to authenticate the User directly on the allowed Repository
- Portal allows **more than one internal Repository** -> an authentication form is still available on the Portal, it will try to use the provided User's credentials directly on all the internal Repositories in turn, until it finds one that matches or tries them all without success
- Portal allows **external Repositories** ([OpenID Repositories](../identity/openid.md)) -> the Portal's form will include link(s) to redirect the User to the external authentication authorities, the user will be able to connect with them and come back to the Authentication Portal once it's done (provided the external authority allows the Authentication Portal's redirect URI)
- **All of the above** -> the Portal's authentication form will include a credentials prompt **and** redirection link(s), the user will be able to choose either method to connect (depending on the repository containing its account) to authenticate


### IDP Portals
This kind of Portal is a little bit different, although being named a "Portal", the IDP is not used for the same reasons and with the same configuration.

- IDPs are not **linked to Vulture Workflows**
- They are **directly linked** to a **Vulture Listener** and a specific **FQDN**
- They are always serving **OpenID Connect APIs** and conform with **OpenID authentication methods**
- As they're valid [Oauth2 Authorization Servers](https://auth0.com/docs/authenticate/protocols/oauth), IDP Portals can be used with Vulture, but can also be used with external applications
- They do not use the same session cookie name: its name is generated at random for each created IDP, and can be manually changed on the GUI (through the *Session cookie name* parameter)

As you probably understood, IDP Portals define generic Oauth2 Authorization Servers, compatible with OpenID Connect. They can be used alongside Vulture Authentication Portals ([OpenID Connectors](../identity/openid.md) will be created for ease of use on Vulture every time a new ID is created) or can be used as regular Authorization Servers with your existing applications and stack.  
Vulture IDP portals currently provide a subset of Grant Flows usually supported by Oauth2 Authorization Servers:

- [Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow): the most frequently used Grant Type, allows to connect regular server-side web apps
- [Authorization Code Flow with PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce): a variant of the `Authorization Code Flow` grant Type, allows to replace the insecure Implicit Grant FLow by securely connecting with client-side applications while keeping User's credentials secure
- [Refresh Token](https://auth0.com/docs/secure/tokens/refresh-tokens): allows an application to refresh his access token and extend its session's duration

Vulture does not currently support other Grant Types (such as *Client Credentials* or *Device Flows*), and won't support some of them (*Implicit Flow*) by choice.  
Other features not available at the moment include:

- **JWT Tokens**

Feel free to [open issues on our Github](https://github.com/VultureProject/vulture-gui/issues) if you'd like new features on IDP Portals.


### Navigating protected endpoints
When protected by Authentication Portals, Vulture Workflows will check every request made through them to authorize or redirect the client making them. Some behaviours are explained below.

#### Through portal session

When authenticated through a regular Portal's Form, a User is authenticated through their **portal session's cookie**. This cookie contains the User's generated scopes and claims (if configured), the repo they authenticated with, their oauth token(s) and technical information on the session.<br>
Although the session's timeout can be infinite by activating a parameter (see [Configuration](#main-settings) below), activating Oauth2 on the Authentication Portal will generate Bearer tokens, whose timeout cannot be extended. In those cases, you might see two 307 redirections happen at regular intervals while you navigate with your browser: those redirections will allow the Authentication Portal to regenerate a new Bearer Token with your session, and should not impact your regular navigation experience (although slowing down some requests from time to time). If you wish to decrease the amount of those refresh, you can simply increase the validity of the Oauth2 tokens in the [Oauth2 tab](#oauth2), but bear in mind that will also have security implications.<br>
When the User is not authenticated, the Authentication Portals will intercept the request and return the authentication form instead. They'll also potentially rewrite the URL to hit the base of the Workflow. For example, when trying to access the workflow with FQDN = *app.mydomain.com* and base directory */test/* on the URL *https://app.domain.com/test/user/page*, the URL will be rewritten to *https://app.domain.com/test/?redirect_url=/test/user/page*)

#### Through Headers

Another means to authenticate through restricted Vulture Workflows is to use **headers**. This method is frequently used when there is a need for **stateless requests** made by **client-side applications or scripts** on REST APIs.<br>
Vulture currently supports 2 headers: 

- `Authorization`: this is the regular Header to pass authentication information, Vulture will check the **Bearer** type tokens with a valid Bearer token provided by any Vulture IDP or Authentication Portal
- `X-Vlt-Token`: this is a Vulture3 legacy header, still available to use on Vulture4 Portals

When using a header, Vulture will validate the value with all its known bearer tokens (scoped on authorized repositories only), and will either pass the request to the underlying Backend or reject the request with a 401.

**Note**: *JWTs are currently not supported by the Vulture Portals, we plan on implementing them in the future*

## Configuration

### Main settings

From this tab you can manage global properties of the Portal.

`Name` : A friendly name to refer to the portal. It has to be unique.

`Enable Identity Provider` : If checked, Vulture will act as an IDP Provider. In this mode, external users and applications may authenticate on Vulture to obtain a **Bearer Token**. Vulture will then be able to control the provided bearer token and let the HTTP request pass. User will have to provide a user and a password that will be verified against the configured **Authentication repository**. In this mode, the Portal is self-sufficient and won't be available in Workflows' associations, you'll have to link your IDP directly with a Listener and a specific FQDN.

 - `FQDN` : This is where you define the FQDN of the Identity Provider (only available with this mode). This FQDN is supposed to be resolved by a DNS and to point to the IP Address and Ports defined bellow
 - `Listen IDP on` : Here you choose the listener on which Vulture will bind the Identity Provider.

**Note**: Whenever you configure Vulture to act as an Identity Provider, the **OAuth2 provider** is automatically enabled.
**Note**: ONLY LDAP REPOSITORIES ARE SUPPORTED WITH IDENTITY PROVIDERS

`Authentication repositories` : Here you associate one or more authentication sources to the authentication portal. You have 2 types of repositories : "internal" and "external" ones.

- Internal repositories will allow the portal to directly check your user/password with the repository and authenticate you if one of them validates your credentials. Those repositories include Internal django repos, LDAP, Kerberos, Radius and the likes.
- External repositories will make the portal redirect you to those repositories (typically IDP providers) and delegate authentication to them. The authentication result will still be checked by the portal after returning to it. You'll have to go to [OpenID Federation](../identity/openid.md) to configure them.

`Authentication type`: Vulture supports 3 authentication prompts to authenticate users:
 - **HTML Form**: The user will be prompted for a login and a password via the help of an HTML form. You can configure the look and feel of this HTML form via a [HTML Template](templates.md) containing your custom images, css, js....
 - **Basic Authentication**: Vulture will send a 401 HTTP response expecting the client to authenticate via the appropriate "Authorization: basic" HTTP header
 - **Kerberos Authentication**: Same as basic Authentication, but using the autonegotiate kerberos protocol between the web browser and Vulture. Note that this mode requires specific configuration in your IT environment to work properly.

`User's scope`: When a user authenticates, Vulture may associate "attributes" to the user and propagate them to the application backend for any useful purpose. 

 - When Vulture is configured to authenticate users against an **external OpenID provider**, these attributes, also named "scopes" and "claims" are present within the authentication token created by the provider. If you choose the default "Retrieve all claims", Vulture will pass the existing claims in the token. You may choose a custom policy, previously created from the [User's scope menu](../identity/scopes.md). Thanks to this policy, Vulture will ADD/REMOVE/MODIFY the scopes associated to the token.
 - When Vulture is configured to authenticate users against an internal repository, the default "Retrieve all claims" won't do anything. You may however use a custom policy to create specific attributes based on user properties, depending on your needs.

`Session cookie name`: this parameter only appears for IDP portals and allows configuration of a specific session cookie name for every IDP portal, preventing session clashes between different IDPs and Application Portals (which would be detrimental to the use of IDPs, as opposed to Application Portals). Its value is not set by default, but will be assigned a random 8-character value for each new IDP portal if left empty.

`Disconnect timeout`: Vulture holds a global session with the user, and will destroy it after the defined timeout. The user will have to re-authenticate to access backend applications again. This setting allows to force the user to be disconnected after an arbitraty period of time. Generally you don't want this behaviour, *so be sure to enable the next option*.

If `Reset timeout after a request` is checked, Vulture will reset the timeout counter whenever it receives a request (the user navigates on the endpoint). So the user will never be disconnected as long as it send requests to Vulture. After an inactivity period (no request sent) greater than the configured Disconnect timeout (see above), the user will be disconnected. *This is the default behaviour*.

`Enable captcha` : If enabled, Vulture will display a simple Captcha after the authentication process. The user will have to complete the challenge before being able to access backend applications. 

### OTP

Here you may choose an optional [MFA & OTP configuration](../identity/mfa.md) if you want to enable MFA for security enforcement. After the user has succesfully passed the authentication phase, he will have to validate the MFA challenge.

### Disconnect

When a user authenticates on Vulture, two sessions are created:
 - A global `portal session`, associated to the user with Vulture. Thanks to this session, Vulture is able to perform SSO : Vulture will not ask a user to authenticate again on a repository on which he is already authenticated.
 - An `application session`, associated to the backend the user wants to access to.
 
As an example, if a user has accessed 3 applications, via the same authentication repository, he will have :
 - 1 portal session
 - 3 application sessions

If the user wants to access a 4th application protected by the same authentication repository, Vulture won't ask anything and will let the user access the application.

If a user disconnects itself from a backend application, the corresponding Vulture's application session won't be destroyed until the configured Timeout. However, you can tell Vulture, via the `Disconnect regex` regular expression to detect the disconnection from the backend application. *The regular expression applies to an HTTP URL*. When matched, Vulture will destroy the corresponding application session.

**Note**: When the user disconnects from the backend application, even if the Vulture's session is destroyed, he can still access the application because Vulture will trigger the SSO **thanks to the remaining portal session**. If you want to prevent SSO, please enable `Destroy portal session on disconnect` (see below). 

`Display the disconnect message from template` : If enabled, Vulture will display an HTML page, defined from the selected [HTML Template](templates.md), after the user's disconnection has been caught by the regex (see above).

`Destroy portal session on disconnect` : If enabled, Vulture will destroy both the application session and the portal session after a disconection from the application. User will have to re-authenticate completely to access any endpoint they were connected to.

### Identity Provider

**Note** : When Vulture acts as an Identity provider, it can only map to LDAP authentication repositories!

When Vulture is configured as an IDP Provider, it also exposes REST APIs to manage users. See [Swagger API Documentation](../api/authentication/idp/idp.yml) for details.

From this menu, when a user is created on this IDP, it will be automatically added into the group defined in `Add users in group (ldap)`. Here you just have to define the name of the group (The group's DN must be properly defined in the [LDAP Repository](../identity/ldap.md) settings). Vulture will add the group's DN to the "memberOf" attribute of the user.

`Update group members (ldap)`: If checked, Vulture will also update the group defined before, by adding a new "member" entry that points to the User's DN.

### OAuth2

`Enable OAuth2 provider` : Enable or disable the Vulture's OAuth2 responder features. 

**Note**: 
 - You **MAY** enable this feature for any authentication portal
 - The feature **is automatically enabled** if `Enable Identity Provider` is checked from the main settings (aka. enabled for IDP providers)

`Application ID (client_id)` : This is the application ID (or client ID) defined by Oauth2 specifications. It is automatically generated by the GUI and cannot be modified.

`Secret (client_secret)` : This is the application secret (or client secret) defined by Oauth2 specifications. It is automatically generated by the GUI and cannot be modified. This information MUST stay confidential and staya between the IDP and connected external (backend) applications.

`Redirect URI(s)` : This is an exhaustive list of allowed redirection URIs, this represents the allowed applications' URIs to redirect the authenticated user to once the authentication is finished and validated.

`OAuth2 tokens timeout` : This is the expiration time of the tokens created and associated with the authentication request. This timeout is static and non-updatable.

`Enable OAuth2 refresh token` : This option enables the creation of a refresh token which can be used to renew access tokens without reauthentication.

`Enable refresh token rotation` : This option sends another refresh token after each use of the currently valid refresh token. The predecessor is invalidated and cannot be reused. 

`History of expired tokens` : If this parameter is activated (>1), Vulture will remember the last N refresh tokens and will invalidate all refresh/access tokens if any old refresh token is reused, preventing replay attacks.

### SSO Forward

Once a user is authenticated on a Vulture portal, it can access the backend application, but it will sometimes have to manually login on the application by supplying new credentials...

By enabling **SSO Forward**, Vulture can automatically authenticate the user on the backend application after authenticating with the authentication portal. Indeed, Vulture is able to:
 - Propagate the credentials provided by the user to the protected application. We call that **Autologon** (same login/password as the ones given to the portal)
 - Propagate other credentials, previously learned and stored by Vulture. We call that **SSO Learning**
 - Propagate other information, recovered from scopes and claims created from authentication (see [User's scopes](../identity/scopes.md))

**Note**: When SSO forward is enabled, even if a user disconects from an application, it will automatically be logged as soon as he comes back.

`Enable sso forward`: Check to enable the SSO Forward feature

`Sso forward type`:
  - **HTML Form**: Vulture will send credentials via an HTTP POST request to the backend application
  - **Basic Authentication**: Vulture will send credentials via an "Authorization: Basic" Header to the backend application
  - **Kerberos Authentication**:  Vulture will send credentials via an "Authorization: Negotiate" Header to the backend application

`Sso forward content type`: Define the value of the Content-Type HTTP header sent to the backend application during the SSO forward HTTP request.

`Sso forward timeout`: The SSO Forward request will fail in timeout after this amount of seconds between the Vulture's request and the response from the backend application.

`Sso forward url`: The URL of the backend application that will be called by Vulture to send user's credentials. The URL **MUST** starts with "http://" or "https://".

`WIZARD autoconfiguration`: Once you have defined the login URL, click on the **Wizard button** to configure the SSO Forward. The wizard will call the Forward URL and display all the form fields it has detected within the login page of the application. You need to configure every field needed for the authentication process of the backend application. For every detected field, you must define the type of the field as well as the value that will be sent.

Here are the supported field types :

 - **Dynamic Value**: Vulture will send the field with the existing value coming from the backend application (use it for CSRF token for instance) 
 - **OAuth2 Token**: Vulture will send the User's OAuth2 token in the field
 - **Autologon User**: Vulture will send the login provided by the user on the Authentication portal (only possible when using internal authentication repositories)
 - **Autologon Password**: Vulture will send the password provided by the user on the Authentication portal (only possible when using internal authentication repositories)
 - **Custom Text Value**: Vulture will send the custom value you have defined here
 - **Learning**: The first time the user connects to the application, Vulture will ask for its value - and will store it for future use (TEXT INPUT, unencrypted).
 - **Learning Secret**: The first time the user connects to the application, Vulture will ask for its value - and will store it for future use (PASSWORD INPUT, ecnrypted).
 - **Repository attribute**: Will use one of the attributes returned by the internal authentication repository
 - **Do not send**: The field will be ignored and thus not sent to the backend application


`SSO forward status`: Either "configured" or "Not configured". It indicates if the wizard has been launched and configured. You can hover over it with the mouse to see current configuration once configured.
