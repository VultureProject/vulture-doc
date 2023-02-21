# WebGUI - Menu "Authentication Portal / Portal"

From this view you can manage authentication portals on Vulture. An authentication portal is responsible of user authentication on Web sites protected by Vulture.

Before creating an authentication portal you need to configure at least one [Authentication repository](../identity/repository.md)

## Authentication portal / User Authentication

### Main settings

From this tab you can manage global properties of the Portal.

`Name` : A friendly name to refers to the portal. It has to be unique.

`Enable Identity Provider` : If checked, Vulture will act as an IDP Provider. In this mode, external users and applications may authenticate on Vulture to obtain a **Bearer Token**. Vulture will then be able to control the provided bearer token and let the HTTP request pass. User will have to provide a user and a password that will be verified against the configured **Authentication repository**

 - `FQDN` : This is where you define the FQDN of the Identity Provider. This FQDN is supposed to be resolved by a DNS and to point to the IP Address and Ports defined bellow
 - `Listen IDP on` : Here you choose the listener on which Vulture will bind the Identity Provider.

**Note**: Whenever you configure Vulture to act as an Identity Provider, the **OAuth2 provider** is automatically enabled.
**Note**: ONLY LDAP REPOSITORIES ARE SUPPORTED WITH IDENTITY PROVIDER MODE

`Authentication repositories` : Here you associate one or more identify providers to the authentication portal. Vulture will verify user's identity against these repositories. Vulture will try all selected repositories and stop as soon as a valid authentication is performed

`Authentication type`: Vulture supports 3 authentication method to authenticate users:
 - **HTML Form**: The user will be prompted for a login and a password via the help of an HTML form. You can configure the look and feel of this HTML form via a [HTML Template](template.md) containing your custom images, css, js....
 - **Basic Authentication**: Vulture will send a 401 HTTP response expecting the client to authenticate via the appropriate "Authorization: basic" HTTP header
 - **Kerberos Authentication**: Same as basic Authentication, but using the autonegotiate kerberos protocol between the web browser and Vulture. Note that this mode requires specific configuration in your IT environment to work properly.

`User's scope`: When a user authenticates, Vulture may associate "attributes" to the user and propagate them to the application backend for any useful purpose. 

 - When Vulture is configured to authenticate users against an **external OpenID provider**, these attributes, also named "scopes" are present within the authentication token created by the provider. If you choose the default "Retrieve all claims", Vulture will use the existing claims in the token. You may choose a custom policy, previously created from the [User's scope menu](../identity/scopes.md). Thanks to this policy, Vulture will ADD/REMOVE/MODIFY the scopes associated to the token.
 - When Vulture is configured to authenticate users against a classical identity provider, the default "Retrieve all claims" will do nothing. You may use a custom policy to create specific attributes based on user properties.

`Disconnect timeout`: Vulture will destroy the user's session after the defined timeout. The user will have to re-authenticate to access backend applications. This setting allows to force user to be disconnected after an arbitraty period of time. Generally you don't want this behaviour, *so be sure to enable the following option*.

 - If `Reset timeout after a request` is checked, Vulture will reset the timeout counter whenever it receives a request. So the user will never be disconnected as long as it send requests to Vulture. After a inactivity period (no request sent) greater than the configured timeout, the user will be disconnected. *This is the default behaviour*.

`Enable captcha` : If enable, Vulture will display a Captcha (Google reCaptcha) after the authentication process. The user will have to complete the challenge before being able to access backend applications. 

### OTP

Here you may choose an optional [OPT configuration](../identity/totp.md) if you want to enable MFA for security enforcement. After the user has succesfully passed the authentication phase, he will have to succeed in the MFA challenge.

### Disconnect

When a user authenticates on Vulture, two sessions are created:
 - A global `portal session`, associated to the authentication repository. Thanks to this session, Vulture is able to perform SSO : Vulture will not ask a user to authenticate again on a repository on which he is already authenticated.
 - An `application session`, associated to the backend the user wants to access to.
 
As an example, if a user has accessed 3 applications, via the same authentication portal, he will have :
 - 1 portal session
 - 3 applications sessions

If the user wants to access a 4th application protected by the same portal, Vulture won't ask anything and will let the user access the application.

If a user disconnects itself from a backend application, the corresponding Vulture's application session won't be destroyed until the configured Timeout. However, you can tell Vulture, via the `Disconnect regex` regular expression to detect the disconnection from the backend application. *The regular expression applies to an HTTP URL*. When matched, Vulture will destroy the corresponding application session.

**Note**: When the user disconnects from the backend application, even if the Vulture's session is destroyed, he still can access the application because Vulture will trigger the SSO **thanks to the remaining portal session**. If you want to prevent SSO, please disable `Destroy portal session on disconnect` (see below). 

`Display the disconnect message from template` : If enabled, Vulture will display an HTML page, defined from the selected [HTML Template](template.md) after the user's disconnection.

`Destroy portal session on disconnect` : If enabled, Vulture will destroy both the application session and the portal session after a disconection from the application

### Identity Provider

`Reminder` : When Vulture acts as an Identity provider, it must use LDAP repositories only !

When Vulture is configured as an IDP Provider, it exposes REST API to manage LDAP users. See [Swagger API Documentation](../api/authentication/idp/idp.yml) for details.

From this menu, when a user is created on this IDP, it will be automatically added into the group defined in `Add users in group (ldap)`. Here you just have to define the name of the group (The group's DN must me properly defined in the [LDAP Repository](../identity/ldap.md) settings). Vulture will add the group's DN to the "memberOf" attribute of the user.

`Update group members (ldap)`: If checked, Vulture will also update the group defined before, by adding a new "member" entry that points to the User's DN.

### OAuth2

`Enable OAuth2 provider` : Enable or disable the Vulture's OAuth2 responder features. 

**Note**: 
 - You **MAY** enable this feature for any authentication portal
 - The feature **is automatically enabled** if `Enable Identity Provider` is checked from the main settings

`Application ID (client_id)`: #Fixme

`Secret (client_secret)`: #Fixme

`Redirect URI(s)`: #Fixme

`OAuth2 tokens timeout`: #Fixme

### SSO Forward

Once a user is authenticated on a Vulture portal, it can access the backend application, but it will have to manually login on the application by supplying a login, a password or whatever... 

By enabling **SSO Forward**, Vulture automatically authenticates the user on the backend application. Indeed, Vulture is able to:
 - Propagate the credentials provided by the user to the protected application. We call that **Autologon** (same login/password as the one given to the portal)
 - Propagate other credentials, previously learned and stored by Vulture. We call that **SSO Learning**

**Note**: Vulture is also able to send to the application any user attributes created via the `User's scope`menu (see before).
**Note**: When SSO forward is enabled, even if a user disconects from an application, it will be automatically logged as soon as he came back.

`Enable sso forward`: Check to enable the SSO Forward feature

`Sso forward type`:
  - **HTML Form**: Vulture will send credentials via an HTTP POST request to the backend application
  - **Basic Authentication**: Vulture will send credentials via an "Authorization: Basic" Header to the backend application
  - **Kerberos Authentication**:  Vulture will send credentials via an "Authorization: Negotiate" Header to the backend application

`Sso forward content type`: Define the value of the Content-Type HTTP header sent to the backend application during the SSO forward HTTP request.

`Sso forward timeout`: The SSO Forward request will failed in timeout after this amount of seconds between the Vulture's request and the response from the backend application.

`Sso forward url`: The URL of the backend application that will be called by Vulture to send user's credentials. The URL **MUST** starts with "http://" or "https://".

`WIZARD autoconfiguration`: One you have defined the login URL, click on the **Wizard button** to configure SSO Forward. The wizard will call the Forward URL and display all the form fields it has detected within the login page of the application. You need to configure every field needed for the authentication process of the backend application. For every detected field, you must define the type of the field as well as the value that will be sent.

Here are the supported field types :

 - **Dynamic Value**: Vulture will send the field with the existing value coming from the backend application (use it for CSRF token for instance) 
 - **OAuth2 Token**: Vulture will sent the User's OAuth2 token in the field
 - **Autologon User**: Vulture will send the login provided by the user on the Authentication portal
 - **Autologon Password**: Vulture will send the password provided by the user on the Authentication portal
 - **Custom Text Value**: Vulture will send the custom value you have defined here 
 - **Learning**: The first time the user will connect to the application, Vulture will ask for the value - and will store it for a later use (TEXT INPUT).
 - **Learning Secret**: The first time the user will connect to the application, Vulture will ask for the value - and will store it for a later use (PASSWORD INPUT).
 - **Repository attribute**: #Fixme
 - **Do not send**: The field will be ignored and thus not sent to the backend application


`SSO forward status`: Either "configured" or "Not configured". It indicates if the wizard has been launched and configured.
