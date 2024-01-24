# WebGUI - Menu "System / Cluster config"

From this menu you can manage the global configuration of the Vulture Cluster. Remind that Vulture is **always** running as a cluster of 1 to any nodes. It allows Vulture to easily scale by adding new nodes whenever needed.

Nodes are managed from the [Nodes Config](node.md) menu.

## General

Vulture is multi-tenant and you can host and run services that are dedicated to a tenant and isolated from other tenants.
This is useful, for example, in logs services : You will be able to add special tags and tenant-specific information into the logs.

`Internal tenants config` : This parameter let you choose the default tenant configuration to apply anywhere in the Vulture configuration when no specific tenant is selected. Tenants are managed from the [Tenants Config](tenant.md) menu.

`vlt-adm SSH authorized_keys` : You can copy / paste the ssh-ed25519 public key of the vlt-adm account into this textarea. This allows you to log in on Vulture via SSH using an SSH key, previously generated via ssh-keygen -t ed25519.

`Redis cluster password` : This field is used by the local Redis cluster to improve security and may be usefull in case of Redis exposition.

## Network services

From this menu you can configure some global parameters related to network services.

`SMTP server` : Vulture will use this SMTP server whenever it has to send an email. Emails may be send by the underlying HardenedBSD system (cronjob, audit check, ...) as well as by Vulture for specific purposes (eg: Sending an OTP code via email). You may configure the local postfix service (/usr/local/etc/postfix/main.cf) and choose **127.0.0.1** as SMTP server here if you do not have existing SMTP relays in your organisation.

`Allowed sources for SSH connexion` : By default Vulture will accept SSH connexion from anywhere (**any** keyword). Here you can specify a whitelist of IP addresses or hostnames and Vulture will block SSH connexion from everywhere except those addreses.

**Be careful not denying yourself** where configuring this options.

`Allowed sources for GUI connexion` : By default Vulture will accept HTTPS connexion on its Web UI (TCP/8000) from anywhere (**any** keyword). Here you can specify a whitelist of IP addresses or hostnames and Vulture will block HTTP connexion from everywhere except those addreses.

**Be careful not denying yourself** where configuring this options.

`Packet Filter Whitelist` : Vulture won't filter any network trafic originated from the sources declared here. The corresponding pf rules (/usr/local/etc/pf.conf) is :
```
pass in quick from <vulture_whitelist>
```

`Packet Filter Blacklist` : Vulture will drop any network trafic originated from the sources declared here. The corresponding pf rules (/usr/local/etc/pf.conf) is :
```
block in quick from <vulture_blacklist>
```

**Note :** This dropped trafic won't be logged by firewall, to prevent DOS.

**Note :** It can be usefull to whitelist your local IP to prevent blacklisting from Vulture
```
sudo pfctl -t vulture_blacklist -T flush; sudo pfctl -t vulture_whitelist -T add <My IP>
```

## REST API

Vulture is fully manageable via REST API.
Please have a look at the [SWAGGER DOCUMENTATION](../api.md).

Here you can defined the expected API Key to access REST Endpoint.
Be sure to use something **robust** if you change it, by default Vulture will generate a 16 bytes ASCII random key.

## Authentication

By default vulture uses its **internal** MongoDB repository for user authentication.
You may want to use a corporate LDAP to authenticate users on Vulture GUI, so here you can define the LDAP server to use.

You can add LDAP configurations from the /authentication/ldap/ menu.

## SSO

Here you can define technical parameters related to the SSO features of Vulture, such as cookies and token Names.

`Header name for OAuth2 authentication` : Defaults to **X-Vlt-Token**. It is the name of the HTTP Header that Vulture will read to get the User OAuth2 access token, when using oauth2 authentication in Vulture for Web application.

`Portal cookie name` : Defaults to **random value**. It is the name of the main session cookie used by Vulture when it authenticate a user on is Web Portal.

`Public token` : Defaults to **random value**. The Vulture Web portal, used for user authentication, is available through a specific URL. This URL is not "predictable" as Vulture use this public token to "randomize" it. You way override this random value here.

## Logs settings

`Retention period of internal database logs` : Vulture store logs into the Internal MongoDB database. Here you can define the retention period, in seconds. Default is **86400** (1 day).

`Logs encryption PEM certificate` : Not supported yet.