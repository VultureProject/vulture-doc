# WebGUI - Menu "Applications / Backend settings"

From this view you can edit the settings of a specific backend server.

Multiple modes are available when creating a backend :

 - **TCP** : Create a TCP HAProxy backend
 - **HTTP** : Create an HTTP HAProxy backend
 
Depending on which mode you chose, configuration settings differ.


## General parameters

`Enable backend` : You can enable or disable your backend.

`Friendly name` : Here you can specify a friendly name for your backend. You cannot have multiple backends with the same name.

`Mode` : Here you chose a mode for your backend :

 - **TCP** (backend use TCP protocol)
 - **HTTP** (backend use HTTP protocol)

`Timeout connect` : Configure the allowed connect timeout (in ms) after which HAProxy will end new connection.

`Timeout server` : Set the maximum inactivity time on the server side.

`Tags` : Friendly tags.


## Servers


Here you can configure the servers.

`Balancing mode` : 

- **RoundRobin**
- **Static RoundRobin**
- **Least Conn**
- **First server**
- **Source IP based**
- **URI based**
- **URL param based**
- **Header based**
- **Cookie based**

`Servers directory` : Root of the url when forwarding to the servers

For each row, you can configure the following parameters (depends on the protocol used) :

- **Target address** : Select the IP address you want to point to.
- **Port** : Configure the port you want to point to.
- **Socket** : Select the UNIX socket you want to point to.
- **TLS Profile** : Here you can select a [TLS Profile](../global_config/tls.md) for the server.
- **Weight** : Set a weight parameter for the balancing method.
- **Source** : Configure a source IP addresse.


## Custom configuration

Via this tab, you may declare custom HAProxy directives. These directives will be placed within the [Backend] section of HAProxy configuration file related to the current Server.


## Specific settings for HAProxy Server Modes

Depending on which server mode you chose, configuration settings differs.
**See below for the specific configuration settings**

### TCP server mode specific parameters

`TCP Keep alive` : Activate the HAProxy's TCP keep alive option.

`Timeout` :  Time for HAProxy to keep the TCP tunnel open.

`TCP health check` : Enable the health check for this backend.

`Close the connection cleanly` : Allow HAProxy for sending a FIN packet instead of RST.

`Message to send` : String sent to the server after connection established.

`TCP Health Check expected` : Expected string sent by the server, can be :

 - **None**
 - **Response content contains**
 - **Response content match regex**
 - **Response binary contains**
 - **Response binary match regex**
 - **Response content does not contain**
 - **Response content does not match regex**
 - **Response binary does not contains**
 - **Response binary does not match regex**

`TCP Health Check interval` : Time between each health check.

### HTTP server mode specific parameters

`Accept invalid HTTP response` : Even malformed HTTP response will be handled.

`Send source ip in` : Header name where source IP will be placed.

`Except for` : IP that will not be placed in the header mentionned above.

`HTTP Keep alive` : Activate the HAProxy's HTTP keep alive option.

`Timeout` :  Time for HAProxy to keep the HTTP connection open.

`HTTP health check` :  Enable the health check for this backend.

`Header select` : Name of the inserted header.

`Header value` : Value of the inserted header.

`Close the connection cleanly` : Allow HAProxy for sending a FIN packet instead of RST.

`HTTP Health Check expected` : Expected answer sent by the server, can be :

 - **Status code is**
 - **Status code match regex**
 - **Response content contains**
 - **Response content match regex**
 - **Status code different**
 - **Status code does not match regex**
 - **Response content does not contain**
 - **Response content does not match regex**

`HTTP Health Check interval` : Time between each health check.
