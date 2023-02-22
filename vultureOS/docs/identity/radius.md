# Radius Repository

## Overall operation

Vulture is able to authenticate a user against a Radius server, via its username and password. 

The feature, implemented into Vulture's portal, relies on the **pyrad** Python package: "pyrad is an implementation of a RADIUS client/server as described in RFC2865. It takes care of all the details like building RADIUS packets, sending them and decoding responses.".

When connecting to the portal, the user will be prompted to enter its login and password and Vulture will verifu the credentials against the Radius server. 

## Settings

`Name`: A friendly name to identify the repository. It has to be unique.

`Host`: The IP address or the hostname (has to be resolvable by Vulture) of the radius server

`Port`: The associated port number

`NAS_ID`:  The radius NAS identifier of the server

`Authentication secret`: The radius shared secret 

`Max retries to authenticate clients`: Maximum number of retries to contact Radius server before of a failure, when the radius server is not responding

`Max timeout to authenticate clients`: Maximum timeout that Vulture will wait for a response of the radius server
