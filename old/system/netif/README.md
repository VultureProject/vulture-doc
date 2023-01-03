# Network

Here you can manage all the network interface cards and IP addresses available in the Cluster.

Behind a single IP address, you may have several nodes / NICs. Indeed, Vulture supports the CARP protocol: it allow you to have a Virtual IP addresses associated with several NICs. Whenever the active NIC became unavailable, another backup CARP NIC will be ellected as active and handle the IP address.

Thus, a Vulture network interface is defined by:
* 1 or more NICs (Network Card), that may be hosted on 1 or more nodes
* A unique IP Address

## Network Interface list

It display the list of available network card / IP address within the Vulture cluster. Click on a line to edit the configuration of a given interface and click on *Add an entry* to create a new one.

### Name

This is the friendly name of the network interface

### Type

Vulture considers 2 types of network card.

#### "System" network interface

These are the network interfaces configured by default during HBSD install. Vulture detects theses cards using the "/sbin/ifconfig" command and store the corresponding configuration into MongoDB database. Then, vultured will generate the */etc/rc.conf.d/network* configuration file for you. DO NOT MODIFY THIS FILE BY HAND, has it will be overwritten by vultured.

So you cannot add "additional" network configuration in this file.

If you want to add custom network configuration, use the */usr/local/etc/custom.intf* file: Its content will be merged by Vulture in the /etc/rc.conf.d/network file.

For example, if you want to configure an LACP trunk using bge0 and bge1 NIC, you will add the folowwing configuration into /usr/local/etc/custom.intf:
> ifconfig_bge0="up"
> ifconfig_bge1="up"
> ifconfig_lagg0="up laggproto lacp laggport bge0 laggport bge1"


If you have system card that are not showing up in the Vulture GUI (in case you modified the system configuration for example or if you add additional network card), click on *Refresh NIC* on the upper right corner to synchronize system configuration with MongoDB configuration.

#### "Alias" network interface

You may add additional IP address to existing NIC, using the "Add an entry" menu. Whenever you do this, the created network interface will be flagged as "alias".

The corresponding configuration will be stored in */etc/rc.conf.d/netaliases*. DO NOT MODIFY THIS FILE BY HAND, has it will be overwritten by vultured.

### NIC

This shows the Node and the network card attached to the Vulture network interface.

### IP Address

This is(are) the IP address(es) associated to the Vulture network interface.

### Netmask

This is the corresponding netwask or prefix associated to the IP address of the Vulture network interface.

### CARP vhid

For CARP IP addresses, this is the VirtualHost ID. Set vhid=0 (DIsabled) for non-carp ip address.

### VLAN

If the Vulture network interface should by tagged in a VLAN, defines the VLANID here. Use vlan=0 to disable VLAN.

### Action

Here you can delete a Vulture network interface, only if it is an alias interface.
