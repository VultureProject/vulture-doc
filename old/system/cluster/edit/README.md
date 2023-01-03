# System / Nodes settings

From this view you can edit the settings of a specific node within the Vulture Cluster

## Main settings

### Hostname

This is the hostname of the node. **You cannot modify the hostname from here**.
Hostname modification must be done at the system level via the admin tool: /home/vlt-adm/admin.sh

Indeed, changing the hostname have several consequences :

 * System files will be changed on all cluster nodes (/etc/hosts)
 * The vultured daemon will be restarted on the modified node
 * Node certificate will be re-issued with the new hostname
 * Apache will be restarted on the node, for Web UI and Web Portal
 * The node name will be updated within the MongoDB replicaset 
 * Apache will be restarted on all nodes, for Web GUI
 * rsyslog configuration will be re-generated on all nodes


### Send rsyslog pstats logs to

Here you can select a log backend where to forward the rsyslog "pstats" info. pstats info are related to internal performance counter of the rsyslog process.

Example :
> */zroot/rsyslog/var/log/pstats*
> 2020-11-27T02:01:00.945119+00:00 rsyslog rsyslogd-pstats: { "name": "Internal_Dashboard_internal_pstats", "origin": "core.action", "processed": 58306, "failed": 0, "suspended": 0, "suspended.duration": 0, "resumed": 0 }

You can define additional log forwarders from the [Logs Forwarders](/apps/logfwd/) menu.
Supported log forwarder are: File, REDIS, SYSLOG (TCP/UDP/RELP), Elasticsearch and MongoDB

## Network

From this tab you can modify IP address and network topology for the node, such as routing table, masquerading IPs...

### Internet IP Address 

When Vulture has to communicate with remote servers, it will be NAT-ed behind this IP Address.
By default, here are the network connexions that are using this IP address :

* DNS Resolution (From all Jails to any)
> nat proto udp from { any_jails } to any port 53 -> {{ node.internet_ip }}
* HTTP / HTTPS for updates (From all jails to any)
> nat proto tcp from { any_jails } to any port { 80, 443} -> {{ node.internet_ip }}
* HTTP for updates through a proxy (From all jails to proxy)
> nat proto tcp from { any_jails } to {{proxy_ip}} port {{proxy_port}} -> {{node.internet_ip}}

### InterCluster IP Address

Inter-cluster network traffic (redis/sentinel, mongodb, rsyslog) is NAT-ed behind this IP address.
This IP address is also used by the Web UI and the REST API management endpoint.

### Backends outgoing IP Address masquerading

Network traffic from haproxy to a remote TCP or HTTP backend is NAT-ed behind this IP address.

### Log forwarders IP Address masquerading

Network traffic from rsyslog to a remote log repository is NAT-ed behind this IP address.

### Default router

Define here the default IPv4 network gateway of the system

### Default IPV6 router

Define here the default IPv6 network gateway of the system

### Static network routes

Here you can define the routing table of the node. You have to use the FreeBSD syntax, as the content here will be used into the system file */etc/rc.conf.d/routing*. Have a look at [FreeBSD Gateways and Routes](https://www.freebsd.org/doc/handbook/network-routing.html) if needed.

*Note*: Vulture allows by default 2 fib (2 routing tables). If needed you can increase the number of routing tables by overriding the *net.fibs* settings defined in /boot/loader.conf. To to that, override the value in */boot/loader.conf.local*

Here is a rather complex example of a Vulture routing table using 2 differents FIB, one per VLAN plus a specific route to access a VPN gateway:

> static_routes="internal vlan101 vlan102 vpn"
> route_internal="-fib 0 -net 10.0.0.0/8 10.1.1.1.1"
> route_vlan101="-fib 0 default 10.1.1.1.1"
> route_vlan102="-fib 1 default 10.2.2.2"
> route_vpn="-net 8.9.10.11/32 10.3.3.3"

### Scanner IP Address

BHyve virtual machines are NAT-ed behind this IP address whenever they try to communicate outside the node.
Here is the default pf rule associated to this:
> nat pass from 192.168.1.0/24 to any -> {{ node.scanner_ip.ip }}

## Firewall

From this tab you can define pf Firewall's internal limits and add custom firewall rules.
This correspond to the first line of Vulture's PF configuration file (/usr/local/etc/pf.conf):
set limit { states {{node.pf_limit_states}}, frags {{node.pf_limit_frags}}, src-nodes {{node.pf_limit_src}} }

Please remind that Vulture's pf configuration file is generated automaticaly based on Vulture configuration. Any manual change to this file will be lost. The vultured daemon is in charge of managing the pf configuration file.

### Max. entries for PF state table

Maximum number of entries in the memory pool used for state table entries (filter rules that specify keep state). Default is 500000. 

### Max. entries for PF packet reassembly

Maximum number of entries in the memory pool used for packet reassembly (scrub rules). Default is 25000.

### Max. entries for PF source tracking

Maximum number of entries in the memory pool used for tracking source IP addresses (generated by the sticky-address and source-track options). Default is 50000.

### Custom PF Configuration

Here you can define specific PF rules to be included in the /usr/local/etc/pf.conf file. Any change here is immediaely applied by the vultured on the node. pf will be reloaded with the new ruleset. In case of an error, new ruleset won't be used. Also, please check logs to detect any misconfiguration.

Here is the global structure of pf configuration file :

> Global PF settings and limits
> Outgoing NAT Jails masqueraring rules
> Outgoing NAT Intercluster traffic and Web GUI / REST Endpoint rules
> Outgoing NAT Rsyslog forwarders rules
> Outgoing NAT Haproxy backends rules
> Outgoing NAT Bhyve rules
> Incoming RDR traffic to local Jails rules
> Incoming RDR Intercluster traffic and Web GUI / REST Endpoint rules
> Incoming RDR traffic to haproxy and rsyslog frontends
> Whitelist / Blacklist / Reputation / Security rules
> Automatic Filtering rules
> *CUSTOM PF CONFIGURATION*
> Incoming traffic to Web UI
> Incomming Intercluster traffic
> Incoming traffic on SSH
> Incoming traffic to haproxy and rsyslog frontends

*WARNING*: The Custom PF Configuration if *AFTER* NAT and RDR Rules, in the "filter section". *SO you can't use any 'nat' or 'rdr' directive in the Custom PF Configuration*. Please contact us if you are facing an issue to configure a proper firewall configuration in your environment.