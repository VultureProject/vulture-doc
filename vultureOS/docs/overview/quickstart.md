# Vulture - Quick start

## Vulture's main features

Vulture is a security device (Cloud / VM / Bare-metal) specialized in :

 - **Network firewall** : Packet filter, load-balancing and tcp/http reverse-proxy
 - **Log processing** : Collect, parsing, enrichment, anomaly detection
 - **Web Authentication portal**: Protect Web applications, authenticate users with Federation and SSO capabilities
 - **Web Application Firewall**: Work in progress

It is powered by a custom build of HardenedBSD and can be managed by a unified Web Interface

## Network firewall

Incoming and outgoing network trafic pass through the internal BSD Firewall "pf". This is a core feature of VultureOS than cannot be disabled. The firewall is automatically managed : Incoming trafic is blocked by default, except management ports. You do not have to worry about the firewall configuration, because Vulture will automatically open or block the ports whenever you publish a new service.

Of course you can customize the firewall configuration to fit your needs if needed. See "Custom PF Configuration" in [Network firewall](../../global_config/node/#firewall).

## TCP/HTTP Load-balancing and reverse-proxy

These features are provided by HAProxy, it is one of the most important component of Vulture. Vulture implements the HAProxy concepts of "Frontend" and "Backend" :

 - Frontend are the public listerners that will accept incoming trafic
 - Backend are the application servers that are "behind" the reverse-proxy

In Vulture, Frontends are manager through the listeners in [Services/Listeners](../services/listener.md)
 - Vulture handles "TCP" and "HTTP" listener, as HAProxy does
 - It also handles special "LOG" listeners : These listeners are able to process log streams, either via RSYSLOG or Filebeat (these components are both embedded into Vulture)

Thanks to HAProxy, incoming log trafic (except UDP) can be load-balanced between several Vulture devices.

## LOG Processing

LOG Listeners allow Vulture to accept incoming log stream. Log processing is handle by either Filebeat or RSYSLOG. You don't have to bother with Filebeat or RSYSLOG configuration, as Vulture will manage basic settings for you. Of course you always have the possibility to adapt settings to your specific needs.

Where you create a "LOG" listener in Vulture, the incoming data flow is : 

  - PF -> HAPROXY -> RSYSLOG / Filebeat if incoming protocol is TCP
  - PF -> RSYSLOG / Filebeat if incoming protocol is UDP

See [Available LOG Modes](../services/listener/#specific-settings-for-rsyslog-listening-modes)

### RSYSLOG Capabilities

Vulture can process incoming logs with the following protocols: UDP, TCP, TCP&UDP, RELP, FILE, KAFKA, REDIS... 

See available [Vendor API Listeners](../services/listener/#vendor-log-api-listening-mode-specific-parameters)

### Filebeat Capabilities
