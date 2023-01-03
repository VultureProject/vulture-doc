# Welcome to VultureOS Documentation

VultureOS is an operating system based on [HardenedBSD](https://hardenedbsd.org/).
It has been design to deliverer cybersecurity services for the Advens SOC.

It is a security platform able to host numerous services, from security scanners to IDS sensors or even running embedded virtual machines tnaks to bhyve.

## Features

With VultureOS we are able to do all the following things :

- Create a cluster of **load-balanced TCP services** with CARP and centralized management
- Deploy HAPROXY listeners to **reverse-proxify trafic** to TCP services or HTTP services
- Deploy RSYSLOG collectors to **collect logs over UDP and TCP**
    - Apply **enrichment features** on top of collected logs : Contextual tagging and Cyber Threat Intelligence
    - Normalize logs into a **normalized JSON model** with your own rules
    - Pass logs through a machine learning pipeline to **detect anomalies and security issues**
- **Collect Logs via REST API** from many vendors and process them via the rsyslog stack
- Implement **basic Web filtering** thanks to advanced haproxy ACLs
- **Forward all the incoming trafic** to many backend, including TCP/HTTP servers, redis, kafka, elasticsearch, syslog, and more..
- **Set up an OpenID Identity Provider** and add authentication on top of any existing web Application, with **Web SSO**
- **Authenticate WEB users and REST API call against external OpenID Providers**

## Licence

VultureOS is Open Source, except on the following sub-components :

- Rsyslog rulebases for log normaliation
- Detection algorithms based on Artificial Intelligence or Machine Learning

You may still use these components with VultureOS, but you will have to implement your own rules and algorithms. If you need professional support and access to our log parsers and algorithm, please contact us.

