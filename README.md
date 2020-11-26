# Vulture 4 HOME

On this page you have a global overview of the Vulture cluster.

For each member of the cluster, the status of critical services is displayed: If green everything os OK, if red: an error has occured and action is required to solve it.

* Frontend: 
    - This status is related to the TCP and HTTP listeners, managed by HAPROXY
* AI Framework:
    - This status is related to the "darwin" process, in charge of Artificial Intelligence / Machine learning for anomaly detection
* Packet Filter:
    - This status is related to the network firewall, "pf"
* IPSEC:
    - This status is related to the Strongswan service.
    - If unused, the button color will be "gray"
* VPN SSL:
    - This status is related to the OpenVPN service.
    - If unused, the button color will be "gray"
* Logging:
    - This status is related to RSYSLOG services, in charge of incoming logs


