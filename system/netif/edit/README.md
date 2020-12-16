# Network

### Name

This is the friendly name of the network interface

### Network Interface Cards

Select the NIC to use for the new interface. If you want to create a CARP IP address, you can select multiple NIS here.
Then you will have to configure the CARP priority for each NIC within the CARP group.

### IP Address

This is the IP address associated to the Vulture network interface.

### Netmask

This is the corresponding netwask or prefix associated to the IP address of the Vulture network interface.

### CARP vhid

For CARP IP addresses, this is the VirtualHost ID. Set vhid=0 (DIsabled) for non-carp ip address.

### Vlan ID

If the Vulture network interface should by tagged in a VLAN, defines the VLANID here. Use vlan=0 to disable VLAN.

### Vlan parent device

When using a VLAN for your network interface, you need to associate the parent physical system NIC.
