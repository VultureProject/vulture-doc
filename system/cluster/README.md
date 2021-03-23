# System / Nodes config

From this menu you can manage the nodes composing your Vulture cluster. Remind that Vulture is **always** running as a cluster of 1 to any nodes. It allows Vulture to easily scale by adding new nodes whenever needed.

Cluster-wide parameters are managed from the [Cluster Config](/system/config/) menu.

## List of nodes

The table show all the nodes, with their main characteristics. Just **click on the node** to enter into edition mode. 

### Name

This is the friendly name of the node

### Network Interfaces

The list of all the network interfaces available on the Node is displayed here

### MongoDB

It indicates the **status** of the node within the mongodb replicaset. State can be **PRIMARY** or **SECONDARY** (or OTHER in case of cluster failure).

Click on **Step Down** to force a reelection in the MongoDb Cluster. This operation can be triggered on MongoDB Primary node only.

### Redis

It indicates the **status** of the node within the redis cluster. State can be **MASTER** or **SLAVE**

### Action

Here you can delete / remove a node from the cluster.
To be documented.

## Adding a new node into an existing cluster

To **add a node**, please install another Vulture server, bootstrap it and run /home/vlt-adm/gui/cluster_join.sh to join the existing cluster. See the [Configuration Guide](https://github.com/VultureProject/vulture-base/blob/master/CONFIGURE.md).




