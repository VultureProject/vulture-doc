# Deployment guidelines

## Prerequisites

- Modern CPU with 2 cores
- 4Gb of RAM
- Default Vulture image uses 10Gb of RAM - adjust to the storage you needs for logs

### Installation on virtual machine

You can download **amd64** Vulture's disk images from [The VultureProject Mirror](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/).

Once you have downloaded the appropriate disk image you need to create a Virtual Machine using this disk. Feel free to increase the disk size as the default may not suits your needs. Once started, Vulture will automatically launch growfs to extend the filesystem to the new disk size.

### Installation on physical server

**Note :** VultureOS requires a ZFS root volume. The zpool is supposed to be named 'zroot'.

`Fixme`

## Automatic - Configuration and bootstraping via Cloud Init

Vulture may be started and automatically configured via Cloud Init.

`Fixme`

## Manual - Initial Configuration

Once installed, Vulture needs to be bootstraped.

One logged as `vlt-adm`, you can type the `admin` command to access the following menu :

 - `Keymap` : Configure keymap, like during installation of FreeBSD,
 - `Time` : Configure timezone and ntp server,
 - `Password` : Change vlt-adm password,
 - `Geli Change` : Change the ZFS disk encryption password,
 - `Email` : Define the administration SMTP Email address,
 - `Netconfig` : Manage network configuration, like during installation of FreeBSD,
 - `Proxy` : Configure proxy,
 - `Management` : Modify current management IP used to bind services,
 - `Hostname` : Configure hostname,
 - `Shell` : Launch a CSH shell as vlt-adm,
 - `RootShell` : Launch a CSH shell as root,
 - `Update OS` : Update system and jails, with pkg and freebsd-update,
 - `Exit` : Exit admin menu.

**Mandatory steps are :**

1. Adjust `Time`
2. Set `Management IP`
3. Set the `Hostname`

Once done, Vulture's internal database will be ready and the required processes will be started.

## Manual - Bootstraping

Depending on what you want do to, you have 2 scripts available :
 - `/home/vlt-adm/gui/cluster_create.sh` : To create a new **Master** node
 - `/home/vlt-adm/gui/cluster_join.sh` : To create a **Slave** node and join an existing cluster

#### If you want to initialize a new Vulture cluster

```
sudo /home/vlt-adm/gui/cluster_create.sh <admin_user> <admin_password>
sudo service vultured start
```
`admin_user` will be the login required to access the web GUI.
`admin_password` will be the password required to access the web GUI.


### If you want to add a new node to an existing Vulture cluster

Before

```
sudo  /home/vlt-adm/gui/cluster_join.sh <master_hostname> <master_ip> <secret_key>
sudo service vultured start
```
`master_hostname` is the name of the Vulture's master node.
`master_ip`  is the IP address of the Vulture's master node.
`secret_key` is the secret key of the node.


