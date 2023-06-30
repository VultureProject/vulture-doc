# Deployment guidelines

## Prerequisites

- Modern CPU with 2 cores
- 4Gb of RAM
- Default Vulture image uses 10Gb of RAM - adjust to the storage you needs for logs

### Installation on virtual machine

You can download **amd64** Vulture's disk images from [The VultureProject Mirror](https://hbsd.vultureproject.org/amd64/current/13-stable/BUILD-LATEST/).

Once you have downloaded the appropriate disk image you need to create a Virtual Machine using this disk. Feel free to increase the disk size as the default may not suits your needs. Once started, Vulture will automatically launch growfs to extend the filesystem to the new disk size.

### Installation on physical server

**Note :** VultureOS requires a ZFS root volume. The zpool is supposed to be named 'zroot'.

#### Prerequisites

You need a working HardenedBSD installed **on top of a ZFS filesystem**.

Please download one of the HardenedBSD installers from the VultureProject Mirror:

 - [Vulture-bootonly.iso](https://hbsd.vultureproject.org/amd64/current/13-stable/BUILD-LATEST/Vulture-bootonly.iso)
 - [Vulture-disc1.iso](https://hbsd.vultureproject.org/amd64/current/13-stable/BUILD-LATEST/Vulture-disc1.iso)
 - [Vulture-memstick.img](https://hbsd.vultureproject.org/amd64/current/13-stable/BUILD-LATEST/Vulture-memstick.img)
 - [Vulture-mini-memstick.img](https://hbsd.vultureproject.org/amd64/current/13-stable/BUILD-LATEST/Vulture-mini-memstick.img)

You will also need git (can be removed after) to clone the "vulture-from-scratch" installation scripts :
```
pkg install git
```

#### Step 1 : Base system configuration

Assuming ZFS pool name is "zroot", please execute the following commands as root :
```
git clone https://github.com/VultureProject/vulture-from-scratch.git
cd vulture-from-scratch
./install-1.sh ./config.txt zroot
```

**Note :** Cloud-init is disabled by default in config.txt, set it to "YES" if needed

After the script completion, ** you need to reboot the system **

#### Step 2 : Jails setup (without Cloud-init)

**Note :** root password has been scrambled after step 1, you need to login as `vlt-adm` with the `vlt-adm` password, to be changed asap.

Once logged as vlt-adm, you may become root with the command `sudo su`

Assuming ZFS pool name is "zroot", please execute the following commands as root :
```
sudo su
cd vulture-from-scratch
./install-2.sh ./config.txt zroot
```

After the script completion, ** you need to reboot the system **

At this point, Vulture should be fully installed and ready for bootstrap (See below).


## Automatic - Configuration and bootstraping via Cloud Init

Vulture may be started and automatically configured via Cloud Init.
Vulture virtual machine have Cloud-init enabled by default. For physical installation, it is disabled by default and can be enable by modifying config.txt (see above).


## Vulture bootstrap - Initial Configuration

Once installed, Vulture needs to be bootstraped.

One logged as `vlt-adm`, you can type the `admin` command to access the following menu :

 - `Keymap` : Configure keymap, like during installation of FreeBSD,
 - `Time` : Configure timezone and ntp server,
 - `Password` : Change vlt-adm password,
 - `Geli Change` : Change the ZFS disk encryption password,
 - `Email` : Define the administration SMTP Email address,
 - `Network IPs` : Modify current management IP used to bind services,
 - `Proxy` : Configure proxy,
 - `Netconfig` : Manage network configuration, like during installation of FreeBSD,
 - `Hostname` : Configure hostname,
 - `Shell` : Launch a CSH shell as vlt-adm,
 - `RootShell` : Launch a CSH shell as root,
 - `Update` : Update system and jails, with pkg and hardenedbsd-update,
 - `Exit` : Exit admin menu.

**Mandatory steps are :**

1. Adjust `Time`
2. Set `Network IPs`
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


