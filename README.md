### Installation on physical server

**Note :** VultureOS requires a ZFS root volume. The zpool is supposed to be named 'zroot'.

#### Prerequisites

You need a working HardenedBSD installed **on top of a ZFS filesystem**.

Please download one of the HardenedBSD installers from the VultureProject Mirror:

 - [Vulture-bootonly.iso](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/Vulture-bootonly.iso)
 - [Vulture-disc1.iso](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/Vulture-disc1.iso)
 - [Vulture-memstick.img](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/Vulture-memstick.img)
 - [Vulture-mini-memstick.img](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/Vulture-mini-memstick.img)

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

At this point, Vulture shoiuld be fully installed and ready for bootstrap [See online Documentation](https://www.vultureproject.org/doc/deploy).
