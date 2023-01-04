# Packaging

## Supported architectures

Supported architecture are **amd64** and **arm64**.

Vulture and all its features are fully working on arm64 but we do not provide image for the moment.

## HardenedBSD Installers - amd64

We provide a non-modified version of HardeneBSD from [The VultureProject Mirror](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/). Servers are located in France and we have very good throughput !

Feel free to download and let us know if you encounter any issue.

**Note :** The update frequency is left to the discretion of the Vulture Team. Nightly builds are beeing tested but not deployed yet. If you need up-to-date HardenedBSD installers and kernels, please go to the official HardenedBSD mirrors.


## Virtual images for VultureOS - amd64

You can download **amd64** Vulture's virtual images from [The VultureProject Mirror](http://hbsd.vultureproject.org/13-stable/amd64/amd64/BUILD-LATEST/).

Following disk images are provided :

 - **vmdk**    -  Virtual Machine Disk
 - **vhd**     -  Dynamic Virtual Hard Disk, version 1 (Hyper-V on Windows Server 2008, 2008R2, 2012R2 and 2012)
 - **vhdf**    -  Fixed Virtual Hard Disk (Microsoft AZURE & Hyper-V on Windows Server 2012 and later versions only)
 - **vhdx**    -  Dynamic Virtual Hard Disk, version 2 (Hyper-V on Windows Server 2012 and later versions only)
 - **raw**     -  Raw Disk
 - **qcow2**   -  QEMU Copy-On-Write, version 2

## Physical Servers - amd64 and arm64

Vulture will run on any physical device supported by HardenedBSD.

For ARM64 devices, Vulture has been certified on :

 - Raspbery Pi 4
 - RockPro 64
 - Khadas Edge-V

Please refer to [Deployment guidelines](deploy.md)

## Cloud

Virtual images for VultureOS rely on cloud-init. 
You should be able to install Vulture via Cloud-Init using the available images.

AMI support is in progress
