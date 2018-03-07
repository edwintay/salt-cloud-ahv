# salt-cloud-ahv
Salt Cloud driver for Nutanix AHV



# Table of Contents
1. [Installation](#install)
1. [Configuration](#configure)
    1. [salt-cloud](#configure-salt-cloud)
1. [Requirements](#requires)
    1. [Prism](#requires-prism)
    1. [cloudinit](#requires-cloudinit)



# <a name="install" />Installation
To add this extension to an existing salt-cloud machine, configure the
'extension\_modules' option to point to this project's root directory

```
On salt master,
  mkdir -p /srv/cloud/ahv
  git clone git@github.eng.nutanix.com/techops/salt-cloud-ahv /srv/cloud/ahv

  vim /etc/salt/master
    ...
    extension_modules: /path/to/local/clone
    ...
```



# <a name="configure" />Configuration

## <a name="configure-salt-cloud" />salt-cloud
See
* [provider](doc/samples/ahv.provider.conf)
* [profile](doc/samples/ahv.provider.conf)
* [map](doc/samples/ahv.map.conf)



# <a name="requires" />Requirements

## <a name="requires-prism" />Prism
Must be running AOS >= 5.5 since this driver uses the v3 Prism API.

## <a name="requires-cloudinit" />cloudinit
Clone targets must have cloudinit >= 0.7.9.

VM `clone_from` targets must have some minimal cloudinit configuration:

```
/etc/cloud/cloud.cfg
  ...
  system_info:
    distro: {{ distro-family-of-the-vm, e.g. debian, rhel }}
```
