# salt-cloud-ahv vagrant



# Table of Contents
1. [Configure](#configure)
1. [Start the salt-cloud master](#startup)
1. [Run salt-cloud](#run)

# <a name="configure" />Configure
Create configuration files for the target AHV cluster and desired virtual
machine setup based on the sample files in:

* conf/cloud.providers.d
* conf/cloud.profiles.d
* conf/cloud.maps.d



# <a name="startup" />Start the salt-cloud master
```
vagrant up
  ... Wait until done ...
vagrant ssh
```



# <a name="run" />Run salt-cloud

* List configured AHV providers

```
> sudo salt-cloud --list-providers
some-ahv-cluster:
    ----------
    ahv:
        ----------
```
