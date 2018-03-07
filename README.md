# salt-cloud-ahv
Salt Cloud driver for Nutanix AHV



# Table of Contents
1. [Installation](#install)



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
