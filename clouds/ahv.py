#!/usr/bin/env python
"""
Copyright (c) 2017 Nutanix Inc. All rights reserved.

.. versionadded: 2016.3.4

:codeauthor: Jason Klein <jklein@nutanix.com>
:codeauthor: Edwin Tay <edwin@nutanix.com>



Nutanix AHV Module
==================
The Nutanix AHV module allows you to interface with a Nutanix AHV cluster to
perform simple CRUD of guest VMs.

:depends: requests >= 2.6.0, python-netaddr >= 0.7.18

To use this module, set up the AHV cluster configuration at
``/etc/salt/cloud.providers`` or
``/etc/salt/cloud.providers.d/ahv.conf``:



Developer Notes
===============
Globals injected by salt

.. code-block:: python

  __active_provider_name__ (str)
  __opts__ (dict)
  __utils__(dict)
"""

import base64
import functools
import jinja2
import json
import logging
import netaddr
import time
import urllib

from collections import defaultdict

# pylint: disable=import-error
from salt.exceptions import (
  SaltCloudException,
  SaltCloudExecutionFailure,
  SaltCloudExecutionTimeout,
  SaltCloudSystemExit,
  SaltCloudNotFound)
import salt.config as config
import salt.utils.cloud

try:
  import requests
  HAS_REQUESTS = True
except ImportError:
  HAS_REQUESTS = False
# pylint: enable=import-error



# Start logging
logger = logging.getLogger(__name__)


__virtualname__ = "ahv"

def __virtual__():
  if get_configured_provider() is False:
    return False

  if get_dependencies() is False:
    return False

  return __virtualname__

def get_configured_provider():
  return config.is_provider_configured(
    __opts__,
    __active_provider_name__ or __virtualname__,
    required_keys=(
      "cluster_uuid",
      "prism_host",
      "prism_user",
      "prism_password"
    )
  )

def get_dependencies():
  deps = {
    'requests': HAS_REQUESTS
  }
  return config.check_driver_dependencies(
    __virtualname__,
    deps
  )


class VmContextAdapter(logging.LoggerAdapter):
  def process(self, msg, kwargs):
    msg, kwargs = super(VmContextAdapter, self).process(msg, kwargs)
    msg = "{}: {}".format(self.extra.get("vmname"), msg)
    return msg, kwargs

def _attach_vm_context(vm_):
  return VmContextAdapter(logger, {
    "vmname": vm_["name"]
  })



#==============================================================================
# templates
#==============================================================================
CLOUDCFG_TMPL_STR = r"""#cloud-config
hostname: {{ hostname }}
fqdn: {{ hostname }}.{{ domain }}
write_files:
  {% for fpath, fcontent in netfiles.items() -%}
  - path: {{ fpath }}
    owner: root:root
    permissions: '0644'
    content: |
      {{ fcontent | indent(6) }}
  {%- endfor %}

bootcmd:
  {% if resolvconf_files -%}
  - rm -f {{ resolvconf_files | join(" ") }}
  {%- endif %}
  - ifdown eth0 && ifup eth0
  - ip -o -4 addr list eth0 | awk '{ print $4 }' | cut -d/ -f1 |
    awk '{ printf "\n%-11s %-31s %s\n", $1, "{{ hostname }}.{{ domain }}", "{{ hostname }}"}' >> /etc/hosts
runcmd:
  - touch /etc/cloud/cloud-init.disabled

datasource_list:
  - ConfigDrive
cloud_init_modules:
  - write_files
  - bootcmd
cloud_config_modules:
  - set_hostname
  - runcmd
  - scripts_user
cloud_final_modules:
  - final_message
"""
NETCFG_REDHAT = r"""
DEVICE={{ device }}
TYPE=Ethernet
DEFROUTE=yes
NM_CONTROLLED=no
IPV4_FAILURE_FATAL=yes
IPV6INIT=no
ONBOOT=yes

BOOTPROTO=none
IPADDR={{ ipaddr }}
PREFIX={{ prefix }}
GATEWAY={{ gateway }}
{% for server in dns_servers -%}
DNS{{ loop.index }}={{ server }}
{% endfor -%}
SEARCH="{{ search_domains | join(" ") }}"
"""
NETCFG_DEBIAN = r"""
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
  address {{ ipaddr }}
  netmask {{ netmask }}
  gateway {{ gateway }}
  dns-nameservers {{ dns_servers | join(" ") }}
  dns-search {{ search_domains | join(" ") }}
"""

class Distro(object):
  cloud_tmpl_str = CLOUDCFG_TMPL_STR
  resolvconf_files = ()
  netcfg_tmpls = {}

class RedhatDistro(Distro):
  resolvconf_files = (
    "/etc/resolv.conf",
  )
  netcfg_tmpls = {
    "/etc/sysconfig/network-scripts/ifcfg-eth0": NETCFG_REDHAT
  }

class UbuntuDistro(Distro):
  resolvconf_files = (
    "/run/resolvconf/resolv.conf",
   )
  netcfg_tmpls = {
    "/etc/network/interfaces": NETCFG_DEBIAN
  }

DISTRO_MAP = {
  "rhel": RedhatDistro,
  "ubuntu": UbuntuDistro
}



#=============================================================================
# event helpers
#=============================================================================
class Event(object):
  message_fmt = "some-event-message"
  tag_fmt = "some-event-tag"
  default_payload = tuple()

  def __init__(self, data):
    self.args = self.extract_args(data)
    self.sock_dir = __opts__["sock_dir"]
    self.transport = __opts__["transport"]

  def fire(self):
    __utils__["cloud.fire_event"](
      "event",
      self.message_fmt.format(**self.args),
      self.tag_fmt.format(**self.args),
      args=self.args,
      sock_dir=self.sock_dir,
      transport=self.transport
    )

  def extract_args(self, data):
    basetag = self.tag_fmt.split("/")[-1]
    payload = self.default_payload
    args = __utils__["cloud.filter_event"](basetag, data, payload)
    return args

class CreatingInstanceEvent(Event):
  message_fmt = "creating instance"
  tag_fmt = "salt/cloud/{name}/creating"
  default_payload = ("name", "profile", "provider", "driver")

class RequestingInstanceEvent(Event):
  message_fmt = "requesting instance"
  tag_fmt = "salt/cloud/{name}/requesting"
  default_payload = ("name", "image", "size", "location")

class QueryingInstanceEvent(Event):
  message_fmt = "querying instance"
  tag_fmt = "salt/cloud/{name}/querying"
  default_payload = ("name", "instance_id")

  def extract_args(self, data):
    data["instance_id"] = data.get("name")
    return super(QueryingInstanceEvent, self).extract_args(data)

class WaitingForSshInstanceEvent(Event):
  message_fmt = "waiting for ssh"
  tag_fmt = "salt/cloud/{name}/waiting_for_ssh"
  default_payload = ("ip_address",)

  def extract_args(self, data):
    data["ip_address"] = data.get("ssh_host")
    return super(WaitingForSshInstanceEvent, self).extract_args(data)

class CreatedInstanceEvent(Event):
  message_fmt = "created instance"
  tag_fmt = "salt/cloud/{name}/created"
  default_payload = ("name", "profile", "provider", "driver")

class DestroyingInstanceEvent(Event):
  message_fmt = "destroying instance"
  tag_fmt = "salt/cloud/{name}/destroying"
  default_payload = ("name",)

  def extract_args(self, name):
    data = {
      "name": name,
      "instance_id": name
    }
    return super(DestroyingInstanceEvent, self).extract_args(data)

class DestroyedInstanceEvent(Event):
  message_fmt = "destroyed instance"
  tag_fmt = "salt/cloud/{name}/destroyed"
  default_payload = ("name",)

  def extract_args(self, name):
    data = {
      "name": name,
      "instance_id": name
    }
    return super(DestroyedInstanceEvent, self).extract_args(data)



#==============================================================================
# REST API Client
#==============================================================================

class LegacyClient(object):
  """
  Client for the Prism v1 REST API and v0.8 management REST API.
  """

  #============================================================================
  # Decorators
  #============================================================================
  def entity_list(func):
    # pylint: disable=no-self-argument
    """
    Decorator for REST API endpoints corresponding to a collection of entities.
    """
    @functools.wraps(func)
    def _wrapped(*args, **kwargs):
      # pylint: disable=not-callable
      try:
        resp = func(*args, **kwargs).json()
      except Exception as exc:
        raise SaltCloudExecutionFailure(str(exc))

      if "entities" not in resp:
        raise SaltCloudExecutionFailure()

      return resp["entities"]

    return _wrapped

  #============================================================================
  # Init
  #============================================================================

  def __init__(self, host, user, password, port=9440,
               base_path="/PrismGateway/services/rest/v1",
               base_mgmt_path="/api/nutanix/v0.8",
               verify_ssl=True):
    # requests.Session to use for communicating with Prism.
    self._session = requests.Session()
    self._session.auth = (user, password)
    self._session.headers["Content-Type"] = "application/json;charset=UTF-8"

    # Base URL for the Prism host.
    self._base_url = "https://%s:%d" % (host, port)
    # Base path for v1 Prism REST API
    self._base_path = base_path
    # Base path for v0.8 Prism management REST API
    self._base_mgmt_path = base_mgmt_path

    self.verify_ssl = verify_ssl

  #============================================================================
  # Public APIs (mgmt v0.8)
  #============================================================================

  @entity_list
  def images_get(self):
    return self._get("%s/images" % self._base_mgmt_path)

  #============================================================================
  # Protected util methods
  #============================================================================

  def _get(self, path, params=None):
    return self._issue_request(
      "GET", "%s/%s" % (self._base_url, path), params=params)

  def _issue_request(self, verb, url, data=None, params=None):
    func = getattr(self._session, verb.lower())
    if not func:
      raise SaltCloudSystemExit("Invalid HTTP method '%s'" % verb)

    return func(url,
      data=data,
      params=params if params else {},
      verify=self.verify_ssl
    )

#==============================================================================
# Utils
#==============================================================================
def get_conn(version=2):
  clienttype = AplosClient
  if version < 3:
    clienttype = LegacyClient

  vm_ = get_configured_provider()

  prism_host = config.get_cloud_config_value(
    "prism_host", vm_, __opts__, search_global=False
  )
  prism_user = config.get_cloud_config_value(
    "prism_user", vm_, __opts__, search_global=False
  )
  prism_password = config.get_cloud_config_value(
    "prism_password", vm_, __opts__, search_global=False
  )
  verify_ssl = config.get_cloud_config_value(
    "verify_ssl", vm_, __opts__, search_global=False
  )

  client = clienttype(
    host=prism_host,
    user=prism_user,
    password=prism_password,
    verify_ssl=verify_ssl
  )
  return client


def get_entity_by_key(entities, key, val):
  ret = None
  for entity in entities:
    if entity.get(key) == val:
      if ret:
        raise SaltCloudNotFound(
          "Found multiple entities matching '%s' == '%s'" % (key, val))
      ret = entity

  if ret is None:
    raise SaltCloudNotFound("No matches for '%s' == '%s'" % (key, val))
  return ret


def _filter_arguments(kwargs):
  """ handle arg parsing of salt.cloud.do_function() """
  call = kwargs.get("call")
  if "kwargs" in kwargs:
    kwargs = kwargs["kwargs"]

  return call, kwargs



#==============================================================================
# Salt cloud driver interface
#==============================================================================
def is_profile_configured(opts, provider, profile, vm_=None):
  required_keys = [
    "provider",
    "clone_from",
    "num_vcpus",
    "num_cores_per_vcpu",
    "memory_size_mib",
    "domain",
    "network",
    "distro_family"
  ]

  alias, driver = provider.split(":")
  provider_key = opts["providers"][alias][driver]
  profile_key = opts["providers"][alias][driver]["profiles"][profile]

  # Check if required fields are supplied in the provider config. If they
  # are present, remove it from the required_keys list.
  for item in list(required_keys):
    if item in provider_key:
      required_keys.remove(item)

  # If a vm_ dict was passed in, use that information to get any other configs
  # that we might have missed thus far, such as a option provided in a map file.
  if vm_:
    for item in list(required_keys):
      if item in vm_:
        required_keys.remove(item)

  # Check for remaining required parameters in the profile config.
  for item in required_keys:
    if profile_key.get(item, None) is None:
      # There's at least one required configuration item which is not set.
      logger.error(
        "The required '{0}' configuration setting is missing from "
        "the '{1}' profile, which is configured under the '{2}' "
        'alias.'.format(item, profile, alias)
      )
      return False

  return True

class CreateResult(object):
  def __init__(self):
    self.created = False
    self.powered_on = False
    self.bootstrapped = False

  def __iter__(self):
    return self.__dict__.iteritems()

def create(vm_, call=None):
  result = CreateResult()

  if vm_["profile"] and not is_profile_configured(__opts__,
      __active_provider_name__ or __virtualname__,
      vm_["profile"],
      vm_=vm_):
    return dict(result)

  CreatingInstanceEvent(vm_).fire()
  conn = get_conn(version=3)

  logg = _attach_vm_context(vm_)
  logg.info("Creating instance ...")

  cluster_uuid = vm_["cluster_uuid"]
  clone_from = vm_["clone_from"]
  vm_name = vm_["name"]
  nics = vm_["network"]
  power_on = vm_["power_on"]

  logg.debug("Requesting Prism clone_vm ...")
  RequestingInstanceEvent(vm_).fire()
  QueryingInstanceEvent(vm_).fire()

  userdata = conn.generate_cloudinit_userdata(vm_)
  metadata = conn.generate_cloudinit_metadata(vm_)

  vm_data = conn.clone_vm(
    cluster_uuid=cluster_uuid,
    clone_from=clone_from,
    vm_name=vm_name,
    nics=nics,
    memory_size_mib=vm_["memory_size_mib"],
    num_vcpus=vm_["num_vcpus"],
    num_cores_per_vcpu=vm_["num_cores_per_vcpu"],
    userdata=userdata,
    metadata=metadata
  )
  logg.debug("VM clone complete")

  if not vm_data:
    logg.error("Failed to clone VM")
    return dict(result)

  # Reboot VM for cloudinit
  vm_data = conn.reboot_for_cloudinit(
    vm_data,
    vm_["ssh_username"],
    vm_["password"]
  )
  if not vm_data:
    logg.error("Failed to reboot for cloudinit")
    return dict(result)
  logg.info("Configured OS with cloudinit")

  # Power on VM if requested
  vm_data = conn.finalize_vm(vm_data, power_on)
  if not vm_data:
    logg.error("Failed final power on")
    return dict(result)
  logg.info("Final power on {}".format(
    "completed" if power_on else "skipped"
  ))
  result.powered_on = power_on

  logg.info("VM created")
  result.created = True

  logg.info("Bootstrapping salt ...")
  ip_list = list(AplosUtil.extract_ips(
    defaultdict(dict, vm_data)["status"]["resources"]["nic_list"]
  ))
  vm_["ssh_host"] = ip_list[0]
  ret = __utils__["cloud.bootstrap"](vm_, __opts__)
  if "Error" in ret:
    logg.warning(ret["Error"])
  else:
    logg.info("Bootstrap complete!")
    result.bootstrapped = True
    logg.debug("ret: {}".format(json.dumps(ret, indent=2)))

  CreatedInstanceEvent(vm_).fire()
  return dict(result)



def destroy(name, call=None):
  """
  Destroy VM by name.

  Args:
    name (str): Name of VM to destroy.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    True on success, False otherwise

  Raises:
    SaltCloudNotFound:
      If no VM with 'name' could be found.
    SaltCloudSystemExit:
      If 'name' corresponds to more than one VM.
  """

  DestroyingInstanceEvent(name).fire()

  conn = get_conn(version=3)

  logg = _attach_vm_context({"name": name})
  logg.info("Deleting VM ...")

  vm_dict = conn.delete_vm_by_name(name)
  if not vm_dict:
    logg.error("Failed to delete VM")
    return False

  logg.info("Deleted VM")
  DestroyedInstanceEvent(name).fire()

  return True



def avail_locations(*args, **kwargs):
  """
  List available clusters.

  Args:
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str,dict>): Map of cluster names to cluster summary.
  """
  call, kwargs = _filter_arguments(kwargs)
  if call != "function" and call is not None:
    raise SaltCloudSystemExit("The avail_locations function must be called "
      "with -f/--function <PROVIDER>, or with --list-locations.")

  conn = get_conn(version=3)
  clusters = conn.list_clusters()

  result = dict( (cluster.name, cluster.to_summary())
    for cluster in clusters
      if cluster.has_pe and cluster.has_ahv
  )
  return result

def avail_images(call=None):
  """
  List available VM images.

  Args:
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str,dict>): Map of image names to image metadata for all images
      known to the image service.
  """
  if call != "function" and call is not None:
    raise SaltCloudSystemExit("The avail_images function must be called "
      "with -f or --function, or with the --list-images option.")

  conn = get_conn()
  return dict((img["name"], img) for img in conn.images_get())

def avail_sizes(*args, **kwargs):
  """
  Lists available options for configuring VM CPU/RAM.

  Args:
    call (str|None): Kind of call by which this function was invoked.

  Returns:
    (dict<str, str>) Map of argument names to descriptions.
  """
  call, kwargs = _filter_arguments(kwargs)
  if call != "function" and call is not None:
    raise SaltCloudSystemExit("The avail_sizes function must be called "
      "with -f/--function <PROVIDER>, or with --list-sizes.")

  return {
    "<num_vcpus>": "Number of vCPUs with which to configure the VM",
    "<num_cores_per_vcpu>":
      "Number of cores with which to configure each vCPU",
    "<memory_size_mib>": "Size of VM memory (in MiB)",
  }

def list_nodes(*args, **kwargs):
  """
  Show summary of all VMs on provider.

  Args:
    call (str|None): Method by which this functions is being invoked.

  Returns:
    dict<str,dict>: Map of VM names to corresponding VM summary
  """
  call, kwargs = _filter_arguments(kwargs)
  if call != "function" and call is not None:
    raise SaltCloudSystemExit("The list_nodes function must be be called "
      "with -f/--function <PROVIDER>, or with --query.")

  conn = get_conn(version=3)
  vms = conn.list_vms()

  result = dict((vm.name, vm.to_summary())
    for vm in vms if vm.tags.get("is_template") is not True
  )
  return result

def show_instance(*args, **kwargs):
  """
  Show details about the VM.

  Args:
    name (str): Name of VM to query.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    dict<str,dict>: Map of VM name to full VM information
  """
  call, kwargs = _filter_arguments(kwargs)
  if call != "action":
    raise SaltCloudSystemExit("The show_instance action must be called "
      "with -a/--action <INSTANCE>.")

  name = args[0]
  conn = get_conn(version=3)
  vm = conn.get_vm_by_name(name)
  return vm.to_dict()



# ===========================================================================
# Prism v3 client
# ===========================================================================
# ===========================================================================
# api entities
# ===========================================================================
class AplosClusterStatus(object):
  @classmethod
  def from_dict(klass, data):
    data = defaultdict(dict, data)

    metadata = data["metadata"]
    uuid = metadata.get("uuid")

    status = data["status"]
    name = status.get("name")

    resources = status["resources"]
    ip = resources["network"].get("external_ip")

    config = resources["config"]
    version = config["build"]["version"]
    opmode = config.get("operation_mode")

    services = config.get("service_list", [])
    has_pe = "AOS" in services
    mgmt_servers = config.get("management_server_list", [])
    has_ahv = len(mgmt_servers) < 1

    kwargs = {
      "uuid": uuid,
      "name": name,
      "ip": ip,
      "version": version,
      "opmode": opmode,
      "has_pe": has_pe,
      "has_ahv": has_ahv
    }
    return klass(status, **kwargs)

  def __init__(self, rawstatus,
      uuid,
      name,
      ip=None,
      version=None,
      opmode="NORMAL",
      has_pe=False,
      has_ahv=False):
    self.status_ = rawstatus

    self.uuid = uuid
    self.name = name
    self.ip = ip

    self.version = version
    self.opmode = opmode
    self.has_pe = has_pe
    self.has_ahv = has_ahv

  def to_dict(self):
    output = self.status_
    return output

  def to_summary(self):
    output = {
      "uuid": self.uuid,
      "external_ip": self.ip,
      "version": self.version,
      "operation_mode": self.opmode
    }
    return output



class AplosVmStatus(object):
  @classmethod
  def from_dict(klass, data):
    data = defaultdict(dict, data)

    metadata = data["metadata"]
    uuid = metadata.get("uuid")

    status = data["status"]
    name = status.get("name")
    description = status.get("description")

    # Custom tags if description is JSON
    tags = None
    try:
      tags = json.loads(description)
    except ValueError as ex:
      pass

    resources = status["resources"]
    num_vcpus = resources.get("num_sockets")
    num_cores_per_vcpu = resources.get("num_vcpus_per_socket")
    memory_size_mib = resources.get("memory_size_mib")
    disks = [ AplosDisk.from_dict(rawdisk)
      for rawdisk in resources.get("disk_list", [])
    ]
    nics = [ AplosNic.from_dict(rawnic)
      for rawnic in resources.get("nic_list", [])
    ]
    power_state = AplosPowerState( resources.get("power_state") )

    kwargs = {
      "rawstatus": status,
      "uuid": uuid,
      "name": name,
      "description": description,
      "tags": tags,

      "num_vcpus": num_vcpus,
      "num_cores_per_vcpu": num_cores_per_vcpu,
      "memory_size_mib": memory_size_mib,
      "disks": disks,
      "nics": nics,
      "power_state": power_state
    }
    return klass(**kwargs)

  def __init__(self, rawstatus,
      uuid,
      name,
      description=None,
      tags=None,
      num_vcpus=0,
      num_cores_per_vcpu=0,
      memory_size_mib=0,
      disks=None,
      nics=None,
      power_state=None):

    self._status = rawstatus

    self.uuid = uuid
    self.name = name
    self.description = description
    self.tags = tags or {}

    self.num_vcpus = num_vcpus
    self.num_cores_per_vcpu = num_cores_per_vcpu
    self.memory_size_mib = memory_size_mib
    self.disks = disks or []
    self.nics = nics or []
    self.power_state = power_state or APLOS_POWER_STATE_OFF

  def to_dict(self):
    output = self._status
    return output

  def to_summary(self):
    disk_summaries = {}
    for disk in self.disks:
      disk_summaries.update( disk.to_summary() )

    nic_summaries = {}
    for nic in self.nics:
      nic_summaries.update( nic.to_summary() )

    description = self.tags or self.description

    # salt.cloud.get_vmnames_by_action() expects 'state' field
    # crashes with KeyError otherwise
    state = "running" if self.power_state else "stopped"

    output = {
      "uuid": self.uuid,
      "name": self.name,
      "description": description,
      "num_vcpus": self.num_vcpus,
      "num_cores_per_vcpu": self.num_cores_per_vcpu,
      "memory_size_mib": self.memory_size_mib,
      "disks": disk_summaries,
      "nics": nic_summaries,
      "state": state
    }
    return output

class AplosVmSpec(object):
  @classmethod
  def from_dict(klass, data):
    data = defaultdict(dict, data)

    metadata = data["metadata"]
    version = metadata.get("spec_version")
    uuid = metadata.get("uuid")

    spec = data["spec"]
    description = spec.get("description")

    # Custom tags if description is JSON
    tags = None
    try:
      tags = json.loads(description)
    except ValueError as ex:
      pass

    power_state = spec["resources"].get("power_state")

    disks = [ AplosDisk.from_dict(rawdisk)
      for rawdisk in spec["resources"].get("disk_list", [])
    ]

    kwargs = {
      "rawspec": spec,
      "uuid": uuid,
      "version": version,
      "tags": tags,
      "disks": disks,
      "power_state": AplosPowerState(power_state)
    }
    return klass(**kwargs)

  def __init__(self, rawspec,
      uuid,
      version,
      tags=None,
      disks=None,
      power_state=None):
    self._spec = rawspec

    self.uuid = uuid
    self.version = version
    self.disks = disks or []
    self.power_state = power_state or APLOS_POWER_STATE_OFF
    self.tags = tags or {}

  def to_dict(self):
    output = self._spec
    output["resources"]["power_state"] = str(self.power_state)
    output["resources"]["disk_list"] = [
      disk.to_dict() for disk in self.disks
    ]
    if self.tags:
      self.tags.pop("is_template", None)
      output["description"] = json.dumps(self.tags)
    return output

class AplosDisk(object):
  @classmethod
  def from_dict(klass, data):
    uuid = data.get("uuid")
    size_mib = data.get("disk_size_mib")

    data = defaultdict(dict, data)
    type_ = data["device_properties"].get("device_type")
    raw_address = data["device_properties"]["disk_address"]
    address = AplosDiskAddress.from_dict(raw_address)

    kwargs = {}
    if type_:
      kwargs["type_"] = type_
    if uuid:
      kwargs["uuid"] = uuid
    if size_mib:
      kwargs["size_mib"] = size_mib
    return klass(address, **kwargs)

  def __init__(self, address,
      type_="DISK",
      uuid=None,
      size_mib=None):
    self.address = address
    self.type_ = unicode(type_)
    self.uuid = uuid
    self.size_mib = size_mib

  def __eq__(self, other):
    return (
      isinstance(other, self.__class__) and
        self.type_ == other.type_ and self.address == other.address
    )

  def __ne__(self, other):
    return not self.__eq__(other)

  def to_dict(self):
    output = {
      "uuid": self.uuid,
      "device_properties": {
        "device_type": self.type_,
        "disk_address": self.address.to_dict()
      },
      "disk_size_mib": self.size_mib
    }
    if not self.uuid:
      del output["uuid"]
    if not self.size_mib:
      del output["disk_size_mib"]
    return output

  def to_summary(self):
    shortaddr = str(self.address)
    detail = {
      "device_type": self.type_,
      "disk_size_mib": self.size_mib
    }
    return { shortaddr: detail }

class AplosDiskAddress(object):
  @classmethod
  def from_dict(klass, data):
    index = data.get("device_index")
    adapter = data.get("adapter_type")
    return klass(adapter, index)

  def __init__(self, adapter, index):
    self.adapter = unicode(adapter.upper())
    self.index = int(index)

  def __eq__(self, other):
    return (
      isinstance(other, self.__class__) and
      self.adapter == other.adapter and
      self.index == other.index
    )

  def __ne__(self, other):
    return not self.__eq__(other)

  def __str__(self):
    return "{0}.{1}".format(self.adapter, self.index)

  def to_dict(self):
    return {
      "adapter_type": self.adapter,
      "device_index": self.index
    }

CLOUDINIT_DISK = AplosDisk(AplosDiskAddress("ide", 3), "CDROM")


class AplosNic(object):
  known_types = (
    "NORMAL_NIC",
    "NETWORK_FUNCTION_NIC"
  )

  @classmethod
  def from_dict(klass, data):
    data = defaultdict(dict, data)

    mac_addr = data.get("mac_address")
    type_ = data.get("nic_type")

    subnet = AplosSubnet.from_dict( data["subnet_reference"] )
    endpoints = tuple( AplosNicEndpoint.from_dict(endpoint)
      for endpoint in data.get("ip_endpoint_list", [])
    )

    return klass(mac_addr, type_, subnet, endpoints=endpoints)

  def __init__(self,
      mac_addr,
      type_="NORMAL_NIC",
      subnet=None,
      endpoints=None):

    self.mac_addr = mac_addr
    self.type_ = type_
    self.subnet = subnet
    self.endpoints = endpoints or []

  def to_summary(self):
    addr = self.mac_addr
    detail = {
      "nic_type": self.type_,
      "subnet": self.subnet.name,
      "endpoints": [ str(endpoint) for endpoint in self.endpoints ]
    }
    return { addr: detail }

class AplosSubnet(object):
  @classmethod
  def from_dict(klass, data):
    name = data.get("name")
    uuid = data.get("uuid")

    kwargs = {}
    if "kind" in data:
      kwargs["kind"] = data["kind"]

    return klass(name, uuid, **kwargs)

  def __init__(self, name, uuid=None, kind="subnet"):
    self.name = name
    self.uuid = uuid
    self.kind = kind

class AplosNicEndpoint(object):
  known_types = (
    "LEARNED",
    "ASSIGNED"
  )

  @classmethod
  def from_dict(klass, data):
    ip = data.get("ip")
    type_ = data.get("type")

    return klass(ip, type_)

  def __init__(self, ip, type_="ASSIGNED"):
    self.ip = ip
    self.type_ = type_

  def __str__(self):
    return "{0} ({1})".format(self.ip, self.type_)


class AplosPowerState(object):
  def __init__(self, power_on):
    if isinstance(power_on, basestring):
      power_on = unicode(power_on) == u"ON"
    self.power_on = power_on

  def __bool__(self):
    return self.power_on

  def __eq__(self, other):
    return self.power_on == other.power_on

  def __str__(self):
    if self.power_on:
      return "ON"
    return "OFF"

APLOS_POWER_STATE_ON = AplosPowerState(True)
APLOS_POWER_STATE_OFF = AplosPowerState(False)



# ===========================================================================
# api async helpers
# ===========================================================================
class AplosUtil(object):
  @classmethod
  def print_failure(klass, result):
    if not result:
      return

    status = result.get("status")
    if not status:
      return

    state = status.get("state")
    if state.lower() == "error":
      logger.error(json.dumps(status, indent=2))
    else:
      logger.error("State: {}\nReason: {}\nDetails: {}\nMessage: {}".format(
        state,
        result.get("reason"),
        result.get("details"),
        result.get("message")
      ))

  @staticmethod
  def is_task_complete(status, result):
    if result and str(result.get('code')) == "404":
      return True
    if result and (status == 200 or status == 202):
      api_status = defaultdict(dict, result)["status"].get("state")
      logger.info(api_status)
      if api_status == "COMPLETE":
        return True
      elif api_status.lower() == "error":
        return None
    return False

  @classmethod
  def has_ip_endpoints(klass, status, result):
    if result and status == 200:
      nic_list = defaultdict(dict, result)["status"]["resources"].get("nic_list", [])
      ip_set = klass.extract_ips(nic_list)
      return ip_set
    return False

  @staticmethod
  def extract_ips(nic_list):
    ip_set = set()
    for nic in nic_list:
      for endpoint in nic.get("ip_endpoint_list", []):
        ip_set.add(endpoint.get("ip"))
    return ip_set

  @classmethod
  def wait_until_complete(klass,
    init_fn,
    status_fn,
    completed_fn,
    retries=100,
    wait_secs=3,
    retry_message=""):

    (status, result) = init_fn()
    return klass.track_request(
      status,
      result,
      status_fn,
      completed_fn=completed_fn,
      retry_message=retry_message
    )

  @classmethod
  def track_request(klass,
      status,
      result,
      status_fn,
      status_retries=100,
      status_wait_secs=3,
      completed_fn=None,
      retry_message=""
    ):
    uuid = defaultdict(dict, result)["metadata"].get("uuid")
    if not uuid:
      return None

    if completed_fn is None:
      completed_fn = klass.is_task_complete

    start_time = time.time()
    for count in range(status_retries):
      completed = completed_fn(status, result)
      if completed is None:
        # terminate on error
        break

      if completed:
        time_taken = time.time() - start_time
        logger.info("Time to completion: {0} seconds".format(
          int(time_taken)
        ))
        return result

      if retry_message:
        time_taken = time.time() - start_time
        logger.info("{0} ({1} seconds)".format(
          retry_message, int(time_taken)
        ))
      time.sleep(status_wait_secs)
      (status, result) = status_fn(uuid)

    klass.print_failure(result)
    return None



class AplosClient(object):
  def __init__(self, host, user, password, verify_ssl=True):
    self.host = host
    self.user = user
    self.password = password
    self.verify_ssl = verify_ssl

    self.content_type = "application/json"
    self.charset = "utf-8"
    self.accept_type = "application/json"

  # =========================================================================
  # http helpers
  # =========================================================================
  def request(self, method, endpoint, body=None):
    url = "https://{}:9440/api/nutanix/v3/{}".format(
      self.host, endpoint
    )

    auth = (self.user, self.password)
    headers = {
      "Content-Type": "{}; charset={}".format(self.content_type, self.charset),
      "Accept": self.accept_type
    }
    verify = self.verify_ssl

    kwargs = {}
    if body:
      kwargs["json"] = body

    try:
      response = requests.request(method,
        url,
        auth=auth,
        headers=headers,
        verify=verify,
        **kwargs
      )
    except requests.exceptions.RequestException as ex:
      return 408, ex.response
    except Exception as ex:
      logger.error("requests: {}".format(ex))
      return 408, None

    try:
      rbody = response.json()
    except ValueError as ex:
      logger.debug("requests: response body is not JSON")
      rbody = response.text

    return response.status_code, rbody

  def GET(self, *args, **kwargs):
    return self.request("GET", *args, **kwargs)

  def POST(self, *args, **kwargs):
    return self.request("POST", *args, **kwargs)

  def PUT(self, *args, **kwargs):
    return self.request("PUT", *args, **kwargs)

  def DELETE(self, *args, **kwargs):
    return self.request("DELETE", *args, **kwargs)

  # =========================================================================
  # commands
  # =========================================================================
  def clone_vm(self,
      cluster_uuid,
      clone_from,
      vm_name,
      nics=None,
      memory_size_mib=2048,
      num_vcpus=2,
      num_cores_per_vcpu=1,
      userdata=None,
      metadata=None
    ):

    logger.info("Looking for template {}".format(clone_from))
    template_vm = self.get_vm_by_name(clone_from)
    if not template_vm:
      return False

    logger.info("Cloning VM from template {}".format(template_vm.name))
    status, result = self.create_vm(
      cluster_uuid,
      template_vm,
      vm_name,
      memory_size_mib=memory_size_mib,
      num_vcpus=num_vcpus,
      num_cores_per_vcpu=num_cores_per_vcpu,
      userdata=userdata,
      metadata=metadata
    )
    if status >= 300:
      logger.error(json.dumps(result, indent=2))
      return False

    # Track if the VM is created
    if status == 202:
      vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
      if not vm_data:
        logger.error("Failed to create VM {}".format(vm_name))
        return
    else:
      logger.error("Failed to create VM {}".format(vm_name))
      AplosUtil.print_failure(result)
      return
    vm_uuid = defaultdict(dict, vm_data)["metadata"].get("uuid")
    logger.info("Cloned VM {} with uuid {}".format(vm_name, vm_uuid))

    # Configure network
    logger.info("Configuring network for VM")
    status, result = self.configure_vm_network(vm_data, nics=nics)
    if status >= 300:
      logger.error("Failed to configure network for vm {}".format(vm_uuid))
      AplosUtil.print_failure(result)
      return

    # Track if network has been configured
    if status == 202:
      vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
      if not vm_data:
        logger.error("Failed to configure network for {}".format(vm_name))
        return
    else:
      logger.error("Failed to configure network for {}".format(vm_name))
      AplosUtil.print_failure(result)
      return

    logger.info("Configured network for {}".format(vm_name))

    return vm_data

  def get_network_by_name(self, name):
    """ Get a network by its name """
    endpoint = "subnets/list"
    body = {
      "filter": "name==" + name
    }
    status, result = self.POST(endpoint=endpoint, body=body)

    entities = result.get("entities")
    if len(entities) > 1:
      raise ValueError("multiple networks with name {}".format(name))
    if len(entities) < 1:
      raise ValueError("no network with name {}".format(name))

    return status, entities[0]

  def get_vm_by_name(self, name):
    """ Get a VM by its name """
    endpoint = "vms/list"
    body = {
      "filter": "vm_name==" + name
    }
    status, result = self.POST(endpoint=endpoint, body=body)

    entities = result.get("entities")
    if len(entities) > 1:
      raise SaltCloudSystemExit("multiple VMs with name {}".format(name))
    if len(entities) < 1:
      raise SaltCloudNotFound("no VM with name {}".format(name))

    if status >= 300:
      logger.error("Failed to fetch vm {}".format(name))
      AplosUtil.print_failure(result)
      return

    entity = entities[0]
    vm = AplosVmStatus.from_dict(entity)

    return vm

  def get_vm_by_uuid(self, uuid):
    """ Get a VM by its UUID """
    endpoint = "vms/{}".format(uuid)
    status, result = self.GET(endpoint=endpoint)
    return status, result

  def delete_vm_by_name(self, name):
    try:
      vm = self.get_vm_by_name(name)
    except SaltCloudNotFound as ex:
      logger.info("VM {0} does not exist. Skipping ...".format(name))
      return True

    return self.delete_vm_by_uuid(vm.uuid)

  def delete_vm_by_uuid(self, uuid):
    """ Delete a VM by its UUID """
    logger.debug("Deleting VM {}".format(uuid))

    endpoint = "vms/{0}".format(uuid)
    status, result = self.DELETE(endpoint=endpoint)

    if status == 404:
      logger.info("VM {0} does not exist. Skipping ...".format(uuid))
      return True
    elif status != 202:
      AplosUtil.print_failure(result)
      return False

    status, result = self.get_vm_by_uuid(uuid)
    vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
    if not vm_data:
      return False
    return True

  def list_vms(self):
    """ Get all VMs """
    endpoint = "vms/list"
    body = {
      "length": 100 # safe default so we don't overload server
    }

    status, result = self.POST(endpoint=endpoint, body=body)
    if status >= 300:
      logger.error("Failed to list vms")
      AplosUtil.print_failure(result)
      return []

    entities = result.get("entities", [])
    vms = [ AplosVmStatus.from_dict(entity) for entity in entities ]
    return vms

  def list_clusters(self):
    """ Get all clusters """
    endpoint = "clusters/list"
    body = {
      "length": 100 # safe default so we don't overload server
    }

    status, result = self.POST(endpoint=endpoint, body=body)
    if status >= 300:
      logger.error("Failed to list clusters")
      AplosUtil.print_failure(result)
      return []

    entities = result.get("entities", [])
    clusters = [ AplosClusterStatus.from_dict(entity) for entity in entities ]
    return clusters


  def create_vm(self,
      cluster_uuid,
      template_vm,
      vm_name,
      memory_size_mib=2048,
      num_vcpus=2,
      num_cores_per_vcpu=1,
      userdata=None,
      metadata=None):

    spec = {
      "name": vm_name,
      "cluster_reference": {
        "kind": "cluster",
        "uuid": cluster_uuid,
      },
      "resources": {
        "parent_reference": {
          "kind": "vm",
          "uuid": template_vm.uuid
        },
        "nic_list": [],
        "power_state": "OFF",
        "num_sockets": int(num_vcpus),
        "num_vcpus_per_socket": int(num_cores_per_vcpu),
        "memory_size_mib": int(memory_size_mib),
        "guest_customization": {
          "cloud_init": {
            "meta_data": base64.b64encode(metadata),
            "user_data": base64.b64encode(userdata)
          }
        }
      }
    }
    body = {
      "api_version": "3.0",
      "metadata": {
        "kind": "vm"
      },
      "spec": spec
    }

    status, result = self.POST(endpoint="vms", body=body)
    return status, result

  def configure_vm_network(self, vm_data, nics):
    def create_nic_spec(key, value):
      if not value:
        return
      if not hasattr(value, "get"):
        return

      name = value.get("name")
      status, result = self.get_network_by_name(name)
      if not result:
        return
      uuid = defaultdict(dict, result)["metadata"].get("uuid")
      if not uuid:
        return

      return {
        "subnet_reference": {
          "kind": "subnet",
          "uuid": uuid
        }
      }

    nic_list = list(create_nic_spec(kk, vv) for kk, vv in nics.items())
    nic_list = filter(bool, nic_list)

    spec = vm_data["spec"]
    spec["resources"]["nic_list"] = nic_list
    spec["resources"]["power_state"] = "OFF"
    spec_version = defaultdict(dict, vm_data)["metadata"].get("spec_version")
    body = {
      "api_version": "3.0",
      "metadata": {
        "kind": "vm",
        "spec_version": spec_version
      },
      "spec": spec
    }

    vm_uuid = defaultdict(dict, vm_data)["metadata"].get("uuid")
    endpoint="vms/{}".format(vm_uuid)

    status, result = self.PUT(endpoint=endpoint, body=body)
    return status, result

  def reboot_for_cloudinit(self, vm_data, ssh_username, ssh_password):
    logger.info("Powering on VM to initiate cloudinit")
    spec = AplosVmSpec.from_dict(vm_data)
    spec.power_state = APLOS_POWER_STATE_ON
    body = {
      "api_version": "3.0",
      "metadata": {
        "kind": "vm",
        "spec_version": spec.version
      },
      "spec": spec.to_dict()
    }
    endpoint="vms/{}".format(spec.uuid)
    status, result = self.PUT(endpoint=endpoint, body=body)
    if status >= 300:
      logger.error("Failed to power on {} for cloudinit".format(spec.uuid))
      AplosUtil.print_failure(result)
      return
    if status == 202:
      vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
      if not vm_data:
        return
    else:
      AplosUtil.print_failure(result)
      return

    start_time = time.time()
    # Extract ip from vm status
    logger.info("Waiting for VM to acquire IP ...")
    vm_data = AplosUtil.wait_until_complete(
      init_fn=lambda: self.get_vm_by_uuid(spec.uuid),
      status_fn=self.get_vm_by_uuid,
      completed_fn=AplosUtil.has_ip_endpoints,
      retry_message="Waiting for VM to acquire IP ..."
    )
    if not vm_data:
      return

    ip_list = list(AplosUtil.extract_ips(
      defaultdict(dict, vm_data)["status"]["resources"]["nic_list"]
    ))
    if not ip_list:
      logger.error("Failed to configure network for {}".format(spec.uuid))
      return
    vm_ip = ip_list[0]
    logger.info("VM {} has IP {}".format(spec.uuid, vm_ip))

    # Give cloudinit time to execute. We estimate boot-up is done when sshd
    # starts accepting connections
    logger.info("Waiting for cloudinit ...")
    salt.utils.cloud.wait_for_passwd(vm_ip,
      username=ssh_username,
      password=ssh_password,
      maxtries=1
    )
    logger.info("Done with cloudinit")
    # The changes done by cloudinit are not recorded by AHV if we modify the
    # disks too soon after, so we have to wait for AHV to catch up if
    # necessary
    # TODO: Report this AHV bug
    minimum_delay = 30 # seconds
    time_elapsed = time.time() - start_time
    remaining_delay = minimum_delay - time_elapsed
    if remaining_delay > 0:
      logger.info("Waiting {:.2f} seconds for cloudinit changes to be "
        "saved".format(remaining_delay)
      )
      time.sleep(remaining_delay)

    # Shutdown VM and remove cloudinit disk
    logger.info("Shutting down VM and removing cloudinit disk")
    spec = AplosVmSpec.from_dict(vm_data)
    spec.power_state = APLOS_POWER_STATE_OFF
    spec.disks = [ disk for disk in spec.disks if disk != CLOUDINIT_DISK ]
    body = {
      "api_version": "3.0",
      "metadata": {
        "kind": "vm",
        "spec_version": spec.version
      },
      "spec": spec.to_dict()
    }
    endpoint="vms/{}".format(spec.uuid)
    status, result = self.PUT(endpoint=endpoint, body=body)
    if status >= 300:
      logger.error("Failed to remove cloudinit disk".format(spec.uuid))
      AplosUtil.print_failure(result)
      return
    if status == 202:
      vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
      if not vm_data:
        return
    else:
      AplosUtil.print_failure(result)
      return

    return vm_data

  def finalize_vm(self, vm_data, power_on):
    logger.info("Finalizing VM")
    desired_power_state = AplosPowerState(power_on)
    spec = AplosVmSpec.from_dict(vm_data)

    if spec.power_state == desired_power_state:
      # already at desired power state
      return vm_data

    spec.power_state = desired_power_state
    body = {
      "api_version": "3.0",
      "metadata": {
        "kind": "vm",
        "spec_version": spec.version
      },
      "spec": spec.to_dict()
    }
    endpoint="vms/{}".format(spec.uuid)
    status, result = self.PUT(endpoint=endpoint, body=body)
    if status >= 300:
      logger.error("Failed to power on {} as requested".format(spec.uuid))
      AplosUtil.print_failure(result)
      return
    if status == 202:
      vm_data = AplosUtil.track_request(status, result, self.get_vm_by_uuid)
      if not vm_data:
        return
    else:
      AplosUtil.print_failure(result)
      return

    return vm_data

  def generate_cloudinit_userdata(self, vm_):
    network = defaultdict(dict, vm_)["network"]
    distro_family = vm_["distro_family"]
    netfiles = self.generate_cloudinit_netfiles(vm_)

    hostname = vm_.get("hostname") or vm_["name"]
    domain = vm_["domain"]
    distro_family = vm_["distro_family"]

    distro = DISTRO_MAP.get(distro_family)
    if not distro:
      raise SaltCloudSystemExit("Unknown distro family {0}".format(
        distro_family
      ))

    tmpl_cloud_cfg = jinja2.Template(distro.cloud_tmpl_str)
    cloud_cfg_str = tmpl_cloud_cfg.render({
      "hostname": hostname,
      "domain": domain,
      "netfiles": netfiles,
      "distro_family": distro_family,
      "resolvconf_files": distro.resolvconf_files
    })
    logger.debug("cloudinit userdata: {0}".format(cloud_cfg_str))

    return cloud_cfg_str

  def generate_cloudinit_netfiles(self, vm_):
    network = defaultdict(dict, vm_)["network"]
    distro_family = vm_["distro_family"]
    dns_servers = vm_["dns_servers"]
    search_domains = vm_["search_domains"]

    # Configure cloudinit network if nic.0 is specified
    # TODO: Support more than one interface
    netfiles = {} # file path, file content
    if "nic.0" in network:
      eth0 = network["nic.0"]

      ipaddr = eth0["ipaddr"]
      prefix = eth0["prefix"]
      gateway = eth0["gateway"]
      cidr = netaddr.IPNetwork("{0}/{1}".format(ipaddr, prefix))

      distro = DISTRO_MAP.get(distro_family)
      if not distro:
        raise SaltCloudSystemExit("Unknown distro family {0}".format(
          distro_family
        ))

      for path, tmpl_str in distro.netcfg_tmpls.items():
        tmpl_net_cfg = jinja2.Template(tmpl_str)
        net_cfg_str = tmpl_net_cfg.render({
          "device": "eth0",
          "ipaddr": ipaddr,
          "prefix": prefix,
          "netmask": cidr.netmask,
          "gateway": gateway,
          "dns_servers": dns_servers,
          "search_domains": search_domains
        })
        netfiles[path] = net_cfg_str
        logger.debug("netcfg: {0}\n{1}".format(path, net_cfg_str))

    return netfiles

  def generate_cloudinit_metadata(self, vm_):
    hostname = vm_.get("hostname") or vm_["name"]
    domain = vm_["domain"]
    fqdn = "{0}.{1}".format(hostname, domain)

    metadata = json.dumps({
      "uuid": fqdn,
      "network": {
        "config": "disabled"
      }
    })
    logger.debug("cloudinit metadata: {0}".format(metadata))

    return metadata
