#
# Copyright (c) 2017 Nutanix Inc. All rights reserved.
#
# Author: jklein@nutanix.com
#
"""
Salt cloud driver module for Acropolis.

Installation:
  Add 'ahv.py' to an existing salt extension_modules directory, or set
  'extension_modules' to point to this project's root directory.

Globals (injected by salt):
  __active_provider_name__ (str)
  __opts__ (dict)
  __utils__
"""

# pylint: disable=unused-argument
import base64
import functools
import json
import logging
import time
import urllib

from salt.exceptions import (
  SaltCloudException,
  SaltCloudExecutionFailure,
  SaltCloudExecutionTimeout,
  SaltCloudSystemExit,
  SaltCloudNotFound)
import salt.config
import salt.utils.cloud


__virtualname__ = "ahv"


_LOG = logging.getLogger(__name__)

DEBUG = _LOG.debug
INFO = _LOG.info
WARNING = _LOG.warning
ERROR = _LOG.error

def ASSERT(boolean, msg="", exc_type=AssertionError):
  """
  Function which acts like the 'assert' statement, but will not be stripped
  out by the interpreter when optimizing code.
  """
  if not boolean:
    raise exc_type(msg)


try:
  import requests
  _HAS_REQUESTS = True
except ImportError as exc:
  ERROR("Unable to import 'requests': %s", exc)
  _HAS_REQUESTS = False

#==============================================================================
# cloud-init templates
#==============================================================================

# ifcfg-<DEVICE>
IFCFG_TMPL = """DEVICE={DEVICE}
ONBOOT=yes
NM_CONTROLLED=no
BOOTPROTO=static
DNS1={DNS_1}
DNS2={DNS_2}
DOMAIN="{DOMAIN}"
IPADDR={IPADDR}
NETMASK={NETMASK}
GATEWAY={GATEWAY}"""


CLOUD_INIT_TMPL = """#cloud-config
write_files:
  - encoding: b64
    content: {CONTENT}
    owner: root:root
    path: /etc/sysconfig/network-scripts/ifcfg-{DEVICE}
    permissions: 0644

runcmd:
  - [ service, network, disable ]
  - [ ifdown, {DEVICE}, down ]
  - [ ifup, {DEVICE}, up ]
"""

#==============================================================================
# Salt entities
#==============================================================================

class SaltEvent(object):
  @classmethod
  def _fire(cls, event, path, vm_):
    DEBUG("Firing %s event for %s", event, vm_["name"])
    __utils__["cloud.fire_event"](
      "event", event, path.format(vm_["name"]),
      args=cls.generate_event_args(vm_),
      sock_dir=__opts__["sock_dir"], transport=__opts__["transport"])

  @classmethod
  def generate_event_args(cls, vm_):
    raise NotImplementedError("Subclasses must implement this")

  @classmethod
  def get_event(cls):
    raise NotImplementedError("Subclasses must implement this")

  @classmethod
  def get_event_text(cls):
    return "%s_instance" % cls.get_event()

  @classmethod
  def get_event_path(cls):
    return "salt/cloud/{0}/%s" % cls.get_event()

  @classmethod
  def fire(cls, vm_):
    cls._fire(cls.get_event_text(), cls.get_event_path(), vm_)


class SaltCreatingEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_):
    return {"name": vm_["name"],
            "profile": vm_["profile"],
            "provider": vm_["driver"]}

  @classmethod
  def get_event(cls):
    return "creating"


class SaltRequestingEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_):
    return {"kwargs": vm_}

  @classmethod
  def get_event(cls):
    return "requesting"


class SaltWaitingForSSHEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_):
    return {"ip_address": vm_["ssh_host"]}

  @classmethod
  def get_event(cls):
    return "waiting_for_ssh"

  @classmethod
  def get_event_text(cls):
    return "waiting_for_ssh"


class SaltDeployingEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_):
    return {"kwargs": vm_}

  @classmethod
  def get_event(cls):
    return "deploying"


class SaltCreatedEvent(SaltEvent):
  generate_event_args = SaltCreatingEvent.generate_event_args

  @classmethod
  def get_event(cls):
    return "created"


class SaltDestroyingEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_name):
    return {"kwargs": {"vm_": vm_name}}

  @classmethod
  def get_event(cls):
    return "destroying"


class SaltDestroyedEvent(SaltEvent):
  @classmethod
  def generate_event_args(cls, vm_name):
    return {"kwargs": {"vm_": vm_name}}

  @classmethod
  def get_event(cls):
    return "destroyed"

# TODO (jklein): Clean this up too...
class SaltVm(object):
  __KEYS__ = ("id", "image", "size", "state", "private_ips", "public_ips")
  def __init__(self, entity_json):
    # VM UUID
    self.id = entity_json["uuid"]

    # ? (Need to check canonical salt vm states)
    self.state = entity_json["state"]

    entity_json = entity_json["config"]

    # Name of image from which VM was created
    self.image = entity_json.get("sourceImage", "")

    # Resource info for VM
    self.size = "%s vCPUs, %s MB RAM" % (
      entity_json["numVcpus"], entity_json["memoryMb"])

    # VM internal IPs
    self.private_ips = []

    # VM external IPs
    self.public_ips = [] #entity_json["ipAddresses"]

  def to_dict(self):
    return dict((k, getattr(self, k)) for k in self.__KEYS__)

#==============================================================================
# AHV entities
#==============================================================================

# TODO (jklein): Clean up this mess.

class AhvVmNicSpec(object):
  def __init__(self, uuid):
    self.network_uuid = uuid

  def to_dict(self):
    return {
      "networkUuid": self.network_uuid
    }


class AhvDiskSpec(object):
  def __init__(self, bus_type="scsi",
               bus_index=None, is_cdrom=False, is_empty=False):
    self.disk_address = {"deviceBus": bus_type}
    if bus_index:
      self.disk_address["deviceIndex"] = bus_index
    self.is_cdrom = is_empty
    self.is_empty = is_empty
    self.vm_disk_clone = None
    self.vm_disk_create = None

  def to_dict(self):
    ret = {
      "diskAddress": self.disk_address,
      "isCdrom": self.is_cdrom,
      "isEmpty": self.is_empty
    }
    if self.vm_disk_clone:
      ret["vmDiskClone"] = self.vm_disk_clone.to_dict()
    elif self.vm_disk_create:
      ret["vmDiskCreate"] = self.vm_disk_create.to_dict()

    return ret


class AhvDiskCloneSpec(object):
  def __init__(self, vm_disk_uuid, minimum_size=1):
    self.minimum_size = minimum_size
    self.vm_disk_uuid = vm_disk_uuid

  def to_dict(self):
    return {
      "minimumSize": self.minimum_size,
      "vmDiskUuid": self.vm_disk_uuid
    }


class AhvDiskCreateSpec(object):
  def __init__(self, container_uuid, size=1024**3):
    self.container_uuid = container_uuid
    self.size = size

  def to_dict(self):
    return {
      "containerUuid": self.container_uuid,
      "size": self.size
    }


class AhvVmCreateSpec(object):
  __KEY_MAP__ = {
    "memory_mb": "memoryMb",
    "num_vcpus": "numVcpus",
    "num_cores_per_vcpu": "numCoresPerVcpu",
    "description": "description",
    "vm_nics": "vmNics",
    "vm_disks": "vmDisks",
    "name": "name"
  }

  @classmethod
  def from_salt_vm_dict(cls, vm_, conn):
    kwargs = {"name": vm_["name"],
              "container_name": vm_["container"]}

    for key in cls.__KEY_MAP__.iterkeys():
      if key in vm_:
        kwargs[key] = vm_[key]

    vm_spec = cls(**kwargs)

    vm_spec.resolve_container(conn)
    network_map = dict((n["name"], n) for n in conn.networks_get())

    for name, spec in vm_.get("network", {}).iteritems():
      if spec["name"] not in network_map:
        raise SaltCloudNotFound(
          "Unable to locate requested network '%s' for adapter '%s'" %
          (spec["name"], name))
      vm_spec.add_network(network_map[spec["name"]]["uuid"])
      #vm_spec.inject_network_script("eth0", vm_)

    for name, spec in vm_.get("disk", {}).iteritems():
      bus_type, bus_index = name.split(".")
      vm_spec.add_disk(spec["size"]*1024**3, bus_type, int(bus_index))

    if "clonefrom" in vm_:
      vms = conn.vms_get(name=vm_["clonefrom"])
      ASSERT(len(vms) == 1)
      vm_disk_uuid = vms[0]["nutanixVirtualDiskUuids"][0]
      # images_map = dict((i["name"], i) for i in conn.images_get())
      # ASSERT(vm_["clonefrom"] in images_map)
      # vm_disk_uuid = images_map[vm_["clonefrom"]]["vmDiskId"]
      # ret = conn.virtual_disk_get(vm_disk_uuid)

      if False: #ret.get("diskAddress"):
        # bus_type, bus_index = ret["diskAddress"].split(".")
        # vm_spec.clone_disk(vm_disk_uuid, bus_type, int(bus_index))
        pass
      else:
        vm_spec.clone_disk(vm_disk_uuid)

    return vm_spec

  def __init__(self, name, memory_mb=1024, num_vcpus=1,
               num_cores_per_vcpu=1, description="", container_name=""):
    self.description = description
    self.memory_mb = memory_mb
    self.name = name
    self.num_cores_per_vcpu = num_cores_per_vcpu
    self.num_vcpus = num_vcpus
    self.vm_disks = []
    self.vm_nics = []
    self.container_uuid = None
    self._container_name = container_name
    self._cloud_init_config = None

  def resolve_container(self, conn):
    try:
      ctr_json = conn.container_get(name=self._container_name)
    except AssertionError:
      raise SaltCloudNotFound(
        "Unable to locate requested container %s for VM %s",
        self._container_name, self.name)

    self.container_uuid = ctr_json["containerUuid"]

  def inject_network_script(self, device, vm_):
    net_json = vm_["network"].values()
    ASSERT(len(net_json) == 1,
           "Currently multiple network interfaces are not supported")
    net_json = net_json[0]

    ifcfg = IFCFG_TMPL.format(**{
      "DEVICE": device,
      "DNS_1": vm_["dns_servers"][0],
      "DNS_2": vm_["dns_servers"][1],
      "DOMAIN": net_json["domain"],
      "NETMASK": net_json["subnet_mask"],
      "GATEWAY": net_json["gateway"],
      "IPADDR": net_json["ip"]
    })


    self._cloud_init_config = CLOUD_INIT_TMPL.format(**{
      "CONTENT": base64.b64encode(ifcfg),
      "DEVICE": device
    })

  def add_network(self, uuid):
    self.vm_nics.append(AhvVmNicSpec(uuid))

  def add_cdrom(self):
    self.vm_disks.append(AhvDiskSpec("ide", is_empty=True, is_cdrom=True))

  def add_disk(self, size_bytes, bus_type, bus_index):
    ASSERT(
      self.container_uuid,
      "Cannot add disk without resolving container UUID from container name")
    spec = AhvDiskSpec(bus_type, bus_index)
    spec.vm_disk_create = AhvDiskCreateSpec(self.container_uuid,
                                            size=size_bytes)
    self.vm_disks.append(spec)

  def clone_disk(self, vm_disk_uuid,
                 bus_type="scsi", bus_index=None, minimum_size=1):
    spec = AhvDiskSpec(bus_type, bus_index)
    spec.vm_disk_clone = AhvDiskCloneSpec(vm_disk_uuid,
                                          minimum_size=minimum_size)
    self.vm_disks.append(spec)

  def to_dict(self):
    ret = {}
    for k, v in self.__KEY_MAP__.iteritems():
      # TODO (jklein): This is shit, clean up.
      _v = getattr(self, k)
      if isinstance(_v, list):
        for ii, e in enumerate(_v):
          if hasattr(e, "to_dict"):
            _v[ii] = e.to_dict()
      elif hasattr(_v, "to_dict"):
        _v = _v.to_dict()
      ret[v] = _v

    if self._cloud_init_config:
      ret["vmCustomizationConfig"] = {
        "filesToInjectList": [],
        "userdata": self._cloud_init_config
      }

    return ret

#==============================================================================
# REST API Client
#==============================================================================

class PrismAPIClient(object):
  def async_task(func):
    # pylint: disable=no-self-argument
    """
    Decorator for REST APIs corresponding to asynchronous tasks.
    """
    @functools.wraps(func)
    def _wrapped(*args, **kwargs):
      # pylint: disable=not-callable
      try:
        resp = func(*args, **kwargs).json()
      except Exception as exc:
        raise SaltCloudExecutionFailure(str(exc))

      if "taskUuid" not in resp:
        raise SaltCloudExecutionFailure()

      return resp["taskUuid"]

    return _wrapped

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

  def entity(func):
    # pylint: disable=no-self-argument
    """
    Decorator for REST API endpoints corresponding to a collection of entities.
    """
    @functools.wraps(func)
    def _wrapped(*args, **kwargs):
      # pylint: disable=not-callable
      try:
        return func(*args, **kwargs).json()
      except Exception as exc:
        raise SaltCloudExecutionFailure(str(exc))
    return _wrapped

  def __init__(self, host, user, password, port=9440,
               base_path="/PrismGateway/services/rest/v1",
               base_mgmt_path="/api/nutanix/v0.8"):
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

  #============================================================================
  # Public util methods
  #============================================================================

  def remove_cloud_init_cd(self, uuid):
    """
    Removes CD drive created to mount cloud-init scripts for VM 'uuid'.
    """
    # NB: Cloud-init CD drive is always created as ide:3.
    pass

  def poll_progress_monitor(self, uuid):
    while True:
      INFO("Waiting on '%s'", uuid)
      resp = self.progress_monitors_get(uuid=uuid)
      ASSERT(len(resp) == 1)
      pct_complete = int(resp[0].get("percentageCompleted", 0))
      if pct_complete == 100:
        return str(resp[0].get("status")).lower(), resp[0]

      INFO("Task in progress: %s", resp[0].get("status"))

      time.sleep(1)

  #============================================================================
  # Undocumented APIs
  #============================================================================

  @entity_list
  def progress_monitors_get(self, uuid=None):
    """
    Lookup progress information for tasks.

    Args:
      uuid (str|None): Optional. If provided, restrict query to the task
        specified by 'uuid'.

    Returns:
      requests.Response, content is serialized JSON containing:
        list<dict>: List of task info dicts.
    """
    url = "%s/progress_monitors" % self._base_path
    if uuid:
      url = "%s?filterCriteria=%s" % (url, urllib.quote("uuid==%s" % uuid))
    return self._get(url)

  #============================================================================
  # Public APIs (v1)
  #============================================================================

  @entity_list
  def clusters_get(self):
    return self._get("%s/clusters" % self._base_path)

  def container_get(self, name=None, uuid=None):
    ASSERT(bool(name) ^ bool(uuid),
           "Must specify exactly one of 'name', 'uuid'")
    resp = self._get(
      "%s/containers" % self._base_path,
      params={"searchString": name or uuid,
              "searchAttributeList":
                "container_name" if name else "container_uuid"}).json()
    ASSERT(int(resp["metadata"]["totalEntities"]) == 1)
    return resp["entities"][0]

  @entity_list
  def containers_get(self):
    return self._get("%s/containers" % self._base_path)

  @entity
  def virtual_disk_get(self, uuid):
    return self._get("%s/virtual_disks/%s" % (self._base_path, uuid))

  def vms_get(self, name=None, uuid=None):
    ASSERT(not (name and uuid))
    params = {}
    if uuid:
      return [self._get("%s/vms/%s" % (self._base_path, uuid)).json()]
    if name:
      params["searchString"] = name
      # NB: Fields as defined in $TOP/zeus/configuration.proto
      params["searchAttributeList"] = "vm_name"
    # TODO (jklein): Don't mix APIs.
    if params:
      return self._get(
        "%s/vms" % self._base_path, params=params).json()["entities"]
    return self._get("%s/vms" % self._base_mgmt_path).json()["entities"]

  @async_task
  def vms_create(self, spec):
    return self._post("%s/vms" % self._base_path,
                      data=json.dumps(spec.to_dict()))

  #============================================================================
  # Public APIs (mgmt v0.8)
  #============================================================================

  @entity_list
  def images_get(self):
    return self._get("%s/images" % self._base_mgmt_path)

  @entity_list
  def networks_get(self):
    return self._get("%s/networks" % self._base_mgmt_path)

  def tasks_poll(self, uuid, timeout_secs=60):
    """
    Blocks until completion of 'uuid' or specified timeout.

    If 'retries' is a positive integer, method will sleep and retry polling
    up to 'retries' times for a task which is not found.

    Args:
      uuid (str): UUID of task to poll.
      timeout_secs: (None|int): Optional. If a positive integer, the maximum
        time to wait on the task in seconds. Otherwise, no timeout is set.
    """
    DEBUG("Polling task '%s' with timeout %s", uuid, timeout_secs)
    params = {}
    if timeout_secs and timeout_secs > 0:
      params["timeoutseconds"] = timeout_secs

    resp = self._get("%s/tasks/%s/poll" % (self._base_mgmt_path, uuid),
                     params=params)
    resp, status_code = resp.json(), resp.status_code
    if resp.get("isUnrecognized"):
      raise SaltCloudNotFound("Task '%s' not recognized" % uuid)
    if resp.get("timedOut"):
      raise SaltCloudExecutionTimeout()

    resp = resp.get("taskInfo", {})
    error = resp.get("metaResponse", {}).get("error", "kNoError")
    status = resp.get("progressStatus", "").lower()
    success = all([
      error == "kNoError", status == "succeeded", status_code == 200])
    return success, resp

  @async_task
  def vms_delete(self, uuid):
    """
    Deletes the VM specified by 'uuid'.

    Asynchronous operation, returns UUID of the corresponding task.

    Raises:
      SaltCloudExecutionFailure if delete task is not created successfully.
    """
    return self._delete("%s/vms/%s" % (self._base_mgmt_path, uuid))

  @async_task
  def vms_power_op(self, uuid, op):
    """
    Performs power operation 'op' on VM specified by 'uuid'.

    Args:
      uuid (str): UUID of VM on which to perform 'op'.
      op (str): Power to perform on the VM. Either "on" or "off".
    """
    op = str(op).lower()
    ASSERT(op in ["on", "off"])
    vm_json = self.vms_get(uuid=uuid)[0]
    if vm_json.get("powerState") == op:
      INFO("Skipping power op for VM '%s' already in requested state '%s'",
           uuid, op)
      return None

    return self._post("%s/vms/%s/power_op/%s" %
                      (self._base_mgmt_path, uuid, op), data="{}")

  #============================================================================
  # Protected util methods
  #============================================================================

  def _get(self, path, params=None):
    return self._issue_request(
      "GET", "%s/%s" % (self._base_url, path), params=params)

  def _delete(self, path, params=None):
    return self._issue_request(
      "DELETE", "%s/%s" % (self._base_url, path), params=params)

  def _post(self, path, data=None, params=None):
    return self._issue_request("POST", "%s/%s" % (self._base_url, path),
                               data=data, params=params)

  def _issue_request(self, verb, url, data=None, params=None):
    func = getattr(self._session, verb.lower())
    if not func:
      raise SaltCloudSystemExit("Invalid HTTP method '%s'" % verb)

    return func(url, data=data, params=params if params else {},
                verify=False)

#==============================================================================
# Utils
#==============================================================================

def get_configured_provider():
  return salt.config.is_provider_configured(
    __opts__, __active_provider_name__ or __virtualname__, required_keys=(
      "user", "password", "prism_ip"))


def get_dependencies():
  return salt.config.check_driver_dependencies(__virtualname__, {
    "requests": _HAS_REQUESTS})


def get_conn():
  conf = get_configured_provider()
  return PrismAPIClient(conf["prism_ip"], conf["user"], conf["password"])


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


def remove_keys(entity, keys):
  for key in keys:
    if key in entity:
      del entity["key"]

  return entity

#==============================================================================
# Decorators
#==============================================================================

def action(func):
  """
  Decorator which ensures 'func' was properly called as an "action".
  """
  @functools.wraps(func)
  def _action(*args, **kwargs):
    if kwargs.get("call") != "action":
      raise SaltCloudSystemExit(
        "The %s action must be invoked with -a or --action" % func.__name__)
    return func(*args, **kwargs)
  return _action


def function(func):
  """
  Decorator which ensures 'func' was properly called as a "function".
  """
  @functools.wraps(func)
  def _action(*args, **kwargs):
    if kwargs.get("call") != "function":
      raise SaltCloudSystemExit(
        "The %s action must be invoked with -f or --function" % func.__name__)
    return func(*args, **kwargs)
  return _action


def conn_in(func):
  """
  Decorator which acquires and injects a REST client if necessary.
  """
  @functools.wraps(func)
  def _conn_in(*args, **kwargs):
    if "conn" not in kwargs:
      kwargs["conn"] = get_conn()
    return func(*args, **kwargs)
  return _conn_in


def fire_start_end_events(start_event, end_event):
  def fire_start_end_events_decorator(func):
    def _wrapped(vm_, *args, **kwargs):
      _vm_ = vm_
      if isinstance(vm_, basestring):
        vm_ = {"name": vm_}
      start_event.fire(vm_)
      ret = func(_vm_, *args, **kwargs)
      end_event.fire(vm_)
      return ret

    return _wrapped
  return fire_start_end_events_decorator

#==============================================================================
# Salt cloud driver interface
#==============================================================================

def __virtual__():
  if not (get_configured_provider() and get_dependencies()):
    return False
  return __virtualname__


@fire_start_end_events(SaltCreatingEvent, SaltCreatedEvent)
@conn_in
def create(vm_, conn=None, call=None):
  """
  Create a VM as defined by 'vm_'.

  Args:
    vm_ (dict): VM configuration as provided by salt cloud.
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.
  """
  ret = {"status":
           {"created": False,
            "powered on": False,
            "minion deployed": False}
         }
  INFO("Handling create request for VM %s...", vm_["name"])

  vm_spec = AhvVmCreateSpec.from_salt_vm_dict(vm_, conn)
  DEBUG("Generated VmCreateSpec: %s",
        json.dumps(vm_spec.to_dict(), indent=2, sort_keys=True))

  INFO("Issuing VM Create request...")
  SaltRequestingEvent.fire(vm_)
  task_uuid = conn.vms_create(vm_spec)
  DEBUG("VM Create task '%s' created", task_uuid)

  INFO("Waiting for VM creation to complete...")
  success, task_json = conn.poll_progress_monitor(task_uuid)
  if not success:
    raise SaltCloudExecutionTimeout()
  DEBUG("VM Creation task '%s' complete", task_uuid)
  ret["status"]["created"] = True

  if not vm_.get("power_on"):
    return ret

  INFO("Powering on VM...")
  task_uuid = conn.vms_power_op(task_json["entityId"][0], "on")
  DEBUG("VM Power Op task '%s' created", task_uuid)
  success, task_json = conn.poll_progress_monitor(task_uuid)
  if not success:
    raise SaltCloudExecutionTimeout()
  INFO("VM powered on successfully")
  ret["status"]["powered on"] = True

  if not vm_.get("deploy"):
    return ret

  SaltDeployingEvent.fire(vm_)
  # TODO (jklein): Cap waiting at something.
  INFO("Waiting for VM %s to acquire IP...", vm_["name"])
  t0 = time.time()
  while True:
    DEBUG("Waiting for VM %s to acquire IP... %d seconds",
          vm_["name"], time.time() - t0)
    vm_json = conn.vms_get(name=vm_["name"])[0]
    if vm_json["ipAddresses"]:
      INFO("Acquired IP: %s", vm_json["ipAddresses"])
      vm_["ssh_host"] = vm_json["ipAddresses"][0]
      break

    time.sleep(1)

  INFO("Bootstrapping salt...")
  SaltWaitingForSSHEvent.fire(vm_)
  __utils__["cloud.bootstrap"](vm_, __opts__)
  INFO("Bootstrap complete! Finished creating VM %s", vm_["name"])
  ret["status"]["deployed minion"] = True
  return ret


@conn_in
@fire_start_end_events(SaltDestroyingEvent, SaltDestroyedEvent)
def destroy(vm_name, conn=None, call=None):
  """
  Destroys VM 'vm_name'.

  Args:
    vm_name (str): Name of VM to destroy.
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  Raises:
    SaltCloudNotFound if unable to locate a matching VM, or if 'name' does
      not uniquely identify the VM.
  """
  INFO("Deleting VM '%s'", vm_name)
  vm_json = get_entity_by_key(conn.vms_get(name=vm_name), "vmName", vm_name)
  task_uuid = conn.vms_delete(vm_json["uuid"])
  DEBUG("Created VM Delete task '%s'", task_uuid)

  if not conn.tasks_poll(task_uuid):
    raise SaltCloudException("Deletion task failed for VM %s" % vm_name)

  INFO("Deleted VM %s", vm_name)



@conn_in
def avail_locations(conn=None, call=None):
  """
  List available clusters.

  Args:
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    list<str>: List of cluster names accessible via the configured Prism IP.
  """
  return dict((c["name"], c) for c in conn.clusters_get())


@conn_in
def avail_images(conn=None, call=None):
  """
  List available VM images.

  Args:
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    dict<str,dict>: Map of image names to image metadata for all images known
      to the image service.
  """
  return dict((i["name"], i) for i in conn.images_get())


def avail_sizes(call=None):
  """
  Args:
    call (str|None): Kind of call by which this function was invoked.
  """
  return {
    "<num_vcpus>": "Number of vCPUs with which to configure the VM",
    "<num_cores_per_vcpu>":
      "Number of cores with which to configure each vCPU",
    "<memory_mb>": "Amount (in MB) of RAM with which to configure the VM",
  }


@conn_in
def list_nodes(conn=None, call=None):
  """
  Args:
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  NB: Terminology conflicts with Acropolis terminology.

  Returns:
    dict<str,SaltVm>: Canonical salt metadata for available VMs.
  """
  return dict((vm["config"]["name"], SaltVm(vm).to_dict())
              for vm in conn.vms_get())


@conn_in
def list_nodes_full(conn=None, call=None):
  """
  Args:
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  NB: Terminology conflicts with Acropolis terminology.

  Returns:
    dict<str,AcropolisVm>: Canonical salt metadata enriched with
      additional Acropolis-specific metadata for available VMs.
  """
  return dict((vm["config"]["name"], vm) for vm in conn.vms_get())


@conn_in
def list_nodes_select(conn=None, call=None):
  """
  Args:
    call (str|None): Kind of call by which this function was invoked.
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.

  NB: Terminology conflicts with Acropolis terminology.

  Returns:
    list<AcropolisVm>: Metadata for available VMs restricted to specified
      fields.
  """
  return salt.utils.cloud.list_nodes_select(
    list_nodes_full(conn=conn, call="function"),
    __opts__["query.selection"], call)


@action
@conn_in
def show_instance(name, conn=None, call=None):
  """
  Shows details about VM 'name'.

  Args:
    name (str): Name of VM to query.
    conn (PrismAPIClient|None): Optional. Connection to use. If None, a new
      connection will be injected by the @conn_in decorator.
    call (str|None): Method by which this functions is being invoked.
  """
  vm_json = get_entity_by_key(conn.vms_get(name=name), "vmName", name)
  return remove_keys(vm_json, ["stats, usageStats"])

#==============================================================================
# Additional public actions, functions
#==============================================================================

@function
def generate_sample_profile(call=None):
  pass


@function
def generate_sample_map(call=None):
  pass
