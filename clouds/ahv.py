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

:depends: requests >= 2.6.0

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
import json
import logging
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



#=============================================================================
# salt entities
#=============================================================================
# TODO (jklein): Clean this up too...
class SaltVm(object):
  __KEYS__ = ("id", "image", "size", "state", "private_ips", "public_ips")

  def __init__(self, entity_json):
    config_json = entity_json["config"]

    # VM UUID
    self.id = entity_json["uuid"]

    # TODO (jklein): See if we need to convert/restrict to a canonical set of
    # Salt-defined states.
    self.state = entity_json["state"]

    # Name of image from which VM was created
    self.image = config_json.get("sourceImage", "")

    # Resource info for VM
    self.size = "%s vCPUs, %s MB RAM" % (
      config_json["numVcpus"], config_json["memoryMb"])

    # VM external IPs
    self.public_ips = entity_json.get("ipAddresses", [])

    # VM internal IPs
    self.private_ips = []

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
    if bus_index is not None:
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
    # assert "name" in vm_
    assert "container" in vm_

    kwargs = {}

    clone_vm_uuid = None
    if "clonefrom_vm" in vm_:
      clone_target_json = conn.vms_get(name=vm_["clonefrom_vm"])
      assert len(clone_target_json) == 1
      clone_target_json = clone_target_json[0]

      for key, val in cls.__KEY_MAP__.iteritems():
        if val in clone_target_json:
          kwargs[key] = clone_target_json[val]

      clone_vm_uuid = clone_target_json["uuid"]

    # TODO (jklein): Support cloning from image service.
    #if "clonefrom_image_service":
    # images_map = dict((i["name"], i) for i in conn.images_get())
    # assert vm_["clonefrom"] in images_map
    # vm_disk_uuid = images_map[vm_["clonefrom"]]["vmDiskId"]
    # ret = conn.virtual_disk_get(vm_disk_uuid)

    for key in cls.__KEY_MAP__.iterkeys():
      if key in vm_:
        kwargs[key] = vm_[key]
    kwargs["container_name"] = vm_["container"]
    vm_spec = cls(**kwargs)

    vm_spec.resolve_container(conn)
    network_map = dict((n["name"], n) for n in conn.networks_get())

    if not "clonefrom_vm" in vm_:
      pass
      # for vm_disk_uuid in clone_target_json["nutanixVirtualDiskUuids"]:
      #   vm_disk_json = conn.virtual_disk_get(vm_disk_uuid)
      #   bus_type, bus_index = vm_disk_json["diskAddress"].split(".")
      #   vm_spec.clone_disk(vm_disk_uuid, bus_type, int(bus_index))


    for name, spec in vm_.get("network", {}).iteritems():
      if spec["name"] not in network_map:
        raise SaltCloudNotFound(
          "Unable to locate requested network '%s' for adapter '%s'" %
          (spec["name"], name))
      vm_spec.add_network(network_map[spec["name"]]["uuid"])
      vm_spec.inject_network_script("eth0", vm_)

    # for name, spec in vm_.get("disk", {}).iteritems():
    #   bus_type, bus_index = name.split(".")
    #   vm_spec.add_disk(spec["size"]*1024**3, bus_type, int(bus_index))

    if False:
    #if "clonefrom_vm" in vm_:
      if False: #ret.get("diskAddress"):
        # bus_type, bus_index = ret["diskAddress"].split(".")
        # vm_spec.clone_disk(vm_disk_uuid, bus_type, int(bus_index))
        pass
      else:
        #vm_spec.clone_disk(vm_disk_uuid)
        pass

    return clone_vm_uuid, vm_spec

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
      raise SaltCloudNotFound("Unable to locate container %s for VM %s" %
        (self._container_name, self.name))

    self.container_uuid = ctr_json["containerUuid"]

  def inject_network_script(self, device, vm_):
    self._cloud_init_config = ""

  def add_network(self, uuid):
    self.vm_nics.append(AhvVmNicSpec(uuid))

  def add_cdrom(self):
    self.vm_disks.append(AhvDiskSpec("ide", is_empty=True, is_cdrom=True))

  def add_disk(self, size_bytes, bus_type, bus_index):
    assert self.container_uuid, \
      "Cannot add disk without resolving container UUID from container name"
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

class LegacyClient(object):
  """
  Client for the Prism v1 REST API and v0.8 management REST API.
  """

  #============================================================================
  # Decorators
  #============================================================================

  def async_task(*func, **kwargs):
    # pylint: disable=no-self-argument,no-method-argument
    """
    Decorator for REST APIs corresponding to asynchronous tasks.
    """
    def _async_task_wrapper(_func):
      @functools.wraps(_func)
      def _wrapped(self, *_args, **_kwargs):
        # pylint: disable=not-callable
        try:
          resp = _func(self, *_args, **_kwargs).json()
        except Exception as exc:
          raise SaltCloudExecutionFailure(str(exc))

        if "taskUuid" not in resp:
          raise SaltCloudExecutionFailure(resp)

        task_uuid = resp["taskUuid"]
        if not kwargs.get("block", True):
          return task_uuid

        timeout_secs = kwargs.get("timeout_secs", 60)
        logger.debug("Blocking on task '%s' (timeout: %s seconds)" %
          (task_uuid, timeout_secs))
        success, resp_json = self.poll_progress_monitor(
          task_uuid, timeout_secs=timeout_secs)
        if kwargs.get("raise_on_error", True) and not success:
          raise SaltCloudExecutionFailure()

        return resp_json

      return _wrapped

    # Check for case where optional arguments are omitted and decorator is
    # applied directly to the target function.
    if func:
      assert len(func) == 1 and callable(func[0]), \
             "Unexpected argument provided to @async_task"
      assert not kwargs, \
        "@async_task passed a callable argument, but was not applied as a " \
        "parameter-free decorator"
      return _async_task_wrapper(func[0])
    return _async_task_wrapper

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

  #============================================================================
  # Init
  #============================================================================

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

  def remove_cloud_init_cd(self, uuid, device_index=3):
    """
    Removes CD drive created to mount cloud-init scripts for VM 'uuid'.
    """
    # NB: Currently cloud-init CD drive is always created as ide-3.
    self.vms_power_op(uuid, "off")
    task_uuid = self._delete(
      "%s/vms/%s/disks/ide-%d" %
      (self._base_mgmt_path, uuid, device_index)).json()["taskUuid"]
    success, _ = self.poll_progress_monitor(task_uuid)
    if not success:
      raise SaltCloudException()
    self.vms_power_op(uuid, "on")

  def poll_progress_monitor(self, uuid, timeout_secs=60):
    deadline_secs = time.time() + timeout_secs
    while time.time() < deadline_secs:
      logger.debug("Waiting on task '%s'" % uuid)
      resp = self.progress_monitors_get(uuid=uuid)
      assert len(resp) == 1
      pct_complete = int(resp[0].get("percentageCompleted", 0))
      if pct_complete == 100:
        return str(resp[0].get("status")).lower(), resp[0]

      logger.debug("Task in progress: %s" % resp[0].get("status"))

      time.sleep(1)

    raise SaltCloudExecutionTimeout("Task '%s' timed out after %s seconds" %
                                    (uuid, timeout_secs))

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
    """
    Looks up available clusters.
    """
    return self._get("%s/clusters" % self._base_path)

  def container_get(self, name=None, uuid=None):
    """
    Looks up a storage container by 'name' or 'uuid'.
    """
    assert bool(name) ^ bool(uuid), \
           "Must specify exactly one of 'name', 'uuid'"
    resp = self._get(
      "%s/containers" % self._base_path,
      params={"searchString": name or uuid,
              "searchAttributeList":
                "container_name" if name else "container_uuid"}).json()
    assert int(resp["metadata"]["totalEntities"]) == 1
    return resp["entities"][0]

  @entity_list
  def containers_get(self):
    """
    Lists available storage containers.
    """
    return self._get("%s/containers" % self._base_path)

  @entity
  def virtual_disk_get(self, uuid):
    """
    Looks up a virtual disk by 'uuid'.
    """
    return self._get("%s/virtual_disks/%s" % (self._base_path, uuid))

  def vms_get(self, name=None, uuid=None):
    """
    Looks up available VMs, filtering on 'name' or 'uuid' if provided.
    """
    assert not (name and uuid)
    params = {}
    if uuid:
      return [self._get("%s/vms/%s" % (self._base_path, uuid)).json()]
    if name:
      params["searchString"] = name
      # NB: Fields as defined in $TOP/zeus/configuration.proto
      params["searchAttributeList"] = "vm_name"
    if params:
      ret = self._get(
        "%s/vms" % self._base_path, params=params).json()["entities"]
      for vm_json in ret:
        if vm_json["vmName"] == name:
          return [vm_json]
    # TODO (jklein): Doesn't seem to be any way to avoid querying both APIs.
    ret = self._get("%s/vms" % self._base_mgmt_path).json()["entities"]
    ret2 = dict((vm_json["vmName"], vm_json)
                for vm_json in self._get(
                  "%s/vms" % self._base_path).json()["entities"])

    for vm_json in ret:
      vm_json.update(ret2[vm_json["config"]["name"]])

    return ret

  @async_task
  def vms_create(self, spec):
    """
    Creates a new VM according to 'spec'.

    Raises:
      SaltCloudExecutionFailure if the task is not created successfully.
    """
    return self._post("%s/vms" % self._base_path,
                      data=json.dumps(spec.to_dict()))

  @async_task
  def vms_clone(self, uuid, spec):
    """
    Clones VM with UUID 'uuid' according to 'spec'.

    Raises:
      SaltCloudExecutionFailure if the task is not created successfully.
    """
    spec = remove_keys(spec.to_dict(), "vmDisks")
    spec["overrideNetworkConfig"] = True
    for nic in spec["vmNics"]:
      nic["requestIp"] = False
    customization = spec.pop("vmCustomizationConfig")
    return self._post("%s/vms/%s/clone" % (self._base_path, uuid),
                      data=json.dumps(
                        {"specList": [spec, ],
                         "vmCustomizationConfig": customization}))

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
    logger.debug("Polling task '%s' with timeout %s", uuid, timeout_secs)
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
      SaltCloudExecutionFailure if the task is not created successfully.
    """
    return self._delete("%s/vms/%s" % (self._base_mgmt_path, uuid))

  @async_task
  def vms_power_op(self, uuid, op):
    """
    Performs power operation 'op' on VM specified by 'uuid'.

    Args:
      uuid (str): UUID of VM on which to perform 'op'.
      op (str): Power to perform on the VM. Either "on" or "off".

    Raises:
      SaltCloudExecutionFailure if the task is not created successfully.
    """
    op = str(op).lower()
    assert op in ["on", "off"]
    vm_json = self.vms_get(uuid=uuid)[0]
    if vm_json.get("powerState") == op:
      logger.debug("Skipping power op for VM '%s' already in requested state "
        "'%s'", uuid, op)
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

    return func(url, data=data, params=params if params else {}, verify=False)

#==============================================================================
# Utils
#==============================================================================
def get_conn(version=2):
  clienttype = AplosClient
  if version < 3:
    clienttype = LegacyClient
  conf = get_configured_provider()
  client = clienttype(
    host=conf["prism_host"],
    user=conf["prism_user"],
    password=conf["prism_password"]
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


def remove_keys(entity, keys):
  for key in keys:
    if key in entity:
      del entity["key"]

  return entity


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
    "os_family",
    "num_vcpus",
    "num_cores_per_vcpu",
    "memory_size_mib",
    "network"
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



def create(vm_, call=None):
  result = {
    "created": False,
    "powered": False,
    "bootstrapped": False
  }

  if vm_["profile"] and not is_profile_configured(__opts__,
      __active_provider_name__ or __virtualname__,
      vm_["profile"],
      vm_=vm_):
    return result

  CreatingInstanceEvent(vm_).fire()
  conn = get_conn(version=3)

  logg = _attach_vm_context(vm_)
  logg.info("Creating instance ...")

  cluster_uuid = vm_["cluster_uuid"]
  clone_from = vm_["clone_from"]
  vm_name = vm_["name"]
  os_family = vm_["os_family"]

  logg.debug("Requesting Prism clone_vm ...")
  RequestingInstanceEvent(vm_).fire()
  QueryingInstanceEvent(vm_).fire()
  task_json = conn.clone_vm(
    cluster_uuid=cluster_uuid,
    clone_from=clone_from,
    os_family=os_family,
    vm_name=vm_name,
    nics=vm_["network"],
    memory_size_mib=vm_["memory_size_mib"],
    num_vcpus=vm_["num_vcpus"],
    num_cores_per_vcpu=vm_["num_cores_per_vcpu"],
    power_on=vm_["power_on"]
  )
  logg.debug("VM clone complete")

  logg.info("VM created")
  result["created"] = True
  CreatedInstanceEvent(vm_).fire()

  return result

def _create(vm_, call=None):
  """
  Create a VM as defined by 'vm_'.

  Args:
    vm_ (dict): VM configuration as provided by salt cloud.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str,str>): Map of configuration steps to boolean success.
  """
  CreatingInstanceEvent(vm_).fire()
  conn = get_conn()

  logg = _attach_vm_context(vm_)
  ret = {"created": False,
         "powered on": False,
         "deployed minion": False}
  logg.info("Handling instance create...")

  clone_vm_uuid, vm_spec = AhvVmCreateSpec.from_salt_vm_dict(vm_, conn)
  logg.debug("Generated VmCloneSpec: %s" %
    json.dumps(vm_spec.to_dict(), indent=2, sort_keys=True))

  logg.debug("Issuing CloneVM request to Prism...")
  RequestingInstanceEvent(vm_).fire()
  task_json = conn.vms_clone(clone_vm_uuid, vm_spec)
  logg.debug("VM clone task complete")

  QueryingInstanceEvent(vm_).fire()
  logg.info("VM created")
  ret["created"] = True

  if not vm_.get("power_on"):
    CreatedInstanceEvent(vm_).fire()
    return ret

  logg.info("Powering on VM")
  vm_uuid = task_json["entityId"][0]
  conn.vms_power_op(vm_uuid, "on")
  logg.info("VM powered on successfully")
  ret["powered on"] = True

  WaitingForSshInstanceEvent(vm_).fire()
  # TODO (jklein): Cap waiting at something.
  logg.info("Waiting for VM to acquire IP...")
  t0 = time.time()
  while True:
    logg.debug("Waiting for VM to acquire IP...%d seconds", time.time() - t0)
    vm_json = conn.vms_get(name=vm_["name"])[0]
    if vm_json["ipAddresses"]:
      logg.info("Acquired IP: %s" % vm_json["ipAddresses"])
      vm_["ssh_host"] = vm_json["ipAddresses"][0]
      break

    time.sleep(1)

  logg.info("Detaching cloud-init customization CD...")
  conn.remove_cloud_init_cd(vm_uuid)
  logg.info("Detached cloud-init customization CD")

  # TODO (jklein): Cap waiting at something.
  logg.info("Waiting for VM to acquire IP...")
  t0 = time.time()
  while True:
    logg.debug("Waiting for VM to acquire IP...%d seconds",
      time.time() - t0)
    vm_json = conn.vms_get(name=vm_["name"])[0]
    if vm_json["ipAddresses"]:
      logg.info("Acquired IP: %s" % vm_json["ipAddresses"])
      vm_["ssh_host"] = vm_json["ipAddresses"][0]
      if vm_["ssh_host"] == vm_["network"].values()[0]["ip"]:
        break
      else:
        logg.error("Incorrect IP detected: %s" % vm_["ssh_host"])

    time.sleep(1)

  if not vm_.get("deploy"):
    CreatedInstanceEvent(vm_).fire()
    return ret

  logg.info("Bootstrapping salt...")
  __utils__["cloud.bootstrap"](vm_, __opts__)
  logg.info("Bootstrap complete!")
  ret["deployed minion"] = True

  CreatedInstanceEvent(vm_).fire()
  return ret



def destroy(vm_name, call=None):
  """
  Destroys VM 'vm_name'.

  Args:
    vm_name (str): Name of VM to destroy.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    {"message": <str>} Message to display on success.

  Raises:
    SaltCloudNotFound if unable to locate a matching VM, or if 'name' does
      not uniquely identify the VM.
  """
  DestroyingInstanceEvent(vm_name).fire()

  conn = get_conn()

  logg = _attach_vm_context({"name": vm_name})
  logg.info("Handling instance destroy...")
  vm_json = get_entity_by_key(conn.vms_get(name=vm_name), "vmName", vm_name)
  task_uuid = conn.vms_delete(vm_json["uuid"])
  logg.debug("Created VM Delete task")
  if not conn.tasks_poll(task_uuid):
    raise SaltCloudException("Deletion task failed for VM '%s'" % vm_name)

  logg.info("Deleted VM")
  DestroyedInstanceEvent(vm_name).fire()
  return {"message": "Successfully deleted"}



def avail_locations(call=None):
  """
  List available clusters.

  Args:
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str,dict>): Map of cluster names to cluster metadata for clusters
      accessible via the configured Prism IP.
  """
  if call != "function" and call is not None:
    raise SaltCloudSystemExit("The avail_locations function must be called "
      "with -f or --function, or with the --list-locations option.")

  conn = get_conn()
  return dict((cluster["name"], cluster) for cluster in conn.clusters_get())

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

def list_nodes(call=None):
  """
  Args:
    call (str|None): Method by which this functions is being invoked.

  NB: Terminology conflicts with Acropolis terminology.

  Returns:
    (dict<str,SaltVm>) Map of VM names to canonical salt metadata for
      corresponding VMs.
  """
  if call == "action":
    raise SaltCloudSystemExit("The list_nodes function cannot be called "
      "as an action.")

  conn = get_conn()
  return dict((vm["vmName"], SaltVm(vm).to_dict()) for vm in conn.vms_get())

def show_instance(name, call=None):
  """
  Shows details about VM 'name'.

  Args:
    name (str): Name of VM to query.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str, AcropolisVm>) Map of VM name to full VM metadata.
  """
  if call != "action":
    raise SaltCloudSystemExit("The show_instance action must be called "
      "with -a or --action.")

  conn = get_conn()

  vm_json = get_entity_by_key(conn.vms_get(name=name), "vmName", name)
  return remove_keys(vm_json, ["stats, usageStats"])



# ===========================================================================
# Prism v3 client
# ===========================================================================
CENTOS7_CLOUD_CFG=r"""#cloud-config
write_files:
  - path: /etc/sysconfig/network-scripts/ifcfg-eth0
    owner: root:root
    permissions: '0644'
    content: |
      DEVICE=eth0
      TYPE=Ethernet
      DEFROUTE=yes
      NM_CONTROLLED=no
      IPV4_FAILURE_FATAL=yes
      IPV6INIT=no
      ONBOOT=yes

      BOOTPROTO=none
      IPADDR=<desired-ip>
      PREFIX=24
      GATEWAY=10.4.10.1
      DNS1=10.4.8.15
      DNS2=10.4.8.16
      DOMAIN="it.nutanix.com corp.nutanix.com nutanix.com"

bootcmd:
  - rm -f /etc/resolv.conf*
  - ifdown eth0 && ifup eth0
  - ip -o -4 addr list eth0 | awk '{ print $4 }' | cut -d/ -f1 | awk '{ printf "\n%-11s %-31s %s\n", $1, "<desired-hostname>.it.nutanix.com", "<desired-hostname>"}' >> /etc/hosts
runcmd:
  - hostnamectl set-hostname <desired-hostname>.it.nutanix.com
  - touch /etc/cloud/cloud-init.disabled

datasource_list:
  - ConfigDrive
cloud_init_modules:
  - write_files
  - bootcmd
cloud_config_modules:
  - runcmd
  - scripts_user
cloud_final_modules:
  - final_message
"""

UBUNTU_CLOUD_CFG=r"""#cloud-config
hostname: <desired-hostname>
fqdn: <desired-hostname>.it.nutanix.com
write_files:
  - path: /etc/network/interfaces
    owner: root:root
    permissions: '0644'
    content: |
      # This file describes the network interfaces available on your system
      # and how to activate them. For more information, see interfaces(5).

      source /etc/network/interfaces.d/*

      # The loopback network interface
      auto lo
      iface lo inet loopback

      # The primary network interface
      auto eth0
      iface eth0 inet static
        address <desired-ip>
        netmask 255.255.255.0
        gateway 10.4.10.1
        dns-nameservers 10.4.8.15 10.4.8.16
        dns-search it.nutanix.com corp.nutanix.com nutanix.com

bootcmd:
  - rm -f /run/resolvconf/resolv.conf
  - ifdown eth0 && ifup eth0
  - ip -o -4 addr list eth0 | awk '{ print $4 }' | cut -d/ -f1 |
    awk '{ printf "\n%-11s %-31s %s\n", $1, "<desired-hostname>.it.nutanix.com", "<desired-hostname>"}' >> /etc/hosts
runcmd:
  - touch /etc/cloud/cloud-init.disabled

datasource_list:
  - ConfigDrive
cloud_init_modules:
  - write_files
  - bootcmd
  - set_hostname
cloud_config_modules:
  - runcmd
  - scripts_user
cloud_final_modules:
  - final_message

system_info:
  distro: ubuntu
"""

CLOUDINIT_MAP = {
  "centos-7": CENTOS7_CLOUD_CFG,
  "ubuntu": UBUNTU_CLOUD_CFG
}

# ===========================================================================
# api entities
# ===========================================================================
class AplosVmStatus(object):
  @classmethod
  def from_dict(klass, data):
    data = defaultdict(dict, data)

    metadata = data["metadata"]
    uuid = metadata.get("uuid")

    status = data["status"]
    name = status.get("name")

    kwargs = {
      "rawstatus": status,
      "uuid": uuid,
      "name": name
    }
    return klass(**kwargs)

  def __init__(self, rawstatus, uuid, name):
    self._status = rawstatus

    self.uuid = uuid
    self.name = name

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

  def to_dict(self):
    return {
      "adapter_type": self.adapter,
      "device_index": self.index
    }

CLOUDINIT_DISK = AplosDisk(AplosDiskAddress("ide", 3), "CDROM")



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
  def track_request(klass,
      status,
      result,
      status_fn,
      status_retries=100,
      status_wait_secs=3,
      completed_fn=None
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
        end_time = time.time()
        time_taken = end_time - start_time
        logger.info("Time to completion (seconds): {:.2f}".format(time_taken))
        return result

      (status, result) = status_fn(uuid)
      time.sleep(status_wait_secs)

    klass.print_failure(result)
    return None



class AplosClient(object):
  def __init__(self, host, user, password):
    self.host = host
    self.user = user
    self.password = password

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
    verify = False # allow unverified https

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

  # =========================================================================
  # commands
  # =========================================================================
  def clone_vm(self,
      cluster_uuid,
      clone_from,
      os_family,
      vm_name,
      nics=None,
      memory_size_mib=2048,
      num_vcpus=2,
      num_cores_per_vcpu=1,
      power_on=True):
    logger.info("Looking for template {}".format(clone_from))
    status, result = self.get_vm_by_name(clone_from)
    if status >= 300:
      logger.error("Failed to fetch info for template {}".format(clone_from))
      AplosUtil.print_failure(result)
      return False

    template_vm = AplosVmStatus.from_dict(result)
    logger.info("Cloning VM from template {}".format(template_vm.name))

    status, result = self.create_vm(
      cluster_uuid,
      template_vm,
      vm_name,
      os_family=os_family,
      nics=nics,
      memory_size_mib=memory_size_mib,
      num_vcpus=num_vcpus,
      num_cores_per_vcpu=num_cores_per_vcpu
    )
    if status >= 300:
      logger.error(json.dumps(result, indent=2))
      return False

    logger.debug("{}\n{}".format(status, json.dumps(result, indent=2)))
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

    logger.debug("{}\n{}".format(status, json.dumps(result, indent=2)))
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

    # Power-on and reboot for cloudinit

    # Final VM configuration
    status, result = self.get_vm_by_uuid(vm_uuid)
    if status == 200:
      logger.info("VM: {}".format(json.dumps(result, indent=2)))
    else:
      logger.error("Failed to get the information for vm {}".format(vm_uuid))
      AplosUtil.print_failure(result)
      return

    return True

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

    return status, entities[0]

  def get_vm_by_uuid(self, uuid):
    """ Get a VM by its UUID """
    endpoint = "vms/{}".format(uuid)
    status, result = self.GET(endpoint=endpoint)
    return status, result

  def create_vm(self,
      cluster_uuid,
      template_vm,
      vm_name,
      os_family,
      nics,
      memory_size_mib=2048,
      num_vcpus=2,
      num_cores_per_vcpu=1):

    static_ip = defaultdict(dict, nics)["nic.0"]["ip"]
    userdata = CLOUDINIT_MAP.get(os_family).replace(
        "<desired-ip>", static_ip).replace(
        "<desired-hostname>", vm_name)
    metadata = json.dumps({
      "uuid": vm_name,
      "network": {
        "config": "disabled"
      }
    })

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
    spec["resources"]["power_state"] = "ON"
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
