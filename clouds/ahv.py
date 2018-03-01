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

import functools
import json
import logging
import time
import urllib

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
# Salt entities
#==============================================================================

class SaltEvent(object):
  @classmethod
  def _fire(cls, event, path, vm_):
    logger.debug("Firing %s event for %s" % (event, vm_["name"]))
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

class PrismAPIClient(object):
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
def get_conn():
  conf = get_configured_provider()
  client = PrismAPIClient(
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
def create(vm_, call=None):
  """
  Create a VM as defined by 'vm_'.

  Args:
    vm_ (dict): VM configuration as provided by salt cloud.
    call (str|None): Method by which this functions is being invoked.

  Returns:
    (dict<str,str>): Map of configuration steps to boolean success.
  """
  SaltCreatingEvent.fire(vm_)

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
  SaltRequestingEvent.fire(vm_)
  task_json = conn.vms_clone(clone_vm_uuid, vm_spec)
  logg.debug("VM clone task complete")
  logg.info("VM created")
  ret["created"] = True

  if not vm_.get("power_on"):
    SaltCreatedEvent.fire(vm_)
    return ret

  logg.info("Powering on VM")
  vm_uuid = task_json["entityId"][0]
  conn.vms_power_op(vm_uuid, "on")
  logg.info("VM powered on successfully")
  ret["powered on"] = True

  if not vm_.get("deploy"):
    SaltCreatedEvent.fire(vm_)
    return ret

  SaltDeployingEvent.fire(vm_)
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

  logg.info("Bootstrapping salt...")
  SaltWaitingForSSHEvent.fire(vm_)
  __utils__["cloud.bootstrap"](vm_, __opts__)
  logg.info("Bootstrap complete!")
  ret["deployed minion"] = True

  SaltCreatedEvent.fire(vm_)
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
  SaltDestroyingEvent.fire(vm_name)

  conn = get_conn()

  logg = _attach_vm_context({"name": vm_name})
  logg.info("Handling instance destroy...")
  vm_json = get_entity_by_key(conn.vms_get(name=vm_name), "vmName", vm_name)
  task_uuid = conn.vms_delete(vm_json["uuid"])
  logg.debug("Created VM Delete task")
  if not conn.tasks_poll(task_uuid):
    raise SaltCloudException("Deletion task failed for VM '%s'" % vm_name)

  logg.info("Deleted VM")
  SaltDestroyedEvent.fire(vm_name)
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
    "<memory_mb>": "Amount (in MB) of RAM with which to configure the VM",
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
