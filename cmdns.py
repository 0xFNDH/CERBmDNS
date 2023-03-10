#!env/bin/python3
# Developed: Nov 12th, 2022

import socket
import binascii
import sys
import time
import hashlib
import struct
from random import randint, choice, _urandom
from math import ceil

class CERBmDNS(object):
  """Creates multicast DNS Packets
  """

  def X(self, bit:int, size=2):
    """Takes integer as input and returns byte string. The size refers to it as a base, where base 2 is \\x00\x01 and base 1 is \\x01.
    """
    size = size*2
    bit = hex(bit).split("x")[-1]
    if len(bit) < size:
      bit = "0"*(size-len(bit)) + bit
    return bit

  def H(self, ascii:str):
    """Converts string to hex and bytes to hex.
    """
    if type(ascii) == bytes:
      return binascii.hexlify(ascii).decode()
    return binascii.hexlify(ascii.encode()).decode()

  def get_pointer(self, mdns_name, raw_data, subclass=None):
    """Multicast DNS Packets compress information by creating pointers with \\xc0 that point to different levels of the service domain name.
    Returns the pointer for the service domain name contained in the packet.
    """

    if type(subclass) == str:
      subclass = subclass.encode()

    if mdns_name in raw_data:
      pointer = raw_data.index(mdns_name)
      if subclass == None:
        return b"\xc0"+bytes([pointer])
      elif subclass in mdns_name:
        pointer += mdns_name.index(subclass)-1
        return b"\xc0"+bytes([pointer])
      else:
        raise Exception("Subsidiary service not in mDNS service")
        return None
    else:
      raise Exception("mDNS service not in provided packet")
      return None

  def mDNS_sharp(self, info:str):
    """Sharp is used to convert strings into mDNS strings which require a starting byte that is equal to the length of the string.
    """
    sharp = self.X(len(info),1)
    sharp += self.H(info)
    return binascii.unhexlify(sharp)

  def mDNS_plain_header(self, questions=0, answers=0, authority_rr=0, additional_rr=0, transaction=0x0000, flags=0x8400):
    """Returns a mDNS header with various flags as options.
    """
    header = ""
    for section in [transaction, flags, questions, answers, authority_rr, additional_rr]:
      header += self.X(section)
    return binascii.unhexlify(header.encode())

  def mDNS_plain_name(self, device=None, service=None, protocol=None, domain="local", foot=None):
    """Returns mDNS FQDN based on function options.
    """
    if type(device) in [tuple, list]:
      device, service, protocol = device
    fqdn = ""
    for section in [device, service, protocol, domain]:
      if section != None:
        fqdn += self.X(len(section.encode()),1)
        fqdn += self.H(section)
    if foot != None:
      if type(foot) == int:
        fqdn += self.X(foot,1)
      else:
        fqdn += foot
    return binascii.unhexlify(fqdn.encode())

  def mDNS_plain_answer(self, atype:int, ttl=4500, aclass=0x0001, *data):
    """Returns answer segement for packet based on construction inputs. Answers are divided into three types which are:
            12: Domain Name Pointer *data=(device,)
            16: Text/String *data=(txt,)
            33: Server Selection *data=(priority, weight, port, target, pointer=None,)
    """

    answer = ""
    if atype == 0x0c:
      answer += self.X(0x0c)
      answer += self.X(aclass)
      answer += self.X(ttl,4)
      device = data[0]

      if type(device) == bytes:
        answer += self.X(len(device)+1)
        answer += self.X(len(device)-2,1)
        answer += binascii.hexlify(device).decode()
      else:
        answer += self.X(len(device)+3)
        answer += self.X(len(device),1)
        answer += self.H(device)
        answer += self.X(0xc00c)
      return binascii.unhexlify(answer.encode())

    elif atype == 0x10:
      answer += self.X(0x10)
      answer += self.X(aclass)
      answer += self.X(ttl,4)
      txt = data[0]

      if type(txt) == str:
        answer += self.X(len(txt)+1)
        answer += self.X(len(txt),1)
        answer += self.H(txt)

      elif type(txt) == dict:
        data_length = 0
        answer_resp = ""
        for key in txt:
          resp_field = key+"="+txt[key]
          resp_length = len(resp_field)
          data_length += resp_length
          answer_resp += self.X(resp_length,1)
          answer_resp += self.H(resp_field)
        data_length += len(txt.keys())
        answer += self.X(data_length,2)
        answer += answer_resp
      else:
        raise Exception(f"Value Error:\n{txt} must be <type='str'> or <type='dict'>")
        return None
      return binascii.unhexlify(answer.encode())

    elif atype == 0x21:
      priority, weight, port, target, pointer = data
      answer += self.X(atype)
      answer += self.X(aclass)
      answer += self.X(ttl,4)
      srv_length = len(target)+7
      if pointer:
        srv_length += 2
      answer += self.X(srv_length)
      answer += self.X(priority)
      answer += self.X(weight)
      answer += self.X(port)
      answer += self.X(len(target),1)
      answer += self.H(target)
      if pointer:
        answer += self.H(pointer)
      return binascii.unhexlify(answer.encode())

    elif atype == 0x00:
      answer += self.X(0x0c)
      answer += self.X(aclass)
      answer += self.X(ttl,4)
      return binascii.unhexlify(answer)

    else:
      raise Exception(f"Supported Answer Types: <0x0c=PoinTer> <0x10=TXT> <0x21=SRV>")
      return None

  def mDNS_plain_option(self, option, name=0, otype=0x29, ps=0x05a0, rcode=0, ednsv=0, zrule=0x1194, optcode=4):
    option_data = self.X(name,1)
    option_data += self.X(otype)
    option_data += self.X(ps)
    option_data += self.X(rcode,1)
    option_data += self.X(ednsv,1)
    option_data += self.X(zrule)
    option_data += self.X(len(option)+4)
    option_data += self.X(optcode)
    option_data += self.X(len(option))
    option_data += self.H(option)
    return binascii.unhexlify(option_data.encode())

class Cerberus(object):

  def __init__(self):
    """Cerberus contains several commands for experimenting with mDNS traffic.
    """
    self.multi = None
    self.device_cache = []

  def LAN(self):
    """Returns LAN IPv4 address privately.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
      s.connect(("255.255.255.255", 1))
      lan = s.getsockname()[0]
    except Exception:
      IP = "127.0.0.1"
    finally:
      s.close()
    return lan

  def ascii(self, packet:bytes):
    """Similiar functionality to the linux 'string' function in that it extracts ASCII characters from binary/bytes data.
    """
    ascii = []
    if type(packet) == bytes:
      count = 0
      recent = ""
      for bit in packet:
        if 32 <= bit <= 126:
          recent += bytes([bit]).decode()
          count += 1
        elif count >= 6:
          ascii.append(recent)
          recent = ""
          count = 0
      return " ".join(ascii)

  def splitbytes(self, device:bytes):
    """Used to divide up mDNS packets based on the hostname included the packet.
    """
    device_info = []
    name = b""
    for char in device:
      if 126 >= char >= 30:
        name += bytes([char])
      elif len(name) >= 2:
        device_info.append(name.decode())
        name = b""
    return tuple(device_info)

  def _bind(self, timeout=None):
    """Multicast socket binding is set up as an independant function to avoid automatically binding when the listening functions are not being used.
    """
    MCAST_GRP = "224.0.0.251"
    MCAST_PORT = 5353
    address = self.LAN()
    self.multi = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    self.multi.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.multi.bind((MCAST_GRP, MCAST_PORT))
    self.multi.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY))
    self.multi.settimeout(timeout)

  def _close(self, unregister=False):
    """Properly terminates the multicast session on device's NIC and unregisters the service.
    """
    if self.multi != None:
      if unregister == True:
        self.multi.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP, struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY))
      self.multi.close()
      self.multi = None

  def sniff_device_names(self, search=b"", ttl=15):
    """Listens to mDNS traffic and compiles a list of active device names which will be used to create embedded packets.
    """

    if self.multi == None:
      self._bind(ttl*1.5)
      time.sleep(1)

    expired = time.time()+ttl

    while time.time() < expired:
      data, addr = self.multi.recvfrom(2056)
      if b"local" in data and len(data) <= 350:
        if search in data.split(b"local")[0]:
          name = data.split(b"local")[0][12:]
          try:
            if len(self.splitbytes(name)) == 3:
              expired += ttl
              return (self.splitbytes(name), addr)
          except Exception as e:
            print(e)
            pass

    self._close(True)
    raise TimeoutError(f"Search time exceeded the current TTL value of {ttl}")
    return None

  def sniff_multicast_traffic(self, filters=b"", size_limit=300):
    """Listens to mDNS traffic and returns a device name that matches the filter.
    """

    if self.multi == None:
      self._bind()

    capture = []

    while len(capture) == 0:
      data, addr = self.multi.recvfrom(1024)
      if filters in data and len(data) <= size_limit:
        capture = [data, addr]
        break

    self._close(True)
    return capture

if __name__ == "__main__":
  CERBmDNS = CERBmDNS()
  Cerberus = Cerberus()
