Cerberus mDNS Framework
=======================
Multicast DNS Packet Creation for Python

CERBmDNS was developed during the creation of a PoC vulnerability that used multicast DNS as a vector.
Due to the need of a multicast DNS packet creator, this framework was developed. 

.. code:: asm

                               /\_/\____,
                  ,___/\_/\   /  ^     /
                  \     ^  \ )     DNS
                    DNS     /    /\_/\___,
                       \o-o/-o-o/   ^    /
                        ) /     \    DNS
                       _|    / \ \_/
                    ,-/   _  \_/   \
                   / (   /____,__|  )   
                  (  |_ (    )  \) _|
                 _/ _)   \   \__/   (_  
                (,-(,(,(,/      \,),),) 




How to use CERBmDNS
-------------------

There are two primary classes in this framework: CERBmDNS and Cerberus.
CERBmDNS is more advanced but focuses on creating each segment of a mDNS packet.
Cerberus contains functions that allow users to interact and view different information from mDNS traffic on their network.

..  code:: python

  import cmdns
  
  mdns = cmdns.CERBmDNS()
  
  device = "iCerb"
  device_service = "_device-info"
  
  packet = mdns.mDNS_plain_header(answers=1, additional_rr=1) # Define Header
  packet += mdns.mDNS_plain_name(device, device_service, "_tcp", foot="00") # Define Device
  
  packet += mdns.mDNS_plain_answer(16, 4500, 1, "Hello") # Answer Data
  packet += mdns.mDNS_plain_name(device, "_rdlink", domain=None) # Answer Device
  packet += mdns.get_pointer(mdns.mDNS_plain_name(device, service, "_tcp"), packet, "_tcp") # Reference To Defined Device (Needed)
  
  packet += mdns.mDNS_plain_option("Hello World!") # Additional RRs Data
  
How to use Cerberus
-------------------

Cerberus does not require CERBmDNS to function and instead is used to grab mDNS packets or packet information.

..   code:: python

  import cmdns
  
  cerb = cmdns.Cerberus()
  
  mdns_packet = cerb.sniff_multicast_traffic(filters=b"", size_limit=900)
  print(f"Recieved packet size {len(mdns_packet)}")
  
  iPhone = cerb.sniff_device_names(search=b"iPhone", ttl=5)
  print(iPhone)


ASCII Art by b'ger
