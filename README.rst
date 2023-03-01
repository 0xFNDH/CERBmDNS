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

There are two primary classes this framework which include CERBmDNS and Cerberus.
CERBmDNS is more advanced but focuses on creating each segment of a mDNS packet.
Cerberus contains functions that allow users to interact and view different information from mDNS traffic on their network.

..  code:: python

  print("hello world")

ASCII Art by b'ger
