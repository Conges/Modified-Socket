# Modified-Socket
We are making source routing using Segment Routing [SR] protocol and [SDN] architecture in order to take the decision of changing the normal path route that the data follows usually and reroute it to another path depending on [TCP] session congestion state.

This module will change the behavior of the normal TCP socket in order to monitor the congestion and send the state of it to the SDN controller.

This module is responsible for monitoring TCP sessions between hosts and writing down the congestion state between these sessions. After that, this module will be responsible for sending this data to the SDN controller.

The operation of monitoring and sending sessions’ data to the SDN will be distributed over the hosts, every host will monitor its own congestion and send the data to the SDN. Thus, these data will be received by the SDN and be analyzed by TCP Tracker module.

## Module Specifications

## Input:
This module will receive its input from every packet send from a host.
* Processing:
Somehow this module responsible for reading these attributes for every TCP session in the host: Sender IP, Sender Port, Destination IP, Destination Port, and Congestion state.

## Output:
Every host will responsible for sending these 5 attributes to the SDN controller.
#Submodules:
This module has two main sub module one responsible for monitoring congestion, and other for ending data to the SDN controller.
