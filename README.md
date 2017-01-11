# pcap_anon
Packet captire and anonymization tool using C

Due to the ongoing success of video streaming services, the traffic introduced by these video service providers has a remarkable share on the overall traffic. This research project focuses on developing a packet capture and anonymizing tool to analyzing the effect of video streaming on network traffic. A study is conducted on different packet capture tools available in order to determine the most feasible one for this project.  The tool is developed in C program using the Tcpdump library. Due to privacy restriction of ISP, every packet is anonymized with its corresponding private data. Filters are added to capture only the video streams of a particular service over the network. Once the anonymization is complete, all the packets are saved as dump files and are later used for analyzing the impact on network traffic.

How to Use the Tool.

Prerequisites
  1. Linux with GNU C installed.
  2. Install Libpcap libraries.
  3. Install TCPdump and Wireshark.

Terminal Command
  To Compile : sudo gcc tcprewrite.c -l pcap
  To Run : sudo a.out -i eth0 #interface name here

The output is stored as a dumpfile in the same directory which can be opened using wireshark.
