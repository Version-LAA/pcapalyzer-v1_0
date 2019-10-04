# pcapalyzer

PCAPalyzer is a simple packet capture review script designed to take a user supplied pcap file and provide a basic summary of the file provided using the Pyshark library. Great for a quick glimpse of small - medium size packet capture files. Also great for analyst just starting out that can give them a quick summary of a packet capture file.  


# Installation/Running

- Please be sure to place pcap file within pcapalyzer root folder.

# Syntax

pcapalyzer.py [FileName.pcap]


# Output

version 1.0
- General Information Section
  1. Pcap name
  2. Amount of packets contained within user supplied pcap.
  3. Date/Time of first packet within pcap
  4. Date/Time of last packet within pcap
  
- Top talkers
  Provides a listing of the top talkers within the packet capture, along with the amount of packets sent by the IP address.
  
- Common Protocols Identified
  Provides a listing of some common protocols identified within the pcap based on a destination port lookup.
  
- DNS Traffic Identification
  If applicable and exist within pcap file, this will provide a listing of all dns request along with the requesting IP.
  
- HTTP Traffic Identification
  If applicable and exist within pcap file, this will provide a listing of all HTTP GET request along with the requesting IP.
  
  
# Sample Output Images

![User Input/General Information ](https://github.com/cybersecurebyte/pcapalyzer/blob/master/Screen%20Shot%202019-08-05%20at%208.18.02%20PM.png)

![Top Talkers/ Common Protocols ](https://github.com/cybersecurebyte/pcapalyzer/blob/master/Screen%20Shot%202019-08-05%20at%208.18.15%20PM.png)

![DNS/HTTP Info ](https://github.com/cybersecurebyte/pcapalyzer/blob/master/Screen%20Shot%202019-08-05%20at%208.18.27%20PM.png)


![IP's / Ports](https://github.com/cybersecurebyte/pcapalyzer/blob/master/Screen%20Shot%202019-08-05%20at%208.18.38%20PM.png)





  


