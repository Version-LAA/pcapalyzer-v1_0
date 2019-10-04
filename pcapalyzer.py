import pyshark
from collections import Counter
import datetime
import ipaddress

# variables
count = 1
ip_list = []
protocol_list = []
int_ports = []
http_queryList = []
dns_info = []
error_list = []
ip_full_list = []
common_ports = {"22": "ftp20",
                "21": "ftp21",
                "22": "ssh",
                "23": "Telnet",
                "25": "smtp",
                "43": "WHOIS",
                "53": "DNS",
                "80": "http",
                "88": "Kerberos",
                "443": "https",
                "69": "tftp",
                "109": "pop2",
                "110": "pop3",
                "115": "SFTP",
                "118": "SQL Services",
                "137": "NetBIOS- NetBIOS Name Service",
                "138": "NetBIOS- NetBIOS Datagram Service",
                "139": "NetBIOS- NetBIOS Session Service",
                "143": "IMAP4 (Internet Message Access Protocol 4) - used for retrieving E-mails",
                "161": "SNMP (Simple Network Management Protocol)",
                "179": "BGP (Border Gateway Protocol)",
                "194": "IRC",
                "389": "LDAP",
                "445": "Microsoft-DS",
                "6667": "IRC",
                }

# This section takes a user supplies pcap file and checks for errors of the input file.
print("\n***************Welcome to Pcapalyzer V.1***********************")
pcap = input("\n\nPlease enter the name of the pcap file you would like to analyze:")

split = pcap.split(".")  # Splits filename to help identify if file has correct extension.

# Check input for valid pcap file- exits program if pcap.
while True:
    try:
        if "pcap" in split[-1]:
            capture = pyshark.FileCapture(pcap)
            break
        else:
            print("\n\nPlease run again " + pcap + " is not a valid file name")
            exit()
    except FileNotFoundError:
        print("\n\nFILE NOT FOUND - please make sure pcap file is in pcapalyzer root folder")
        exit()

''' BEGINNING OF GENERAL INFORMATION SECTION -
The functions below provide the general information functionality**********
'''

# Provides count of packets within pcap file.
def packet_count():
    p_count = 0
    for p in capture:
        p_count = p_count + 1
    return p_count

# Get basic general information of pcap
def pcap_info():
    start_time = str(capture[0].sniff_time)
    end_time = str(capture[packet_count() - 1].sniff_time)

    print(
        "\n\n ****************************Pcapalyzer General Information:****************************************\n\n")
    print("Pcap Name: ", capture.input_filename)
    print("\n# of packets in PCAP: ", packet_count())
    print("\nTime of first packet: ", str(start_time))
    print("\nTime of last packet:", str(end_time))
    print("\n************Top 3 talkers************* ")
    print("\nIP < -----> Packets Sent")
    print("\n")
    print(pcap_top_talkers())
    print('***************************************')
    print(" Common Protocols Identified")
    print(common_protocols())
    print("\n\n\n********************************DNS INFO******************************************")
    # print("Source IP")
    dns_function()

    print("\n\n\n********************************HTTP INFO******************************************")
    http_info()

    print(
        "\n\n ****************************Pcapalyze General Information :****************************************\n\n")


  #print("\nThe following IP addresses were identified: \n")
    #ip_identifier()

    #print("\nList of Ports in Pcap:")
    #port_identifier()

# The pcap_top_talkers function identifies the top 3 talkers within a pcap
def pcap_top_talkers():
    for packet in capture:

        if "udp" in dir(packet) or "tcp" in dir(packet):
            ip_full_list.append(packet.ip.src)

    ip_count = Counter(ip_full_list)
    ip_common = ip_count.most_common(3)

    for x in ip_common:
        output = print(x[0], "\t< --- >\t", x[1])

# This function will give user a description of some common protocols identified in the traffic.

def ports_list():
    for p in capture:
        if "dns" in p:
            protocol_list.append(p.udp.dstport)
        elif "tcp" in p:
            protocol_list.append(p.tcp.dstport)

    for port in protocol_list:
        int_ports.append(int(port))

def common_protocols():
    ports_list()
    unique_ports = set(protocol_list)

    for port in unique_ports:
        if port in common_ports:
            # print(True)
            print("This PCAP may contain " + common_ports.get(port) + " traffic!!")


'''***************END OF GENERAL INFORMATION SECTION***********************'''

'''***************BEGINNING OF ENDPOINT INFORMATION SECTION**********'''


# Identifies all unique source and destination IP's within pcap file
def ip_parser():
    count = 1
    for p in capture:
        if "ip" in p:
            ip_list.append(p.ip.src)
            count = count + 1


'''***************END OF ENDPOINT INFORMATION SECTION**********'''

'''***************BEGINNING OF DNS INFORMATION SECTION**********'''


# Checks PCAP for DNS traffic, and stores request
def dns_function():
    dns_count = 0
    for packet in capture:
        if ("DNS" in packet) and ('0x00000100' in packet.dns.flags):
            dns_info.append({"ip": packet.ip.src, "Query": packet.dns.qry_name})
            dns_count = dns_count + 1

    for x in dns_info:
        print(x['ip'], " DNS Request:-------->", x['Query'])
    # print(dns_count)
    # elif ("DNS" in packet) and ('0x00008180' in packet.dns.flags):


'''***************END OF DNS INFORMATION SECTION**********'''

'''***************BEGINNING OF HTTP INFORMATION SECTION**********'''


# Checks PCAP for HTTP traffic, and stores request
def http_info():
    http_count = 0
    for x in capture:

        if ('http' in x) and ('get' in dir(x.http)) and ('80' in x.tcp.dstport):
            http_count = http_count + 1

            http_queryList.append({"ip": x.ip.src, "Query": x.http.request_full_uri})

    for x in http_queryList:
        print(x['ip'], " HTTP Request:-------->", x['Query'])


'''***************END OF HTTP INFORMATION SECTION**********'''


def pcapaplyzer_run():
    pcap_info()
    ip_parser()
    ports_list()

    print("\nThe following IP addresses were identified: \n")
    ip_identifier()

    print("\nList of Ports in Pcap:")
    port_identifier()


# Function Identifies all unique IP's within pcap.
def ip_identifier():
    unique_ip = set(ip_list)
    new_ip = []
    for p in unique_ip:
        new_ip.append(ipaddress.ip_address(p))
    new_ip.sort()
    for ip in new_ip:
        print(ip)


# Function identifies all unique ports within pcap.
def port_identifier():
    u_ports = set(int_ports)
    sorted_ports = sorted(u_ports)
    for p in sorted_ports:
        print(p)


pcapaplyzer_run()
