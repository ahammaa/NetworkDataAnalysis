## Import the PacketCapture Class
from PacketCapture import PacketCapture

## Initialize a PacketCapture object 
packetCapture=PacketCapture(100)

## Sniff packets
#packetCapture.sniffPackets()

## Read packets from pcap file
packetCapture.readPcapFile("packets.pcap")

## Generate DataFrame Object with the captured data
packetCapture.generateDataFrame()

##*********************************************************************##

## The next code is used to extract some useful information from the dataframe object ##
# Top Source Adddress
print("# Source Address Summary: ")
print(packetCapture.dataframe['src'].describe(),'\n\n')

# Top Destination Address
print("# Destination Address Summary: ")
print(packetCapture.dataframe['dst'].describe(),"\n\n")

frequent_address = packetCapture.dataframe['src'].describe()['top']
print("# Top Source IP Address: ")
print(frequent_address,"\n\n")

# The IP addresses that the Top Address is speaking to:
print("# The IP addresses that the Top Address is speaking to: ")
print(packetCapture.dataframe[packetCapture.dataframe['src'] == frequent_address]['dst'].unique(),"\n\n")

# The destination ports that the top address is speaking to:
print("# The destination ports that the top address is speaking to:")
print(packetCapture.dataframe[packetCapture.dataframe['src'] == frequent_address]['dport'].unique(),"\n\n")

# The source ports that the top address is speaking to:
print("# The source ports that the top address is speaking to:")
print(packetCapture.dataframe[packetCapture.dataframe['src'] == frequent_address]['sport'].unique(),"\n\n")

##**************************************##