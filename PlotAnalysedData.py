## Import the PacketCapture Class
from PacketCapture import PacketCapture

import binascii # The binascii module contains a number of methods to convert between binary and various ASCII-encoded binary representations.
import seaborn as sns  # Seaborn is a Python data visualization library based on matplotlib. It provides a high-level interface for drawing attractive and informative statistical graphics.
sns.set(color_codes=True)

import matplotlib.pyplot as plt # Matplotlib is a Python 2D plotting library which produces publication quality figures in a variety of hardcopy formats and interactive environments across platforms.


## Initialize a PacketCapture object 
packetCapture=PacketCapture(100)

## Sniff packets
#packetCapture.sniffPackets()

## Read packets from pcap file
packetCapture.readPcapFile("packets.pcap")

## Generate DataFrame Object with the captured data
packetCapture.generateDataFrame()

##*********************************************************************##

## The next code is used to group the data by Source Address and Payload Sum, and to plot the resulted figure
source_addresses = packetCapture.dataframe.groupby("src")['payload'].sum()
source_addresses.plot(kind='barh',title="Addresses Sending Payloads",figsize=(8,5))
plt.show()

## The next code is used to group the data by Destination Address and Payload Sum, and to plot the resulted figure
destination_addresses = packetCapture.dataframe.groupby("dst")['payload'].sum()
destination_addresses.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(8,5))
plt.show()

## The next code is used to group the data by Source Port and Payload Sum, and to plot the resulted figure
source_payloads = packetCapture.dataframe.groupby("sport")['payload'].sum()
source_payloads.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(8,5))
plt.show()

## The next code is used to group the data by Destination Port and Payload Sum, and to plot the resulted figure
destination_payloads = packetCapture.dataframe.groupby("dport")['payload'].sum()
destination_payloads.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))
plt.show()

## The next code is used to extract the history of bytes sent by the most frequent address, and to plot the resulted figure
frequent_address = packetCapture.dataframe['src'].describe()['top']
frequent_address_df = packetCapture.dataframe[packetCapture.dataframe['src'] == frequent_address]
x = frequent_address_df['payload'].tolist()
sns.barplot(x="time", y="payload", data=frequent_address_df[['payload','time']],
            label="Total", color="b").set_title("History of bytes sent by most frequent address")

plt.show()

##**************************************##