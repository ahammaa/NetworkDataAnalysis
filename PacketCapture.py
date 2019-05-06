from scapy.all import * # This library is used for packet manipulation
import pandas as pd # Pandas is a Data Analysis Library. 
# It provides easy-to-use data structures and data analysis tools
# It is used to create and manipulate DataFrames (fast and efficient objects for data manipulation with integrated indexing)
import numpy as np # NumPy is the fundamental package for scientific computing with Python.

class PacketCapture:
    def __init__(self, num_of_packets_to_sniff):
        ## Set the number of packets to sniff
        self.num_of_packets_to_sniff = num_of_packets_to_sniff

        ## Initialize a PacketList object to store the sniffed packets
        self.pcap = plist.PacketList() 

        ## The next code is used to initialize a DataFrame object
        ## Collect field names from IP/TCP/UDP (These will be columns in a DataFrame object)
        ip_fields = [field.name for field in IP().fields_desc]
        layer4_fields = [field.name for field in TCP().fields_desc]
        
        ## Create the final fields object that will be used as dataframe columns
        self.dataframe_fields = ip_fields + ['time'] + layer4_fields + ['payload', 'payload_raw', 'payload_hex']

        ## Create blank DataFrame
        self.dataframe = pd.DataFrame(columns=self.dataframe_fields)


    ## The next method can be used to read a file of already captured packets and store the packets in the packet list
    def readPcapFile(self, file):
        self.pcap = self.pcap + rdpcap(file)


    ## The next code can be used to sniff packets and return and a packet list
    def sniffPackets(self):
        ## sniff(): sniff packets and return and a packet list
        self.pcap = sniff(count=self.num_of_packets_to_sniff)

        ## The next line can be used to specify the network interface for packet sniffing and 'monitor=true' to sniff other 
        ## users' packets (if monitor mode is enabled)
        #self.pcap = sniff(iface="Intel(R) Dual Band Wireless-AC 7265",monitor=True, count=self.num_of_packets_to_sniff)

    
    ## The next method can be used to extract data from the captured packets to fill the DataFrame object
    def generateDataFrame(self):
        ip_fields = [field.name for field in IP().fields_desc]
        layer4_fields = [field.name for field in TCP().fields_desc]
        for packet in self.pcap[IP]:
            ## Field array for the values of each row of DataFrame
            field_values = []
            # Add all IP fields to field_values
            for field in ip_fields:
                if field == 'options':
                    # Retrieving number of options defined in IP Header
                    field_values.append(len(packet[IP].fields[field]))
                else:
                    field_values.append(packet[IP].fields[field])

            field_values.append(packet.time)

            layer_type = type(packet[IP].payload)
            ##print("Layer Type:::")
            ##print(layer_type)
            
            # Add layer 4 fields to field_values
            for field in layer4_fields:
                try:
                    if field == 'options':
                        field_values.append(len(packet[layer_type].fields[field]))
                    else:
                        field_values.append(packet[layer_type].fields[field])
                except:
                    field_values.append(None)

            ##  Append the payload the field_values
            field_values.append(len(packet[layer_type].payload))
            field_values.append(packet[layer_type].payload.original)
            field_values.append(binascii.hexlify(packet[layer_type].payload.original))
            
            ## Add the row to the dataframe self.dataframe
            df_append = pd.DataFrame([field_values], columns=self.dataframe_fields)
            self.dataframe = pd.concat([self.dataframe, df_append], axis=0)

        ## Reset the Index of dataframe self.dataframe
        self.dataframe = self.dataframe.reset_index()

        ## Drop the old index column
        self.dataframe = self.dataframe.drop(columns="index")
        print (self.dataframe)    

packetCapture=PacketCapture(100)
#packetCapture.sniffPackets()
packetCapture.readPcapFile("packets.pcap")
packetCapture.generateDataFrame()