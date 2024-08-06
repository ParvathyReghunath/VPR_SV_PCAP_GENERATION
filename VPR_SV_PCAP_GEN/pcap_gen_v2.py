import sys
import struct
import argparse
import time
import math


def get_second_microsecond(ts):
    second = int(ts)
    microsecond = int(round((ts - second) * 1000000))
    return (second, microsecond)

def write_bytes_le(sv, offset, data, len=-2):
    for i in data:
        if len == -1:
            break
        sv[offset] = i
        offset += 1
        if len > 0:
            len -= 1
def write_bytes_be(sv, offset, data):
    offset += len(data) - 1
    for i in data:
        sv[offset] = i
        offset -= 1

HEADER = (
    b"\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
)
# This data are generated from an pcap file
# It is possible to change the SV to sent. The only restriction is that the
# SV ID must have 8 bytes lenght and must contains only one ASDU
# To change this:
# 1. Capture an SV using Wireshark or tcpdump and generate a pcap file with
#    times in µs. The file must contained only one SV
# 2. Drop the pcap header (0 to 0x18)
# 3. Set timestamp to 0 (set the next 8 bytes to 0)
# 5. At offset 0x28 Ensure the MAC Address destination is a IEEE 802.1X
#    Multicast sampled values address (01:0C:CD:04:00:00 to 01:0C:CD:04:01:FF)
# 6. Adjust in the SV_ID_OFFSET and CMP_CNT_OFFSET in this file

#till svid untagged
SV_DATA = (                
b"\xB2\xCD\x40\x64\xB3\x36\x0C\x00\x7A\x00\x00\x00\x7A\x00\x00\x00"
b"\x01\x0C\xCD\x04\x00\x01\x00\x1E\xD4\x00\x97\xB5\x88\xBA\x40\x00"
b"\x00\x6C\x00\x00\x00\x00\x60\x62\x80\x01\x01\xA2\x5D\x30\x5B\x80")   

#after svid untagged
SV_DATA_CONSTANT1=(
b"\x82\x02\x00\x08\x83"
b"\x04\x00\x00\x00\x01\x85\x01\x00\x87\x40\x00\x00\x0E\x6E\x00\x00"
b"\x08\x00\x00\x00\x51\x2C\x00\x00\x08\x00\x00\x00\x51\x2C\x00\x00"
b"\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x20\x78\x00\x00"
b"\x08\x00\x00\x00\x20\x78\x00\x00\x08\x00\x00\x00\x20\x78\x00\x00"
b"\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00")
#till svid tagged
SV_DATA_TAGGED=(
b"\xB2\xCD\x40\x64\xB3\x36\x0C\x00\x7E\x00\x00\x00\x7E\x00\x00\x00"
b"\x01\x0c\xcd\x04\x00\x04\x00\x1e\xd4\x00\x9c\x51\x81\x00\xe0\x6e"
b"\x88\xba\x40\x00\x00\x6C\x80\x00\x00\x00\x60\x62\x80\x01\x01\xa2"
b"\x5d\x30\x5b\x80")
#afters vid untagged
SV_DATA_CONSTANT2=(

b"\x82\x02\x00\x0b\x83\x04\x00\x00\x00\xc8\x85\x01\x00\x87\x40\x00\x00"
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

TS_OFFSET = 0
SOURCE_MAC_OFFSET = 0x16
DESTINATION_MAC_OFFSET = 0x14
SV_ID_OFFSET = 0x31
VA_OFFSET = 0x2f
VB_OFFSET = 0x37
VC_OFFSET = 0x3f
VN_OFFSET = 0x47
IA_OFFSET = 0x0f
IB_OFFSET = 0x17
IC_OFFSET = 0x1f
IN_OFFSET = 0x27
SIMULATED_OFFSET=0x22
VLAN_OFFSET=0x1e
CMP_CNT_OFFSET = 0x02
#offsets for untagged till svid
length_offset1=0x27
length_offset2=0x2c
length_offset3=0x2e
length_offset4=0x20
length_offset5=0x08
length_offset6=0x0c
#offsets for tagged till svid
taglength_offset1=0x2b     #after 60
taglength_offset2=0x30     #after a2
taglength_offset3=0x32     #after 30
taglength_offset4=0x24     #at 006c
taglength_offset5=0x08     #at 7e
taglength_offset6=0x0c     #at 7e

pcap_data = bytearray()
# Add header
pcap_data += HEADER
#sv_data = bytearray(SV_DATA)
ts = time.time()
duration = 0.001
(second, microsecond) = get_second_microsecond(ts)



def states(D):
    #print(D)
    newb=bytearray()
    blen=bytearray()
    bsvid=bytearray()
    smp_count = -1
    output_pcap = bytearray()
    output_pcap+=HEADER
    elapsed_duration = 0
    SAMPLES_PER_CYCLE = 256
    SAMPLING_INTERVAL = 1/(int(D["frequency"]) * SAMPLES_PER_CYCLE)
    countpersec=int((D["frequency"])) * SAMPLES_PER_CYCLE
    elapsed_duration += SAMPLING_INTERVAL
    t=0
    lists=D["states"]
    lists.extend([lists[-1]]*int(D["repetition"]))

    while (t<int(D["duration"][0])):
        
        smp_count=(smp_count+1)%countpersec
        
        #TAKING EACH STREAM 
        for i in range(0,len(lists)):
            #SVID
            if(D["states"][i]["tagged"]==False):
              SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT1)
            else:
              SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT2)
        #SVDATA
            if(D["states"][i]["tagged"]=="1"):
                
                sv_data = bytearray(SV_DATA_TAGGED)
                #print("printing sv data tagged......", sv_data)
            else:
                sv_data = bytearray(SV_DATA)
                #print("printing sv data", sv_data)
        #TIMESTAMP
            (second, microsecond) = get_second_microsecond(ts + t)
            write_bytes_le(
                    sv_data, TS_OFFSET, struct.pack("II", second , microsecond)
            )      
            #print("after time",sv_data)
        #SOURCE MAC
            SM = b'\x00\x25\x97\x01\x02\x03'
            write_bytes_le(
            sv_data, SOURCE_MAC_OFFSET, SM)
        #DESTINATION MAC   
            dest_mac_count = struct.pack("H", i+1)
            write_bytes_be(sv_data, DESTINATION_MAC_OFFSET, dest_mac_count)

            
        #VLANID
            if(D["states"][i]["tagged"]=="1"):
                vlanid=int(D["states"][i]["VLANID"]) 
                binary=b"\xe0\x00"
                vlan = struct.pack(">h", vlanid)
                vlan_bytes = bytes([binary[0] | vlan[0]] +[vlan[1]])
                write_bytes_le(sv_data, VLAN_OFFSET, vlan_bytes)
               
        #ASSIGNING EACH STATES    
            k=lists[i]["state1"]
            m=lists[i]["state2"]
            c=lists[i]["state3"]
            text=D["states"][i]["svid"]
            num=0
        
        #SIMULATED
            if(D["states"][i]["tagged"]=="1"):
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",0),2)
                    
            else:
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET, struct.pack("H",0),2)
                   

        #SVID
            
            if(D["states"][i]["tagged"]=="1"):
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                    
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                   
                    
            else:
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                    
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                
                    

            sv_data+=newb 

            if (D["states"][i]["tagged"]=="0"):
           
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(111+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,length_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,length_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,length_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,length_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,length_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,length_offset6, struct.pack("B",total_length5))
            else:
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(115+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,taglength_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,taglength_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,taglength_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,taglength_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,taglength_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,taglength_offset6, struct.pack("B",total_length5))
   

        #SAMPLE COUNT    
            if(D["states"][i]["tagged"]=="1"):
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
            else:    
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
                    
                
            for n in range(0,13,4):
                V=float(k[n])*1.414*math.sin(2*3.14*60*t+math.radians(float(k[n+2])))
                I=float(k[n+1])*1.414*math.sin(2*3.14*60*t+math.radians(float(k[n+3])))
                b=int(V*100)
                f=int(I*1000)
                if(D["states"][i]["tagged"]=="0"):
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET , struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET , struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET , struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET , struct.pack("<l",f))  
                else: 
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET, struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET, struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET, struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET, struct.pack("<l",f))
                    
            sv_data+=SV_DATA_CONSTANT
            output_pcap+=sv_data
        t=t+SAMPLING_INTERVAL
    
    while (t>int(D["duration"][0]) and t<int(D["duration"][1])):
        
        smp_count=(smp_count+1)%countpersec
        #TAKING EACH STREAM 
        for i in range(0,len(lists)):
            if(D["states"][i]["tagged"]=="0"):
              SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT1)
            else:
               SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT2)
        #SVDATA
            if(D["states"][i]["tagged"]=="1"):
                
                sv_data = bytearray(SV_DATA_TAGGED)
                #print("printing sv data tagged......", sv_data)
            else:
                sv_data = bytearray(SV_DATA)
                #print("printing sv data", sv_data)
        #TIMESTAMP
            (second, microsecond) = get_second_microsecond(ts + t)
            write_bytes_le(
                    sv_data, TS_OFFSET, struct.pack("II", second , microsecond)
            )      
            #print("after time",sv_data)
        #SOURCE MAC
            SM = b'\x00\x25\x97\x01\x02\x03'
            write_bytes_le(
            sv_data, SOURCE_MAC_OFFSET, SM)
        #DESTINATION MAC   
            dest_mac_count = struct.pack("H", i+1)
            write_bytes_be(sv_data, DESTINATION_MAC_OFFSET, dest_mac_count)

        #VLANID
            if(D["states"][i]["tagged"]=="1"):
                vlanid=int(D["states"][i]["VLANID"]) 
                binary=b"\xe0\x00"
                vlan = struct.pack(">h", vlanid)
                vlan_bytes = bytes([binary[0] | vlan[0]] +[vlan[1]])
                write_bytes_le(sv_data, VLAN_OFFSET, vlan_bytes)
               
        #ASSIGNING EACH STATES    
            k=lists[i]["state1"]
            m=lists[i]["state2"]
            c=lists[i]["state3"]
            text=D["states"][i]["svid"]
            num=0
        
        #SIMULATED
            if(D["states"][i]["tagged"]=="1"):
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",0),2)
                    
            else:
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET, struct.pack("H",0),2)
                   
        #SVID
            
            if(D["states"][i]["tagged"]=="1"):
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
            else:
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                    
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                
            sv_data+=newb 

            if (D["states"][i]["tagged"]=="0"):
           
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(111+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,length_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,length_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,length_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,length_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,length_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,length_offset6, struct.pack("B",total_length5))
            else:
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(115+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,taglength_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,taglength_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,taglength_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,taglength_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,taglength_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,taglength_offset6, struct.pack("B",total_length5))
   

        #SAMPLE COUNT    
            if(D["states"][i]["tagged"]=="1"):
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
            else:    
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
                    
            for n in range(0,13,4):
                V=float(m[n])*1.414*math.sin(2*3.14*60*t+math.radians(float(m[n+2])))
                I=float(m[n+1])*1.414*math.sin(2*3.14*60*t+math.radians(float(m[n+3])))
                b=int(V*100)
                f=int(I*1000)
                if(D["states"][i]["tagged"]=="0"):
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET , struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET , struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET , struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET , struct.pack("<l",f))  
                else: 
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET, struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET, struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET, struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET, struct.pack("<l",f))
                    
            sv_data+=SV_DATA_CONSTANT
            output_pcap+=sv_data
            #print("final............",output_pcap)
        t=t+SAMPLING_INTERVAL
            
            
    while (t<int(D["duration"][2])):
        
        
        # smp_count=(smp_count+1)%4800
        smp_count=(smp_count+1)%countpersec
        #TAKING EACH STREAM 
        for i in range(0,len(lists)):
            if(D["states"][i]["tagged"]=="0"):
              SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT1)
            else:
              SV_DATA_CONSTANT=bytearray(SV_DATA_CONSTANT2)
        #SVDATA
            if(D["states"][i]["tagged"]=="1"):
                
                sv_data = bytearray(SV_DATA_TAGGED)
                #print("printing sv data tagged......", sv_data)
            else:
                sv_data = bytearray(SV_DATA)
                #print("printing sv data", sv_data)
        #TIMESTAMP
            (second, microsecond) = get_second_microsecond(ts + t)
            write_bytes_le(
                    sv_data, TS_OFFSET, struct.pack("II", second , microsecond)
            )      
            #print("after time",sv_data)
        #SOURCE MAC
            SM = b'\x00\x25\x97\x01\x02\x03'
            write_bytes_le(
            sv_data, SOURCE_MAC_OFFSET, SM)
        #DESTINATION MAC   
            dest_mac_count = struct.pack("H", i+1)
            write_bytes_be(sv_data, DESTINATION_MAC_OFFSET, dest_mac_count)

            
        #VLANID
            if(D["states"][i]["tagged"]=="1"):
                vlanid=int(D["states"][i]["VLANID"]) 
                binary=b"\xe0\x00"
                vlan = struct.pack(">h", vlanid)
                vlan_bytes = bytes([binary[0] | vlan[0]] +[vlan[1]])
                write_bytes_le(sv_data, VLAN_OFFSET, vlan_bytes)
               
        #ASSIGNING EACH STATES    
            k=lists[i]["state1"]
            m=lists[i]["state2"]
            c=lists[i]["state3"]
            text=D["states"][i]["svid"]
            num=0
        
        #SIMULATED
            if(D["states"][i]["tagged"]=="1"):
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET+4 , struct.pack("H",0),2)
                    
            else:
                if ((D["states"][i]["simulated"])=="1"):
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET , struct.pack("H",128),2)
                else:
                    write_bytes_le(
                        sv_data,SIMULATED_OFFSET, struct.pack("H",0),2)
                   

        #SVID
            
            if(D["states"][i]["tagged"]=="1"):
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
            else:
                if (i<=2):
                    newsvid=text
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                else:
                    count_str = str(i+1)
                    count_str_len = len(count_str)
                    newsvid =( text[0:-count_str_len] + count_str)
                    blen=struct.pack("B",len(newsvid))
                    bsvid=newsvid.encode("ascii")
                    newb=blen+bsvid
                
            sv_data+=newb 

            if (D["states"][i]["tagged"]=="0"):
           
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(111+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,length_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,length_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,length_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,length_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,length_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,length_offset6, struct.pack("B",total_length5))
            else:
                total_length1=(87+1+len(newsvid))                  #length after 60
                
                total_length2=(82+1+len(newsvid))                  #length after a2
                
                total_length3=(80+1+len(newsvid))                  #length after 30
                total_length4=(97+1+len(newsvid))                  #length after 60
                
                total_length5=(115+1+len(newsvid))              #total length at 7A
                write_bytes_le(
                            sv_data,taglength_offset1, struct.pack("B",total_length1))
                write_bytes_le(
                            sv_data,taglength_offset2, struct.pack("B",total_length2))
                write_bytes_le(
                            sv_data,taglength_offset3, struct.pack("B",total_length3))
                write_bytes_le(
                            sv_data,taglength_offset4, struct.pack(">H",total_length4),2)
                write_bytes_le(
                            sv_data,taglength_offset5, struct.pack("B",total_length5))
                write_bytes_le(
                            sv_data,taglength_offset6, struct.pack("B",total_length5))
   

        #SAMPLE COUNT    
            if(D["states"][i]["tagged"]=="1"):
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
            else:    
                write_bytes_be(SV_DATA_CONSTANT, CMP_CNT_OFFSET, struct.pack("H", smp_count))
                    
                
            for n in range(0,13,4):
                V=float(c[n])*1.414*math.sin(2*3.14*60*t+math.radians(float(c[n+2])))
                I=float(c[n+1])*1.414*math.sin(2*3.14*60*t+math.radians(float(c[n+3])))
                b=int(V*100)
                f=int(I*1000)
                if(D["states"][i]["tagged"]=="0"):
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET , struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET , struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET , struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET , struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET , struct.pack("<l",f))  
                else: 
                    if (n==0):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VA_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IA_OFFSET, struct.pack("<l",f))
                    elif (n==4):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VB_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IB_OFFSET, struct.pack("<l",f))
                    elif (n==8):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VC_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IC_OFFSET, struct.pack("<l",f))
                    elif (n==12):
                        write_bytes_be(
                        SV_DATA_CONSTANT,VN_OFFSET, struct.pack("<l",b))
                        write_bytes_be(
                        SV_DATA_CONSTANT,IN_OFFSET, struct.pack("<l",f))
                    
            sv_data+=SV_DATA_CONSTANT
                        
                        
            
            output_pcap+=sv_data
            #print("final............",output_pcap)
            
            
        t=t+SAMPLING_INTERVAL
            
    #print(sv_data)
    
    with open("output.pcap", "wb") as f:
      f.write(output_pcap)  
    return 1

'''
D={    "states":
    [
        {"tagged":True,"VLANID":127,"simulated":True,"svid":"KALKIMU000001","state1":[5,2,120,90,5,2,240,180,5,2,480,360,5,2,0,0],"state2":[10,3,120,90,10,3,240,180,10,3,480,360,10,3,0,0],"state3":[3,2,120,90,3,2,120,90,3,2,120,90,3,2,120,90]},
        
        {"tagged":False,"VLANID":127,"simulated":False,"svid":"KALKIMU00002","state1":[10,5,120,90,10,5,240,180,10,5,480,360,10,5,0,0],"state2":[20,6,120,90,20,6,240,180,20,6,480,360,20,6,0,0],"state3":[25,8,120,90,25,8,120,90,25,8,120,90,25,8,120,90]},
        
        {"tagged":False,"VLANID":127,"simulated":False,"svid":"KALKIMU0000003","state1":[10,5,120,90,10,5,240,180,10,5,480,360,10,5,0,0],"state2":[20,6,120,90,20,6,240,180,20,6,480,360,20,6,0,0],"state3":[25,8,120,90,25,8,120,90,25,8,120,90,25,8,120,90]}
        
    ],
    "duration": [0.001,0.002,0.003],
    "repetition":0,
   
    "frequency":50,
    
}



states(D)
'''
