import math
import struct

# Requires crcmod: http://crcmod.sourceforge.net/intro.html
import crcmod

# Update of the original dnp3 function from scada.py. It provided a base, but was not implemented correctly
# See documentation provided through http://dnp.org. Requires subscription for access to "Document Library."
def dnp3 (data, control_code="\x44", src=0, dst=0):
    '''Build DNP3 packets that are ready for transmission. Input includes data to send, control code (defaults to slave),
       source address (decimal), and destination address (decimal). Returns a list of packets ready for transmission. 
       Each entry in the packet list will represent a packet with the appropriate fragmentation. 
       
       This module only handles the building of packets and Transport Layer fragmentation. All other DNP3 functionality
       must be managed else where.'''

    packets          = []
    sync_bytes       = "\x05\x64" # Sync Bytes never change
    len_cntl_dst_src = 5    # Header == cntl + dst + src == 5 bytes. This is a constant
    #master_cntl_code = "\xc4" # Default control code for basic master packets
    #slave_cntl_code  = "\x44" # Default control code for basic slave packets

    # Calculate number of packets, but if there is no data we still need at least one packet
    num_packets = int(math.ceil(float(len(data)) / 250.0))
    if not num_packets:
        num_packets = 1

    for i in xrange(num_packets):
    
        # Transport Layer Fragmentation
        if num_packets > 1:
            # Packets can only be so big, therefore fragment if necessary
            # As we will be adding a byte, only grab 249 to make 250
            sdata = data[i*249 : (i+1)*249]

            # Sequence number is always less than 64
            frag_number = i % 64

            # insert the fragmentation flags / sequence number.
            # first frag: 0x40, last frag: 0x80
            if i == 0:
                frag_number |= 0x40
            if i == num_packets - 1:
                frag_number |= 0x80

            # Add it to the front of the slice so it is included and counted as part of the data
            # Extra byte makes slice 250 bytes
            sdata = chr(frag_number) + sdata

        else:
            # No need to fragment. Just use all the data.
            sdata = data

        # Build Header
        p  = sync_bytes
        # Length is the header (cntl, dst, src) bytes plus the data length, CRC's from ANY chunk are NOT counted
        p += chr(len(sdata) + len_cntl_dst_src)
        p += control_code
        p += struct.pack('<H',dst)
        p += struct.pack('<H',src)

        # Header Checksum
        chksum = crc(p)
        p += chksum

        # Create packet chunks which are 16 bytes long
        num_chunks = int(math.ceil(float(len(sdata) / 16.0)))

        for x in xrange(num_chunks):
            chunk   = sdata[x*16 : (x+1)*16]
            # Add CRC to the end of each fragment, but DO NOT count
            chksum = crc(chunk)
            p      += chunk + chksum

        # Store till we are done
        packets.append(p)

    # Done, return list of packets
    return packets

# Sometimes we want to see the contents of a packet
def print_packet(data):
    '''A method to print DNP3 Packet data like the DNP3 documentation'''
    cnt0 = 10
    cnt1 = 18
    for e in data[:]:
        print ("%.02x"%ord(e)).upper(),
        if cnt0:
            cnt0 -= 1
            if not cnt0:
                print ""
        else:
            cnt1 -= 1
            if not cnt1:
                print ""
                cnt1 = 18
    print ""
    print ""


# crc16 provided by utils/misc is NOT the correct method for computing the DNP3 CRC.
# crcmod provides 'crc-16-dnp' which is the correct method
def crc(data=None):
    '''Compute C12.18 CRC value which uses the x-25 settings in crcmod.
        Stores the results in Little Endian order. Returns CRC bytes on success or 0 on failure'''
    if data == None:
        return 0
    # This has to be initialized everytime.  For some reason
    # it keeps track of old values and will use that as the
    # starting value.  You could start with crcval.new(arg='\x00')
    # but I don't trust it.
    crcval = crcmod.predefined.Crc('crc-16-dnp')
    crcval.update(data)
    return struct.pack('<H',crcval.crcValue)
