import binascii
import collections
class Switch(object):
    DST_STR = 0
    DST_END =6
    SRC_STR=6
    SRC_END= 12

    def __init__(self, max_size):
        self.mac_tlb =collections.OrderedDict()
        self.MAX_SIZE = max_size

    def forward_packet(self, iface, pkt):

        #incase the mac table is full
        if len(self.mac_tlb )>= self.MAX_SIZE :
            import random
            #pick randomly a number of entries to be swept out
            length =random.randrange(1, self.MAX_SIZE/3, 1)
            for i in range(0,length):
                self.mac_tlb.popitem(False)
            print "POP"

        #extract destination and source
        src = pkt[self.SRC_STR:self.SRC_END]
        dst = pkt[self.DST_STR:self.DST_END]
        print " source: %s\n dest: %s\n" %(binascii.hexlify(src),binascii.hexlify(dst))

        #store destination into MAC table
        self.mac_tlb[src] = iface
        assert len(self.mac_tlb)<=self.MAX_SIZE

        #route the packet to destination
        #if destination address is broadcast
        if binascii.hexlify(dst)=="FFFFFFFFFFFF":
            return -1

        #check if MAC address exist in MAC table
        if self.mac_tlb.has_key(dst):
            # if yes, check the destination interface
            out_iface = self.mac_tlb[dst]
            if out_iface == iface:
                #drop the frame
                return 0
            else:
                return out_iface

        #otherwise, broadcast
        return -1
    def MAC_add_lookup(self,iface, ptk):
        pass
    def debug(self):
        print "debug"