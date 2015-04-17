#!/usr/bin/env python

##############################################################################
## 
## Use me to decrypt the binaries that Angler EK downloads (2015)
## 
## Only tested with python2.7 use at your own risk.
##
##############################################################################

__author__ = "Sergei Frankoff"

import struct
import argparse
import os



M32 = 0xffffffffL
def m32(n):
    return n & M32
def madd(a, b):
    return m32(a+b)
def msub(a, b):
    return m32(a-b)
def mls(a, b):
    return m32(a<<b)

def tea_block_decrypt (buff, keys): 
    sum_const = 0xC6EF3720
    delta = 0x61C88647
 
    buff0 = struct.unpack('I',buff[0:4])[0]
    buff1 = struct.unpack('I',buff[4:8])[0]

    for i  in range(0,32):  
        sum_const_ptr = 4* ((sum_const >>11) & 3)           
        buff1 = msub(buff1 , madd((mls(buff0, 4)^(buff0 >> 5)), buff0) ^ madd(sum_const, struct.unpack('I',keys[sum_const_ptr:sum_const_ptr+4])[0]))
        sum_const = madd(sum_const, delta)
        sum_const_ptr  =  4* (sum_const & 3)                 
        buff0 = msub(buff0, madd((mls(buff1,4)^(buff1 >> 5)), buff1) ^ madd(sum_const, struct.unpack('I',keys[sum_const_ptr:sum_const_ptr+4])[0]))

    return struct.pack('I',buff0)+struct.pack('I',buff1)


def tea_decrypt (buff, keys): 
    if (len(buff)%8) != 0:
        raise ValueError("Cyphertext length is not multiple of 8")

    out_buff = ''
    for block in range(0,len(buff),8):
        out_buff += tea_block_decrypt(buff[block:block+8],keys)
    
    return out_buff


def main():
    parser = argparse.ArgumentParser(description="This script can be used to decrypt the payload downloaded by Angler EK 2015.")
    parser.add_argument("infile", help="The file that you wish to decrypt.")
    parser.add_argument('-x','--hex',dest="print_hex",action='store_true',default=False,help="Print output in escaped hex.")
    parser.add_argument('--key',dest="new_key",default=None,help="Specify a new key string. The default key is Du9JOBgkbfzGvmFF")
    args = parser.parse_args()
    infile = args.infile
    print_hex = args.print_hex

    if args.new_key:
        key = args.new_key
    else:
        key = 'Du9JOBgkbfzGvmFF'

    if not os.path.exists(infile):
        print>>sys.stderr, "Error - the payload file %s does not exist.\n" % infile
        parser.print_help()
        sys.exit(1)
       
    with open(infile, mode='rb') as file:
        data = file.read()

    #not sure why but Angler removes the last 4 bytes from the file
    #I tried to do a bit of error handling in case you forgot to remove the final line feed
    tail = len(data)%8
    data = data[:-tail]

    out_data = tea_decrypt(data, key)
    
    if print_hex:
        print "\\x".join("{:02x}".format(ord(c)) for c in out_data)
    else:
        print out_data

if __name__ == '__main__':
    main()

