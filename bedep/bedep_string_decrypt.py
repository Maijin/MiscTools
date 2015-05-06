
#!/usr/bin/env python

##############################################################################
## 
## Use me to decrypt the strings in the Bedep binary 
## 
## Only tested with python2.7 use at your own risk.
##
##############################################################################

__author__ = "Sergei Frankoff"

import argparse
import sys


#bitwise rotate right Author: Satoshi Tandac
def _rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | \
           ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))

def _ror(val, bits, bit_size):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | \
           (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))

__ROR4__ = lambda val, bits: _ror(val, bits, 32)
__ROR8__ = lambda val, bits: _ror(val, bits, 64)
__ROL4__ = lambda val, bits: _rol(val, bits, 32)
__ROL8__ = lambda val, bits: _rol(val, bits, 64)


M32 = 0xffffffffL
def m32(n):
    return n & M32
def madd(a, b):
    return m32(a+b)
def msub(a, b):
    return m32(a-b)
def mls(a, b):
    return m32(a<<b)



def decrypt_string(str_in):
    count_1 = 0
    count_2 = 1

    str_out=''

    str_out += chr(ord(str_in[count_1])^0xf0)

    key = 0xa69a4cf0
    for k in range(0,len(str_in)-1):
        
        str_out += chr(0x000000ff &(msub(msub(ord(str_in[count_2]), 0x000000ff & (ord(str_in[count_1])*(key&0x000000ff))), 0x43)))
        count_1 = count_2
        count_2 += 1
        key = madd(key, __ROR4__(key,7))

    return str_out

def main():
    parser = argparse.ArgumentParser(description="This script can be used to decrypt the strings in Bedep.")
    parser.add_argument('cyphertext',help="Specify the string you want decrypted.")
    parser.add_argument('-x','--hex',dest="print_hex",action='store_true',default=False,help="Print output in hex.")
    args = parser.parse_args()
    
    print_hex = args.print_hex
    in_string = args.cyphertext

    try:
        out_string = decrypt_string(in_string)
           
        if print_hex:
            print "\\x"+"\\x".join("{:02x}".format(ord(c)) for c in out_string)
        else:
            print out_string
    except:
        print>>sys.stderr, "Error decrypting the input string." 
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
