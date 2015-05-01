#!/usr/bin/env python

##############################################################################
## 
## Use me to decrypt C2 traffic from Bedep 
## 
## Only tested with python2.7 use at your own risk.
##
##############################################################################

__author__ = "Sergei Frankoff"

import argparse
import os
import sys
import base64
from Crypto.Cipher import AES

KEY='q\x18p\xe5\xabn\xa2\x8b\xb0\xd8L\x81D\x82\xddw'

def decrypt(data, key):
    bin_data = base64.b64decode(data)
    iv = bin_data[:16]
    cyphertext = bin_data[16:]
    decobj = AES.new(key,AES.MODE_CBC,iv)
    plaintext = decobj.decrypt(cyphertext)
    return plaintext



def main():
    parser = argparse.ArgumentParser(description="This script can be used to decrypt Bedep C2 traffic. You must specify either the --text or --file option.")
    parser.add_argument('--text', action="store", dest="b64_text",help="Specify base64 encoded text that you want decrypted.")
    parser.add_argument('--file', action="store", dest="b64_file",help="Specify file containing base64 encoded text that you want decrypted.")
    parser.add_argument('-x','--hex',dest="print_hex",action='store_true',default=False,help="Print output in hex.")
    args = parser.parse_args()
    
    print_hex = args.print_hex

    if args.b64_text:
        out = decrypt(args.b64_text, KEY)
    elif args.b64_file:
        infile = args.b64_file
        if not os.path.exists(infile):
            print>>sys.stderr, "Error - the payload file %s does not exist.\n" % infile
            parser.print_help()
            sys.exit(1)
       
        with open(infile, mode='rb') as file:
            data = file.read()

        out = decrypt(data, KEY)
    else:
        parser.print_help()
        sys.exit(1)


    if print_hex:
        print "\\x"+"\\x".join("{:02x}".format(ord(c)) for c in out)
    else:
        print out


if __name__ == '__main__':
    main()
