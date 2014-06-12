#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import string
import binascii

f = open(sys.argv[1], "rb");
f2 = open(sys.argv[2], "w");
name = str(sys.argv[3])

w = f.read()

f2.write("#define " + name.upper() + "_SIZE " + str(len(w)) + "\n\n")
f2.write("unsigned char %s[%s_SIZE] = {\n" % (name, name.upper()))

for i in range(0, len(w)):
    if(i==(len(w)-1)):
        f2.write("0x" + binascii.hexlify(w[i]))
        continue
    
    f2.write("0x" + binascii.hexlify(w[i]) +  ",")
    if(i%5 == 0):
        f2.write("\n")


f2.write("\n};\n")
    
