#!/usr/bin/python3

import sys

f = open(sys.argv[1], "rb")
ou = open(sys.argv[2], "wb")
fl = f.readlines()

for l in fl:
	l = l.strip()
	l = bytearray(l)
	if (l[0:2] != b'--'):
		i = 0
		while i < len(l):
			l[i] = (~l[i]) & 0xFF
			i += 1
	ou.write(l)
	ou.write(b"\n")

ou.close()
