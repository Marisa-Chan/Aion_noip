#!/usr/bin/python3

f = open("system.cfg", "rb")
fl = f.readlines()

for l in fl:
	l = l.strip()
	l = bytearray(l)
	if (l[0:2] != b'--'):
		i = 0
		while i < len(l):
			l[i] = (~l[i]) & 0xFF
			i += 1
	l = l.decode()		
	print(l)
