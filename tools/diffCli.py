#!/usr/bin/python3

def genList(a,b,c):
	tmp = list()
	for i in range(0, 600): #max packet id
		tmp.append( (((i + a) ^ b) + 0xC) ^ c  )
	return tmp

v = 0xD0

a = genList(v, 0xEC, 0xEC)
b = genList(v, 0xED, 0xED)
c = genList(v, 0xEE, 0xEE)
d = genList(v, 0xEF, 0xEF)

for i in range(len(a)):
	if len(set( (a[i],b[i],c[i],d[i]) ) ) != 1:
		print("{:d} a {:d} b {:d} c {:d} d {:d}".format(i, a[i],b[i],c[i],d[i]))

