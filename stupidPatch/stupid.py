#!/usr/bin/python

import sys
import os
import hashlib

class PESection:
	VAddr = 0
	VSize = 0
	Addr = 0
	Size = 0

Sections = list()

def read4int(fl):
	return int.from_bytes( fl.read(4) , byteorder='little' )

def read2int(fl):
	return int.from_bytes( fl.read(2) , byteorder='little' )

def readPE(fl):
	Sections.clear()
	
	fl.seek(0)
	if fl.read(2) != b'MZ':
		return False
	
	fl.seek(0x3C) #e_lfanew
	PE_POS = read4int(fl)
	
	fl.seek(PE_POS)
	if read4int(fl) != 0x4550:
		return False
	
	fl.seek(PE_POS + 6) #sec Numb
	secNumb = read2int(fl)
	
	i = 0
	while i < secNumb:
		fl.seek(PE_POS + 0xF8 + i * 0x28) #sections
		name = fl.seek(8, 1)
		pes = PESection()
		pes.VSize = read4int(fl)
		pes.VAddr = read4int(fl)
		pes.Size  = read4int(fl)
		pes.Addr  = read4int(fl)
		
		Sections.append(pes)
		
		i += 1
	
	return True

def getMD5(fl):
	fl.seek(0)
	md5 = hashlib.md5()
	while True:
		block = fl.read(4096)
		if not block: break
		md5.update(block)
	return md5.digest()

def GetSec(vaddr, sz):
	for z in Sections:
		if vaddr >= z.VAddr and (vaddr + sz) <= (z.VAddr + z.Size):
			return z
	return None

def Patch(fl, key, pch):
	sec = GetSec(pch[0], len(pch[1]))
	if (sec == None):
		print("\t\tNo section")
	else:
		mna = pch[0] & 0xFFFFFFFC
		mxa = (pch[0] + len(pch[1]) + 4) & 0xFFFFFFFC
		its = (mxa - mna)
		
		flpos = sec.Addr + ((pch[0] - sec.VAddr) & 0xFFFFFFFC)
		fl.seek( flpos )
		
		chkbt = bytearray(len(pch[1]))
		
		i = 0
		while i < its:
			raw = fl.read(4)
			decr = int.from_bytes(raw, byteorder="little")
			decr = (decr - key) & 0xFFFFFFFF
			tmp = bytearray(decr.to_bytes(4, byteorder="little"))

			j = 0
			while j < 4:
				btid = (mna + i + j) - pch[0]
				if ( btid >= 0 and btid < len(pch[1]) ):
					chkbt[btid] = tmp[j]
				j += 1
			i += 4
		
		if (chkbt != pch[1]):
			print("\t  Can't apply patch")
			print("\t ", pch[1].hex() , "!=" , chkbt.hex())
			return
		
			
		fl.seek( flpos )

		i = 0
		while i < its:
			log = {}
			raw = fl.read(4)
			log[0] = raw
			decr = int.from_bytes(raw, byteorder="little")
			decr = (decr - key) & 0xFFFFFFFF
			tmp = bytearray(decr.to_bytes(4, byteorder="little"))
			log[1] = tmp.copy()

			j = 0
			while j < 4:
				btid = (mna + i + j) - pch[0]
				if ( btid >= 0 and btid < len(pch[1]) ):
					tmp[j] = pch[2][btid]
				j += 1
			
			log[2] = tmp.copy()
			encr = int.from_bytes(tmp, byteorder="little")
			encr = (encr + key) & 0xFFFFFFFF
			ptch = encr.to_bytes(4, byteorder="little")
			log[3] = ptch
			
			print("\t  Patching:", log[1].hex(), "(", log[0].hex(),") ->", log[2].hex(), "(", log[3].hex(), ")")
			
			fl.seek(-4, 1)
			fl.write(ptch)
			
			i += 4




##### main:

if len(sys.argv) != 2:
	print("Filename!")
	exit(-1)

key = 0
wfl=None
rdy = -2
pchn = 0



f = open(sys.argv[1], "r")

for ln in f:
	ln = ln.strip()
	a = ln.split(":")
	if len(a) == 2:
		a[0] = a[0].lower().strip()
		a[1] = a[1].strip()
		if a[0] == "target":
			if (wfl != None):
				wfl.close()
				wfl = None
			rdy = -2
			pchn = 0
			wfl = open(a[1], "rb+")
			if readPE(wfl):
				rdy = -1
				print("Wrk fl: ", a[1])
			else:
				print("Error: ", a[1])
		elif a[0] == "md5" and rdy == -1:
			md5 = bytearray.fromhex(a[1])
			if md5 == getMD5(wfl):
				rdy = 0
			else:
				print("\tBad md5")
		elif a[0] == "key" and rdy == 0:
			key = int(a[1], 16)
			rdy = 1
		elif a[0] == "patch" and rdy == 1:
			b = a[1].split("|")
			pchn += 1
			if len(b) == 3:
				b[0] = int(b[0], 16)
				b[1] = bytearray.fromhex(b[1])
				b[2] = bytearray.fromhex(b[2])
				if (len(b[1]) == len(b[2])):
					print("\tPatch #{}:".format(pchn),hex(b[0]), ":", b[1].hex(), "->", b[2].hex())
					Patch(wfl, key, b)		
										
			
	
if wfl != None:
	wfl.close()



#f = open("game.dll", "rb")

	