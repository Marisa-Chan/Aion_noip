#!/usr/bin/python

import sys
import os
import hashlib
import os.path
import io

dryrun = False
ImgBase = 0

class PESection:
	VAddr = 0
	VSize = 0
	Addr = 0
	Size = 0
	
	def __str__(self):
		return "VAddr {:08X} VSize {:08X} Addr {:08X} Size {:08X}".format(self.VAddr, self.VSize, self.Addr, self.Size)

class FileHash:
	filename = ""
	hsh = ""

class KeyOp:
	k = 0
	op = 0

Sections = list()

def read4int(fl):
	return int.from_bytes( fl.read(4) , byteorder='little' )

def read2int(fl):
	return int.from_bytes( fl.read(2) , byteorder='little' )

def readPE(fl):
	global ImgBase
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
	
	fl.seek(PE_POS + 0x18 + 28)
	ImgBase = read4int(fl)
	
	i = 0
	while i < secNumb:
		fl.seek(PE_POS + 0xF8 + i * 0x28) #sections
		name = fl.seek(8, 1)
		pes = PESection()
		pes.VSize = read4int(fl)
		pes.VAddr = read4int(fl) + ImgBase
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

def FAddr(vaddr, sz):
	z = GetSec(vaddr, sz)
	if not z:
		return -1
	return vaddr - z.VAddr + z.Addr

if len(sys.argv) < 2:
	print("Filename!")
	exit(-1)

f = open(sys.argv[1], "rb")
ib = io.BytesIO(f.read())

readPE(f)

if len(sys.argv) >= 4:
	addr = int(sys.argv[2], 0)
	num = int(sys.argv[3], 0)
	for i in range(num):
		a = addr + i * 4
		fa = FAddr(a, 4)
		if fa < 0:
			sys.exit("ERROR -1 ({:08X})".format(a))
		ib.seek(fa)
		dat = read4int(ib)
		otp = dat - ImgBase
		print(hex(a), hex(dat), hex(otp))
		
		ib.seek(fa)
		ib.write( otp.to_bytes(4, byteorder="little") )

ib.seek(0)
o = open("out.dll", "wb")
o.write(ib.read())
o.close()
		
	