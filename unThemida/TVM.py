#!/usr/bin/python3

import sys
VMA = 0
R_EIP = 0x9F
R_FIRSTFUNCPTR = 0x56
R_31 = 0x31
R_39 = 0x39
R_69 = 0x69
R_4a = 0x4a
R_8c = 0x8c
R_5c = 0x5c
R_8a = 0x8a
R_9d = 0x9d
R_08 = 0x08
R_2c = 0x2C
R_a7 = 0xa7
R_ImgBase = 0x99 
R_OldBase = 0x45

def U32(numb):
	return numb & ((1 << 32) - 1)

def JCC(tp):
	if (tp == 0xa2):
		return "JNB/JNC [CF == 0]"
	elif (tp == 0x80 or tp == 0x4b):
		return "JE/JZ [ZF == 1]"
	elif (tp == 0x04):
		return "JNE/JNZ [ZF == 0]"
	elif (tp == 0xfc):
		return "JA/JNBE [CF == 0 & ZF == 0]"
	elif (tp == 0x9c):
		return "JB/JC/JNAE [CF == 1]"
	elif (tp == 0xd0):
		return "JBE/JNA [CF == 1 | ZF == 1]"
	elif (tp == 0x0c):
		return "JG/JNLE [ZF == 0 & SF == OF]"
	elif (tp == 0x3a):
		return "JGE/JNL [SF == OF]"
	elif (tp == 0x94):
		return "JL/JNGE [SF != OF]"
	elif (tp == 0x4b):
		return "JLE/JNG [ZF == 1 | SF != OF]"
	elif (tp == 0xdb):
		return "JNO [OF == 0]"
	elif (tp == 0x92):
		return "JNP/JPO [PF == 0]"
	elif (tp == 0xdd):
		return "JNS [SF == 0]"
	elif (tp == 0xf5):
		return "JO [OF == 1]"
	elif (tp == 0x52):
		return "JP/JPE [PF == 1]"
	elif (tp == 0xf3):
		return "JS [SF == 1]"
	else:
		sys.exit("UNKNOWN ASM_0xCF TP: {:02X}".format(tp))

class EFLAGS:
	CF = 0
	PF = 0
	AF = 0
	ZF = 0
	SF = 0
	TF = 0
	IF = 0
	DF = 0
	OF = 0
	IOPL = 0
	NT = 0
	RF = 0
	VM = 0
	AC = 0
	VIF = 0
	VIP = 0
	ID = 0
	def __init__(self, *args):
		if len(args) == 1:
			flags = args[0]
			self.CF = (flags >> 0) & 1
			self.PF = (flags >> 2) & 1
			self.AF = (flags >> 4) & 1
			self.ZF = (flags >> 6) & 1
			self.SF = (flags >> 7) & 1
			self.TF = (flags >> 8) & 1
			self.IF = (flags >> 9) & 1
			self.DF = (flags >> 10) & 1
			self.OF = (flags >> 11) & 1
			self.IOPL = (flags >> 12) & 3
			self.NT = (flags >> 14) & 1
			self.RF = (flags >> 16) & 1
			self.VM = (flags >> 17) & 1
			self.AC = (flags >> 18) & 1
			self.VIF = (flags >> 19) & 1
			self.VIP = (flags >> 20) & 1
			self.ID = (flags >> 21) & 1
		elif len(args) == 3:
			if (args[0] == "cmp"):
				if (U32(args[2]) > U32(args[1])):
					self.CF = 1
				if ((args[1] & 0x80000000) != ((args[1] - args[2]) & 0x80000000)):
					self.OF = 1
				if ((args[1] - args[2]) & 0x80000000):
					self.SF = 1
				if (U32(args[1]) == U32(args[2])):
					self.ZF = 1
				if (((args[1] - args[2]) & 0x1) == 0):
					self.PF = 1
	
	def __str__(self):
		return "C{:d} P{:d} A{:d} Z{:d} S{:d} T{:d} I{:d} D{:d} O{:d}".format(self.CF, self.PF, self.AF, self.ZF, self.SF, self.TF, self.IF, self.DF, self.OF)
	def __int__(self):
		return self.CF | (self.PF << 2) | (self.AF << 4) | (self.ZF << 6) | (self.SF << 7) | (self.TF << 8) | (self.IF << 9) | (self.DF << 10) | (self.OF << 11)

class VMem:
	mem = None
	
	def __init__(self, val = None):
		if val:
			self.mem = val
		else:
			self.mem = dict()
	
	def Set(self, addr, data):
		for i in range(len(data)):
			self.mem[addr + i] = data[i]
	
	def Get(self, addr, ln, report = True):
		out = bytearray()
		said = False
		for i in range(ln):
			a = addr + i
			if a in self.mem:
				out.append( self.mem[a] & 0xFF )
			else:
				if not said :#and report:
					print("Empty access {:08X} ({:01X}) ({:02X})".format(addr, ln, addr - VMA))
					said = True
				out.append( 0 ) #0xA5 )
		return out
	def copy(self):
		return VMem(self.mem.copy())

class VMReg:
	addr = 0
	sz = 0
	vmmem = None
	def __init__(self, a, s, m):
		self.addr = a
		self.sz = s
		self.vmmem = m
	
	def __getitem__(self, key):
		return int.from_bytes( self.vmmem.Get(self.addr + key, self.sz, False), byteorder="little" )
	
	def __setitem__(self, key, value):
		mask = (1 << (self.sz * 8)) - 1
		val = value & mask
		self.vmmem.Set(self.addr + key, int(val).to_bytes(self.sz, byteorder="little" ))


class VMRoute:
	mem = None
	next = 0
	eip = 0
	esp = 0
	
	def __init__(self, vm, n, i, OnCopy = True):
		if OnCopy:
			self.mem = vm.mem.copy()
		else:
			self.mem = vm.mem
		self.next = n
		self.eip = i
		self.esp = vm.esp

class VMState:
	data = None
	next = 0
	run = True
	mem = None
	
	Routes = None
	
	OnEnd = None
	
	esp = 0
	VMA = 0
	
	def __init__(self):
		self.mem = VMem()
		self.Routes = list()
		
	def rMem(self, addr, ln):
		return self.mem.Get(addr, ln)
		
	def wMem(self, addr, data):
		self.mem.Set(addr, data)
	
	def rMem1(self, addr):
		return int.from_bytes( self.mem.Get(addr, 1), byteorder="little" )
		
	def rMem2(self, addr):
		return int.from_bytes( self.mem.Get(addr, 2), byteorder="little" )
	
	def rMem4(self, addr):
		return int.from_bytes( self.mem.Get(addr, 4), byteorder="little" )
	
	def wMem1(self, addr, val):
		self.mem.Set(addr, (val & 0xFF).to_bytes(1, byteorder="little") )
	
	def wMem2(self, addr, val):
		self.mem.Set(addr, (val & 0xFFFF).to_bytes(2, byteorder="little") )
	
	def wMem4(self, addr, val):
		self.mem.Set(addr, (val & 0xFFFFFFFF).to_bytes(4, byteorder="little") )
	
	def push(self, val):
		self.esp -= 4
		self.wMem4(self.esp, val)
	
	def pop(self):
		self.esp += 4
		#return self.rMem4(self.esp - 4)
		return int.from_bytes( self.mem.Get(self.esp - 4, 4, False), byteorder="little" )
		

	def __getattr__(self, name):
		if name == "reg1":
			return VMReg(self.VMA, 1, self.mem)
		elif name == "reg2":
			return VMReg(self.VMA, 2, self.mem)
		elif name == "reg4":
			return VMReg(self.VMA, 4, self.mem)
		
		raise AttributeError
		
	def read2(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos + 2 >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.regs[R_EIP], dx, len(data)))
		
		return int.from_bytes(self.data[pos:pos+2], byteorder="little")
	
	def read4(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos + 4 >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.regs[R_EIP], dx, len(data)))
		
		return int.from_bytes(self.data[pos:pos+4], byteorder="little")
	
	def read(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.regs[R_EIP], dx, len(data)))
		
		return int(self.data[pos])
	
	def chEIP(self, step):
		self.reg4[R_EIP] += step
	
	def AddRoute(self, next, eip, _OnCopy = True):
		rt = VMRoute(self, next, eip, _OnCopy)
		self.Routes.append(rt)

	def VM_ADD_R_RM(self, log, r1, r2, efl = -1):
		adr = self.reg4[r2]
		v1 = self.reg4[r1]
		v2 = self.rMem4(adr)
		res = U32(v1 + v2)
		log.append("VMR[{0:02X}] += [VMR[{1:02X}]] ({2:02X} += [{3:02X}]) ({2:02X} += {4:02X}) ({5:02X})".format(r1, r2, v1, adr, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))

	def VM_ADD_RM_R(self, log, r1, r2, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		v2 = self.reg4[r2]
		res = U32(v1 + v2)
		log.append("[VMR[{0:02X}]] += VMR[{1:02X}] ([{2:02X}] += {3:02X}) ({4:02X} += {3:02X}) ({5:02X})".format(r1, r2, adr, v2, v1, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_RM_R(self, log, r1, r2, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		v2 = self.reg4[r2]
		res = U32(v1 - v2)
		log.append("[VMR[{0:02X}]] -= VMR[{1:02X}] ([{2:02X}] -= {3:02X}) ({4:02X} -= {3:02X}) ({5:02X})".format(r1, r2, adr, v2, v1, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_ADD_RM_V(self, log, r1, val, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		res = U32(v1 + val)
		log.append("[VMR[{0:02X}]] += {1:02X} ([{2:02X}] += {1:02X}) ({3:02X} += {1:02X}) ({4:02X})".format(r1, val, adr, v1, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_RM_V(self, log, r1, val, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		res = U32(v1 - val)
		log.append("[VMR[{0:02X}]] -= {1:02X} ([{2:02X}] -= {1:02X}) ({3:02X} -= {1:02X}) ({4:02X})".format(r1, val, adr, v1, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_ADD_R_V(self, log, r, val, efl = -1):
		v1 = self.reg4[r]
		res = U32(v1 + val)
		log.append("VMR[{0:02X}] += {1:02X} ({2:02X} += {1:02X}) ({3:02X})".format(r, val, v1, res))
		self.reg4[r] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_R_V(self, log, r, val, efl = -1):
		v1 = self.reg4[r]
		res = U32(v1 - val)
		log.append("VMR[{0:02X}] -= {1:02X} ({2:02X} -= {1:02X}) ({3:02X})".format(r, val, v1, res))
		self.reg4[r] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_ADD_R_R(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		v2 = self.reg4[r2]
		res = U32(v1 + v2)
		log.append("VMR[{0:02X}] += VMR[{1:02X}] ({2:02X} += {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_ADD_BR_B(self, log, r1, b, efl = -1):
		v1 = self.reg1[r1]
		res = (v1 + b) & 0xFF
		log.append("b, VMR[{0:02X}] += {1:02X}] ({2:02X} += {1:02X}) ({3:02X})".format(r1, b, v1, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_R_R(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		v2 = self.reg4[r2]
		res = U32(v1 - v2)
		log.append("VMR[{0:02X}] -= VMR[{1:02X}] ({2:02X} -= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_R_RM(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		adr = self.reg4[r2]
		v2 = self.rMem4(adr)
		res = U32(v1 - v2)
		log.append("VMR[{0:02X}] -= [VMR[{1:02X}]] ({2:02X} -= [{3:02X}]({4:02X})) ({5:02X})".format(r1, r2, v1, adr, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_OR_R_V(self, log, r, v2, efl = -1):
		v1 = self.reg4[r]
		res = U32(v1 | v2)
		log.append("VMR[{0:02X}] |= {1:02X} ({2:02X} |= {1:02X}) ({3:02X})".format(r, v2, v1, res))
		self.reg4[r] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_OR_R_R(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		v2 = self.reg4[r2]
		res = U32(v1 | v2)
		log.append("VMR[{0:02X}] |= VMR[{1:02X}] ({2:02X} |= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_OR_WR_WR(self, log, r1, r2, efl = -1):
		v1 = self.reg2[r1]
		v2 = self.reg2[r2]
		res = v1 | v2
		log.append("w, VMR[{0:02X}] |= w, VMR[{1:02X}] ({2:02X} |= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg2[r1] = res

		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_R_V(self, log, r, v2, efl = -1):
		v1 = self.reg4[r]
		res = U32(v1 ^ v2)
		log.append("VMR[{0:02X}] ^= {1:02X} ({2:02X} ^= {1:02X}) ({3:02X})".format(r, v2, v1, res))
		self.reg4[r] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_R_R(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		v2 = self.reg4[r2]
		res = U32(v1 ^ v2)
		log.append("VMR[{0:02X}] ^= VMR[{1:02X}] ({2:02X} ^= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_BR_BR(self, log, r1, r2, efl = -1):
		v1 = self.reg1[r1]
		v2 = self.reg1[r2]
		res = (v1 ^ v2) & 0xFF
		log.append("b, VMR[{0:02X}] ^= b, VMR[{1:02X}] ({2:02X} ^= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_BR_B(self, log, r1, v2, efl = -1):
		v1 = self.reg1[r1]
		res = (v1 ^ v2) & 0xFF
		log.append("b, VMR[{0:02X}] ^= {1:02X} ({2:02X} ^= {1:02X}) ({3:02X})".format(r1, v2, v1, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_R_RM(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		adr = self.reg4[r2]
		v2 = self.rMem4(adr)
		res = U32(v1 ^ v2)
		log.append("VMR[{0:02X}] ^= [VMR[{1:02X}]] ({2:02X} ^= [{3:02X}]({4:02X})) ({5:02X})".format(r1, r2, v1, adr, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_RM_R(self, log, r1, r2, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		v2 = self.reg4[r2]
		res = U32(v1 ^ v2)
		log.append("[VMR[{0:02X}]] ^= VMR[{1:02X}] ([{2:02X}]({3:02X}) ^= {4:02X}) ({5:02X})".format(r1, r2, adr, v1, v2, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XOR_RM_V(self, log, r1, v2, efl = -1):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		res = U32(v1 ^ v2)
		log.append("[VMR[{0:02X}]] ^= {1:02X} ([{2:02X}]({3:02X}) ^= {1:02X}) ({4:02X})".format(r1, v2, adr, v1, res))
		self.wMem4(adr, res)
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_BR_BR(self, log, r1, r2, efl = -1):
		v1 = self.reg1[r1]
		v2 = self.reg1[r2]
		res = (v1 - v2) & 0xFF
		log.append("b, VMR[{0:02X}] -= b, VMR[{1:02X}] ({2:02X} -= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_WR_WR(self, log, r1, r2, efl = -1):
		v1 = self.reg2[r1]
		v2 = self.reg2[r2]
		res = (v1 - v2) & 0xFFFF
		log.append("w, VMR[{0:02X}] -= w, VMR[{1:02X}] ({2:02X} -= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg2[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_SUB_BR_B(self, log, r1, b, efl = -1):
		v1 = self.reg1[r1]
		v2 = b & 0xFF
		res = (v1 - v2) & 0xFF
		log.append("b, VMR[{0:02X}] -= {1:02X} ({2:02X} -= {1:02X}) ({3:02X})".format(r1, v2, v1, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_XCHG_R_R(self, log, r1, r2):
		log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})   (VMR[{0:02X}] = {3:02X}  VMR[{1:02X}] = {2:02X})".format(r1, r2, self.reg4[r1], self.reg4[r2]))
		t = self.reg4[r2]
		self.reg4[r2] = self.reg4[r1]
		self.reg4[r1] = t
	
	def VM_XCHG_RM_R(self, log, r1, r2):
		adr = self.reg4[r1]
		v1 = self.rMem4(adr)
		v2 = self.reg4[r2]
		log.append("[VMR[{0:02X}]] <=> VMR[{1:02X}] ([{2:02X}]({3:02X}) <=> {4:02X})  ([{2:02X}] = {4:02X}  VMR[{1:02X}] = {3:02X})".format(r1, r2, adr, v1, v2))
		self.reg4[r2] = v1
		self.wMem4(adr, v2)
	
	def VM_ASGN_BRM_B(self, log, r, b):
		adr = self.reg4[r]
		log.append("b, [VMR[{0:02X}]] = {1:02X} ([{2:02X}] = {1:02X})".format(r, b, adr))
		self.wMem1(adr, b)
	
	def VM_ASGN_WRM_W(self, log, r, w):
		adr = self.reg4[r]
		w &= 0xFFFF
		log.append("w, [VMR[{0:02X}]] = {1:02X} ([{2:02X}] = {1:02X})".format(r, w, adr))
		self.wMem2(adr, w)
	
	def VM_ASGN_BR_BRM(self, log, r1, r2):
		adr = self.reg4[r2]
		b = self.rMem1(adr)
		log.append("b, VMR[{0:02X}] = b, [VMR[{1:02X}]] ([{2:02X}] --> {3:02X})".format(r1, r2, adr, b))
		self.reg1[r1] = b
	
	def VM_ASGN_RM_V(self, log, r, v):
		adr = self.reg4[r]
		log.append("[VMR[{0:02X}]] = {2:02X}  ([{1:02X}] = {2:02X})".format(r, adr, v))
		self.wMem4(adr, v)
	
	def VM_ASGN_WRM_WR(self, log, r1, r2):
		adr = self.reg4[r1]
		v = self.reg2[r2]
		log.append("w, [VMR[{0:02X}]] = w, VMR[{2:02X}]  ([{1:02X}] = {3:02X})".format(r1, adr, r2, v))
		self.wMem2(adr, v)
	
	def VM_ASGN_R_V(self, log, r, v):
		log.append("VMR[{0:02X}] = {1:02X}".format(r, v))
		self.reg4[r] = v
	
	def VM_ASGN_BR_B(self, log, r, v):
		log.append("b, VMR[{0:02X}] = {1:02X}".format(r, v & 0xFF))
		self.reg1[r] = v & 0xFF
	
	def VM_ASGN_BR_BR(self, log, r1, r2):
		v = self.reg1[r2]
		log.append("b, VMR[{0:02X}] = b, VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
		self.reg1[r1] = v
	
	def VM_ASGN_WR_BR(self, log, r1, r2):
		v = self.reg1[r2]
		log.append("w, VMR[{0:02X}] = b, VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
		self.reg2[r1] = v
	
	def VM_ASGN_R_WR(self, log, r1, r2):
		v = self.reg2[r2]
		log.append("VMR[{0:02X}] = w, VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
		self.reg4[r1] = v
	
	def VM_ASGN_WR_V(self, log, r, v):
		log.append("w, VMR[{0:02X}] = {1:02X}".format(r, v & 0xFFFF))
		self.reg2[r] = v
	
	def VM_ASGN_R_R(self, log, r1, r2):
		v = self.reg4[r2]
		log.append("VMR[{0:02X}] = VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
		self.reg4[r1] = v
	
	def VM_ASGN_R_RM(self, log, r1, r2):
		adr = self.reg4[r2]
		v = self.rMem4(adr)
		log.append("VMR[{0:02X}] = [VMR[{1:02X}]] ([{2:02X}] --> {3:02X})".format(r1, r2, adr, v))
		self.reg4[r1] = v
	
	def VM_ASGN_R_BRM(self, log, r1, r2):
		adr = self.reg4[r2]
		v = self.rMem1(adr)
		log.append("VMR[{0:02X}] = b, [VMR[{1:02X}]] ([{2:02X}] --> {3:02X})  #MOVZX".format(r1, r2, adr, v))
		self.reg4[r1] = v
	
	def VM_ASGN_R_BR(self, log, r1, r2):
		v = self.reg1[r2]
		log.append("VMR[{0:02X}] = b, VMR[{1:02X}] ({2:02X})  #MOVZX".format(r1, r2, v))
		self.reg4[r1] = v
	
	def VM_ASGN_WR_WR(self, log, r1, r2):
		v = self.reg2[r2]
		log.append("w, VMR[{0:02X}] = w, VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
		self.reg2[r1] = v
	
	def VM_AND_R_R(self, log, r1, r2, efl = -1):
		v1 = self.reg4[r1]
		v2 = self.reg4[r2]
		res = v1 & v2
		log.append("VMR[{0:02X}] &= VMR[{1:02X}] ({2:02X} &= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_AND_WR_WR(self, log, r1, r2, efl = -1):
		v1 = self.reg2[r1]
		v2 = self.reg2[r2]
		res = v1 & v2
		log.append("VMR[{0:02X}] &= VMR[{1:02X}] ({2:02X} &= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
		self.reg2[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_AND_R_V(self, log, r1, v2, efl = -1):
		v1 = self.reg4[r1]
		res = v1 & v2
		log.append("VMR[{0:02X}] &= {1:02X} ({2:02X} &= {1:02X}) ({3:02X})".format(r1, v2, v1, res))
		self.reg4[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_AND_BR_B(self, log, r1, v2, efl = -1):
		v1 = self.reg1[r1]
		v2 &= 0xFF
		res = v1 & v2
		log.append("b, VMR[{0:02X}] &= {1:02X} ({2:02X} &= {1:02X}) ({3:02X})".format(r1, v2, v1, res))
		self.reg1[r1] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_POP_R(self, log, r):
		v = self.pop()
		log.append("VMR[{0:02X}] = POP( {1:02X} )".format(r, v))
		self.reg4[r] = v
	
	def VM_POP_RM(self, log, r):
		adr = self.reg4[r]
		v = self.pop()
		log.append("[VMR[{0:02X}]] = POP( {1:02X} )   ( [{2:02X}] = POP( {1:02X} ))".format(r, v, adr))
		self.wMem4(adr, v)
	
	def VM_NEG_R(self, log, r, efl = -1):
		v = self.reg4[r]
		res = U32(-v)
		log.append("VMR[{0:02X}] = -VMR[{0:02X}] ({1:02X} --NEG--> {2:02X})".format(r, v, res))
		self.reg4[r] = res
	
		if (efl != -1):
			log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_NOT_RM(self, log, r):
		adr = self.reg4[r]
		v = self.rMem4(adr)
		res = U32(~v)
		log.append("[VMR[{0:02X}]] = ~[VMR[{0:02X}]] ([{1:02X}] --> {2:02X} --NOT--> {3:02X})".format(r, adr, v, res))
		self.wMem4(adr, res)
	
	def VM_LSH_R_V(self, log, r, t, efl = -1):
		t &= 0x1F
		if ( t ):
			v = self.reg4[r]
			res = U32(v << t)
			log.append("VMR[{0:02X}] <<= {1:02X} ({2:02X} <<= {1:02X}) ({3:02X})".format(r, t, v, res))
			self.reg4[r] = res

			if (efl != -1):
				log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_LSH_BR_V(self, log, r, t, efl = -1):
		t &= 0x1F
		if ( t ):
			v = self.reg1[r]
			res = U32(v << t) & 0xFF
			log.append("VMR[{0:02X}] <<= {1:02X} ({2:02X} <<= {1:02X}) ({3:02X})".format(r, t, v, res))
			self.reg1[r] = res

			if (efl != -1):
				log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_RSH_R_V(self, log, r, t, efl = -1):
		t &= 0x1F
		if ( t ):
			v = self.reg4[r]
			res = U32(v >> t)
			log.append("VMR[{0:02X}] >>= {1:02X} ({2:02X} >>= {1:02X}) ({3:02X})".format(r, t, v, res))
			self.reg4[r] = res

			if (efl != -1):
				log.append("VMR[{:02X}] = eflags".format(efl))
	
	def VM_CMP_R_V(self, log, r, v2, efl):
		v1 = self.reg4[r]
		log.append("VMR[{0:02X}] = CMP VMR[{1:02X}] ({2:02X}), {3:02X}".format(efl, r, v1, v2))


VMAsm = dict()


def ASM_0x257(state, log):
	state.next = state.read2(2)
	state.chEIP(+4)
	log.append("NOP \n;next = {:02X}".format(state.next))
VMAsm[0x257] = ASM_0x257

def ASM_0x444(state, log):
	state.reg4[ state.read2() ] = state.esp #"esp"
	state.next = state.read2(2)
	log.append("VMR[0x{:02X}] = {:02X}  <-- real ESP".format(state.read2(), state.reg4[ state.read2() ]))
	log.append(";next = {:02X}".format(state.next))
	state.chEIP(+4)
VMAsm[0x444] = ASM_0x444

def ASM_0x51(state, log):
	state.reg4[ R_2c ] = 0
	state.reg4[ R_39 ] = 0
	state.reg4[ R_4a ] = 0
	state.reg4[ R_5c ] = 0
	state.reg4[ R_69 ] = 0
	state.reg4[ R_a7 ] = 0
	state.reg4[ R_8c ] = 0
	
	state.reg2[ R_08 ] = 0
	state.reg2[ R_8a ] = 0
	state.reg2[ R_9d ] = 0

	state.next = state.read2(0)
	state.chEIP(+2)
	log.append("INIT REGZ \n;next = {:02X}".format(state.next))
VMAsm[0x51] = ASM_0x51

def ASM_0x4F5(state, log):
	state.reg4[ R_2c ] ^= 0x27257140
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] -= 0x27257140
	ivar2 = state.read2(0) + state.reg4[ R_2c ]
	state.reg4[ R_39 ] += ivar2
	state.reg4[ R_69 ] |= 0x1564fda6
	state.reg2[ R_9d ] ^= (ivar2 & 0xFFFF)
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] &= 0x7f971425	
	svar = state.reg2[R_9d] & 0xFFFF
	r = (svar + 0x21E1) & 0xFFFF
	state.VM_POP_R(log, r)

	r2 = state.read2(4)
	if ( r != r2 ):
		state.VM_ADD_R_V(log, r2, 4)
	
	uvar3 = state.read2(2) + state.reg4[ R_39 ]
	state.reg4[ R_39 ] ^= uvar3

	state.next = uvar3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F5] = ASM_0x4F5


def ASM_0x2AC(state, log):
	r1 = state.read2(0)
	r2 = state.read2(2)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uvar3 = U32(state.read2(8) + state.reg4[ R_39 ] + state.reg4[ R_2c ])
	state.reg4[ R_39 ] &= uvar3
	state.reg4[ R_69 ] ^= 0x604cadfc
	state.reg2[ R_9d ] ^= (uvar3 & 0xFFFF)
	
	r3 = (state.reg2[ R_9d ] & 0xFFFF) ^ 0xfba4
	state.VM_POP_R(log, r3)
	
	r4 = state.read2(6)
	if (r4 != r3):
		state.VM_ADD_R_V(log, r4, 4)
	
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] |= 0x4774ac77
	
	tmp = U32(state.read2(4) + 0xaa6ba9d7)
	state.reg4[ R_39 ] ^= tmp
	
	state.next = tmp & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2AC] = ASM_0x2AC

def ASM_0x33C(state, log):
	state.reg4[ R_2c ] += state.reg4[ R_39 ]
	uVar1 = state.read2(0)
	state.reg4[ R_69 ] ^= 0x1e86ebd3
	state.reg2[ R_9d ] ^= uVar1
	if ((state.reg4[ R_69 ] & 1) != 0):
		state.reg4[ R_69 ] &= 0x2d5763d8
	r1 = (state.reg2[ R_9d ] & 0xFFFF) ^ 0x4d5e
	state.VM_POP_R(log, r1)
	
	r2 = state.read2(6)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
	
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] -= 0xf7b3c5b
	
	uVar2 = U32(state.read2(4) + state.reg4[ R_39 ] + 0xfc3344ba)
	state.reg4[ R_39 ] &= uVar2
	
	state.next = uVar2 & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x33C] = ASM_0x33C

def ASM_0x212(state, log):
	t1 = state.read2(4) ^ state.reg4[ R_2c ]
	state.reg4[ R_39 ] &= t1
	state.reg4[ R_69 ] |= 0x20a66696
	state.reg2[ R_9d ] -= t1 & 0xFFFF
	
	r1 = (state.reg2[ R_9d ] & 0xFFFF)
	state.VM_POP_R(log, r1)

	r2 = state.read2(0)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
		
	state.reg4[ R_39 ] -= state.read4(14)
	state.reg4[ R_39 ] -= state.read4(10)
	state.reg4[ R_39 ] -= state.read4(6)
	
	uvar3 = U32((state.read2(2) ^ state.reg4[ R_39 ]) + 0x87a69b9f)
	state.reg4[ R_39 ] |= uvar3
	
	state.next = uvar3 & 0xFFFF
	state.chEIP(+20)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x212] = ASM_0x212


def ASM_0x446(state, log):
	state.reg4[ R_69 ] += 0x363c8801
	state.reg4[ R_2c ] += state.reg4[ R_39 ]
	state.reg4[ R_69 ] &= 0x68c890ff
	
	r1 = state.read2(2)
	state.VM_POP_R(log, r1)

	r2 = state.read2(4)
	state.VM_ADD_R_V(log, r2, 4)
	
	uvar3 = state.read2(0) ^ state.reg4[ R_39 ] ^ 0x4b76c880
	state.next = uvar3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x446] = ASM_0x446

def ASM_0x46A(state, log):
	r = state.read2(3)
	val = state.read(2)
	state.VM_ADD_R_V(log, r, val)
	log.append("#esp += 0x{:02X}".format(val))
	
	state.esp += val	
	
	uvar1 = U32((state.read2(0) ^ state.reg4[ R_39 ]) + 0x446890a5)
	state.reg4[ R_39 ] += uvar1
	
	state.next = uvar1 & 0xFFFF
	
	state.chEIP(+5)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x46A] = ASM_0x46A

def ASM_0x19C(state, log):
	t1 = (state.read2(2) ^ state.reg4[ R_39 ]) + state.reg4[ R_2c ]
	state.reg4[ R_39 ] |= t1
	state.reg2[ R_9d ] += t1 & 0xFFFF
	
	r0 = (state.reg2[ R_9d ] - 0x63c2) & 0xFFFF
	log.append("#push VMR[{:02X}] ({:02X})".format(r0, state.reg4[ r0 ]))
	state.push(state.reg4[ r0 ])
	
	state.reg4[ R_39 ] ^= 0x6bf5fe56
	state.reg4[ R_69 ] ^= 0x3458266d
	
	r1 = state.read2(4)
	state.reg4[ r1 ] -= 4
	log.append("VMR[{:02X}] -= 4".format(r1))
	
	if (state.reg4[ R_69 ] & 1):
		state.reg4[ R_69 ] |= 0x6b9232f0
		
	t2 = state.read2(0) ^ 0x48151a
	state.next = t2 & 0xFFFF
	
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x19C] = ASM_0x19C

def ASM_0x2FD(state, log):
	t1 = U32((state.read(0) - state.reg4[ R_39 ]) + state.reg4[ R_69 ])
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] += 0x2c9d91f9
	state.reg4[ R_8c ] ^= t1
	state.reg4[ R_a7 ] &= t1
	state.reg4[ R_2c ] -= state.reg4[ R_39 ]
	
	t2 = state.read2(7) ^ state.reg4[ R_39 ] ^ state.reg4[ R_2c ]
	state.reg4[ R_39 ] |= t2
	state.reg2[ R_9d ] ^= t2 & 0xFFFF
	
	r1 = (state.reg2[ R_9d ] + 0xcea0) & 0xFFFF
	val = (((state.reg4[ R_8c ]) & 0xFF) + 0xc1) & 0xFF
	state.VM_ASGN_BR_B(log, r1, val)
	
	t3 = U32(U32(state.read2(1) + state.reg4[ R_39 ]) ^ 0x41a790e7)
	state.reg4[ R_39 ] += t3
	
	state.next = t3 & 0xFFFF
	
	state.chEIP(+9)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2FD] = ASM_0x2FD


def ASM_0x2D5(state, log):
	t1 = (state.read2(6) - state.reg4[ R_39 ]) - state.reg4[ R_2c ]
	state.reg4[ R_39 ] -= t1
	state.reg4[ R_69 ] |= 0x6f7143e8
	state.reg2[ R_9d ] += t1 & 0xFFFF
	
	t2 = (state.read2(2) ^ state.reg4[ R_39 ]) + state.reg4[ R_a7 ]
	state.reg4[ R_39 ] |= t2
	state.reg4[ R_69 ] -= 0x1bbc361d
	state.reg2[ R_8a ] ^= t2 & 0xFFFF
	
	r1 = (state.reg2[ R_9d ] ^ 0x5f71) & 0xFFFF
	r2 = (state.reg2[ R_8a ] ^ 0xc4ef) & 0xFFFF

	log.append("VMR[{:02X}] |= VMR[{:02X}]".format(r1, r2))
	state.reg4[ r1 ] |= state.reg4[ r2 ]
	
	r3 = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r3))
	
	t3 = state.read2(8) + state.reg4[ R_39 ] + 0x6eb54eb6
	state.reg4[ R_39 ] -= t3
	
	state.next = t3 & 0xFFFF
	
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2D5] = ASM_0x2D5


def ASM_0x1BE(state, log):
	state.reg4[ R_39 ] -= state.read4(14)
	t1 = state.read2(6) - state.reg4[ R_a7 ]
	
	state.reg4[ R_39 ] |= t1
	state.reg4[ R_69 ] &= 0x728239c6
	state.reg2[ R_8a ] += t1 & 0xFFFF
	
	t2 = state.read2(4)
	state.reg4[ R_69 ] |= 0x2f60b688
	state.reg2[ R_9d ] -= (t2 + state.reg4[ R_39 ]) & 0xFFFF
	
	r1 = (state.reg2[ R_9d ] + 0xa04b) & 0xFFFF
	r2 = (state.reg2[ R_8a ] + 0x50a1) & 0xFFFF

	log.append("VMR[{:02X}] |= VMR[{:02X}]".format(r1, r2))
	state.reg4[ r1 ] |= state.reg4[ r2 ]
	
	r3 = state.read2(12)
	log.append("VMR[{:02X}] = eflags".format(r3))
	
	t3 = (state.read2(2) ^ state.reg4[ R_39 ]) + 0x1f439d9
	state.reg4[ R_39 ] ^= t3
	
	state.next = t3 & 0xFFFF
	
	state.chEIP(+18)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1BE] = ASM_0x1BE


def ASM_0x328(state, log):
	t1 = state.read2(10) - state.reg4[ R_a7 ]
	state.reg4[ R_39 ] += t1
	state.reg4[ R_69 ] += 0x32e7d9b0
	state.reg2[ R_8a ] ^= t1 & 0xFFFF
	
	t2 = state.read2(2) + state.reg4[ R_39 ] ^ state.reg4[ R_2c ]
	state.reg4[ R_39 ] |= t2
	state.reg4[ R_69 ] ^= 0x51499193
	state.reg2[ R_9d ] ^= t2 & 0xFFFF
	
	r1 = state.reg2[ R_9d ] & 0xFFFF
	r2 = (state.reg2[ R_8a ] ^ 0xd9e5) & 0xFFFF

	log.append("b, VMR[{:02X}] ^= b, VMR[{:02X}]".format(r1, r2))
	state.reg1[ r1 ] ^= (state.reg1[ r2 ]) & 0xFF
	
	r3 = state.read2(12)
	log.append("VMR[{:02X}] = eflags".format(r3))
	
	t3 = (state.read2(6) - state.reg4[ R_39 ]) + 0x59c44544
	state.reg4[ R_39 ] ^= t3
	
	state.next = t3 & 0xFFFF
	
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x328] = ASM_0x328


def ASM_0x213(state, log):
	state.reg4[ R_2c ] += 0x36a20511
	state.reg4[ R_a7 ] &= state.reg4[ R_69 ]
	state.reg4[ R_a7 ] += 0x36a20511

	t1 = state.read4(0) ^ state.reg4[ R_69 ]
	state.reg4[ R_69 ] -= 0x570cca79
	state.reg4[ R_8c ] ^= t1
	state.reg4[ R_a7 ] += t1
	
	pval = state.reg4[ R_8c ] ^ 0x6d28a5b6
	log.append("#push {:02X}".format(pval))
	state.push(pval)
	
	r1 = state.read2(6)

	log.append("VMR[{:02X}] -= 4".format(r1))
	state.reg4[ r1 ] -= 4
	
	t3 = (state.read2(4) - state.reg4[ R_39 ]) ^ 0x55460bdd
	state.reg4[ R_39 ] &= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x213] = ASM_0x213

def ASM_0x37E(state, log):
	t1 = state.read2(2) ^ state.reg4[ R_39 ] ^ state.reg4[ R_a7 ]
	state.reg4[ R_39 ] ^= t1
	state.reg2[ R_8a ] ^= t1 & 0xFFFF
	state.reg4[ R_69 ] -= 0xdbd337f
	state.reg4[ R_39 ] ^= 0x2606d533
	state.reg4[ R_69 ] |= 0x72042af0
	
	t2 = state.read2(0) + state.reg4[ R_39 ] ^ state.reg4[ R_2c ]
	state.reg4[ R_39 ] |= t2
	state.reg2[ R_9d ] ^= t2 & 0xFFFF
	state.reg4[ R_69 ] |= 0x3a5379d5
	state.reg4[ R_39 ] ^= state.read4(8)
	
	r1 = (state.reg2[ R_9d ] + 0xca38) & 0xFFFF
	r2 = (state.reg2[ R_8a ] + 0x2e0b) & 0xFFFF

	log.append("[ VMR[{:02X}] ] = VMR[{:02X}]".format(r1, r2))
	log.append("[ {:02X} ] = {:02X}".format(state.reg4[ r1 ], state.reg4[ r2 ]))
	v1 = state.reg4[r2]
	state.wMem4(state.reg4[ r1 ], v1)
	
	t3 = (state.read2(4) ^ 0x603cc1c1) & 0xFFFF
	
	state.next = t3 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x37E] = ASM_0x37E

def ASM_0x1A0(state, log):
	t1 = state.read2(0) - state.reg4[ R_39 ]
	state.reg4[ R_39 ] |= t1
	state.reg2[ R_9d ] -= t1 & 0xFFFF
	state.reg4[ R_69 ] &= 0x351ab5ed
	
	if ( state.reg4[ R_69 ] & 1):
		state.reg4[ R_69 ] += 0x1a136748
	
	r0 = state.reg2[ R_9d ] & 0xFFFF
	log.append("#push VMR[{:02X}] ({:02X})".format(r0, state.reg4[ r0 ]))
	state.push(state.reg4[ r0 ])
	
	r1 = state.read2(4)
	
	log.append("VMR[{:02X}] -= 4".format(r1))
	state.reg4[ r1 ] -= 4 
	
	t2 = (state.read2(2) + 0x56bfbf9a) & 0xFFFF
	
	state.next = t2 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1A0] = ASM_0x1A0

def ASM_0xDC(state, log):
	state.reg4[ R_39 ] |= 0x1c138731
	t1 = state.read2(0) + state.reg4[ R_39 ] - state.reg4[ R_2c ]
	state.reg4[ R_39 ] |= t1
	state.reg2[ R_9d ] -= t1 & 0xFFFF
	state.reg4[ R_69 ] |= 0x6ea58627
	state.reg4[ R_39 ] += 0x12e194da
	
	t2 = state.read2(4)
	state.reg2[ R_8a ] -= (t2 ^ state.reg4[ R_39 ] ^ state.reg4[ R_a7 ]) & 0xFFFF
	state.reg4[ R_69 ] += 0x3bd0d32b
	state.reg4[ R_69 ] |= 0x4d2c08cd
	
	r2 = state.reg2[ R_8a ] & 0xFFFF
	r1 = (state.reg2[ R_9d ] + 0x722f) & 0xFFFF
	state.VM_ASGN_R_R(log, r1, r2)
	
	state.reg4[ R_a7 ] -= state.reg4[ R_69 ]
	state.reg4[ R_a7 ] ^= 0x33fa2277
	
	t4 = (state.read2(2) ^ state.reg4[ R_39 ]) + 0x59d29897
	state.reg4[ R_39 ] &= t4
	
	state.next = t4 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xDC] = ASM_0xDC


def ASM_0x1E6(state, log):
	state.reg4[ R_39 ] &= state.read4(2)
	t1 = state.read2(10) - state.reg4[ R_39 ]
	state.reg4[ R_39 ] &= t1
	state.reg2[ R_9d ] -= t1 & 0xFFFF
	state.reg4[ R_69 ] += 0x6a20810d
	
	t2 = ((state.read4(6) + state.reg4[ R_39 ]) & 0xFFFFFFFF) - (state.reg4[ R_69 ] & 0xFFFFFFFF)
	state.reg4[ R_39 ] -= t2
	state.reg4[ R_8c ] -= t2
	state.reg4[ R_69 ] -= 0x76ed4087
	state.reg4[ R_69 ] |= 0x4537d39b
	
	val = state.reg4[ R_8c ]
	r1 = (state.reg2[ R_9d ] + 0xec02) & 0xFFFF
	
	state.VM_ADD_R_V(log, r1, val, state.read2(0))
	
	t4 = state.read2(12)
	state.reg4[ R_39 ] += t4
	
	state.next = t4 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1E6] = ASM_0x1E6


def ASM_0x3F8(state, log):
	r1 = state.read2(4)
	r2 = state.read2(16)
	state.VM_XCHG_R_R(log, r1, r2)

	t2 = (state.read2(8) - state.reg4[ R_39 ]) - state.reg4[ R_2c ]
	state.reg4[ R_39 ] ^= t2
	state.reg2[ R_9d ] ^= t2 & 0xFFFF
	
	t3 = state.read4(0) + state.reg4[ R_39 ] + state.reg4[ R_69 ]
	state.reg4[ R_39 ] &= t3
	state.reg4[ R_8c ] -= t3
	state.reg4[ R_a7 ] |= t3
	
	r3 = (state.reg2[ R_9d ] - 0x243) & 0xFFFF
	val = (state.reg4[ R_8c ] ^ 0x42e41707) & 0xFFFFFFFF

	state.reg4[ r3 ] -= val
	log.append("VMR[{:02X}] -= {:02X}   ({:02X})".format(r3, val, state.reg4[ r3 ]))
	
	if (state.reg4[ R_69 ] & 1):
		state.reg4[ R_69 ] ^= 0x3550df81
	
	r4 = state.read2(10)
	log.append("VMR[{:02X}] = eflags".format(r4))
	
	state.next = (state.read2(12) + 0xf1db5a25) & 0xFFFF
	state.chEIP(+18)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3F8] = ASM_0x3F8

def ASM_0x42E(state, log):
	t1 = state.read2(2) - state.reg4[ R_39 ] + state.reg4[ R_2c ]
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] |= 0xf2cef96
	state.reg2[ R_9d ] += t1 & 0xFFFF
	
	t2 = state.read2(0) - state.reg4[ R_39 ]
	state.reg4[ R_39 ] -= t2
	state.reg4[ R_69 ] += 0x30d13a14
	state.reg2[ R_8a ] += t2 & 0xFFFF
	
	r1 = state.reg2[ R_9d ] & 0xFFFF
	r2 = (state.reg2[ R_8a ] + 0x968a) & 0xFFFF
	
	state.VM_XCHG_RM_R(log, r1, r2)

	t3 = state.read2(4) - state.reg4[ R_39 ] + 0xe3e64fe3
	state.reg4[ R_39 ] -= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x42E] = ASM_0x42E

def ASM_0x1CF(state, log):
	state.reg4[ R_a7 ] |= state.reg4[ R_69 ]
	state.reg4[ R_a7 ] ^= 0x85dc771
	state.reg4[ R_69 ] += 0x133fa071
	
	r1 = state.read2(8)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)

	state.reg4[ R_2c ] ^= state.reg4[ R_39 ]
	t1 = (state.read2(6) - state.reg4[ R_39 ]) ^ state.reg4[ R_2c ]
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] |= 0x29135be6
	state.reg2[ R_9d ] -= t1 & 0xFFFF
	
	r3 = (state.reg2[ R_9d ] + 0x4d9f) & 0xFFFF
	r4 = state.read2(0)
	state.reg4[ R_a7 ] &= state.reg4[ R_69 ]
	
	state.VM_POP_R(log, r3)
	
	state.reg4[ R_a7 ] -= 0x3fb14265
	
	if ( r4 != r3 ):
		state.VM_ADD_R_V(log, r4, 4)
	
	t2 = state.read2(2)
	state.reg4[ R_39 ] += t2
	
	state.next = t2 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1CF] = ASM_0x1CF


def ASM_0x29C(state, log):
	r0 = state.read2(0)
	log.append("#esp = VMR[{:02X}] ({:02X})".format(r0, state.reg4[r0]))
	state.esp = state.reg4[r0]
	
	t1 = state.read2(2) - state.reg4[R_39] + 0xf2afaf5e
	state.reg4[R_39] ^= t1
	
	state.next = t1 & 0xFFFF
	state.chEIP(+4)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x29C] = ASM_0x29C


def ASM_0x305(state, log):
	state.reg4[R_39] &= state.read4(6)
	state.reg4[R_2c] += state.reg4[R_39]
	state.reg4[R_39] -= 0xc0ca3d7
	state.reg2[R_8a] -= (state.read2(4) + state.reg4[R_39]) & 0xFFFF
	state.reg2[R_9d] += (state.read2(0) - state.reg4[R_2c]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x32fa) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0xf171) & 0xFFFF
	state.VM_ASGN_R_R(log, r1, r2)
	
	t1 = (state.read2(2) ^ state.reg4[R_39]) + 0x6f007d5
	state.reg4[R_39] &= t1
	
	state.next = t1 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x305] = ASM_0x305


def ASM_0x2C1(state, log):
	state.reg4[R_39] += 0x614ef7d7
	state.reg4[R_69] &= 0x6e148bb4
	
	r1 = state.read2(0)
	r2 = state.read2(6)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(16)
	state.reg4[R_69] += 0x103bdcf2
	state.reg2[R_9d] ^= (t1 ^ state.reg2[R_2c]) & 0xFFFF
	
	t2 = (state.read4(2) + state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] ^= t2
	state.reg4[R_69] &= 0x4c55e123
	state.reg4[R_8c] -= t2
	state.reg4[R_a7] += t2
	
	val = state.reg4[R_8c] & 0xFFFFFFFF
	r3 = (state.reg2[R_9d] + 0x846) & 0xFFFF
	state.VM_ADD_R_V(log, r3, val, state.read2(14))
	
	t3 = state.read2(8) - state.reg4[R_39] + 0xeb332817
	state.reg4[R_39] += t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+18)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C1] = ASM_0x2C1


def ASM_0x0E(state, log):
	r1 = state.read2(0)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read4(6) ^ state.reg4[R_69]
	state.reg4[R_39] += t1	
	state.reg4[R_69] ^= 0x77a94a0a
	state.reg4[R_8c] ^= t1
	state.reg4[R_a7] += t1
	state.reg4[R_2c] ^= 0x337393bc
	state.reg4[R_69] ^= 0x337393bc
	
	t2 = state.read2(12) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] ^= t2
	state.reg4[R_69] += 0x39e05d84
	state.reg2[R_9d] -= t2 & 0xFFFF
	state.reg4[R_39] &= 0x1492d776
	state.reg4[R_69] += 0x245a6bb1
	
	val = (state.reg4[R_8c] + 0x64e6dc62) & 0xFFFFFFFF
	r3 = (state.reg2[R_9d] + 0x8141) & 0xFFFF
	
	state.reg4[r3] -= val
	log.append("VMR[{:02X}] -= {:02X}".format(r3, val))
	
	r4 = state.read2(10)
	log.append("VMR[{:02X}] = eflags".format(r4))
	
	t3 = state.read2(2) - state.reg4[R_39] + 0x98dd6af8
	state.reg4[R_39] ^= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x0E] = ASM_0x0E


def ASM_0x1DD(state, log):
	t1 = state.read2(0) + state.reg4[R_2c]
	state.reg4[R_39] -= t1
	state.reg4[R_69] += 0x1276682a
	state.reg2[R_9d] -= t1 & 0xFFFFF
	
	t2 = state.read2(4)
	state.reg4[R_69] |= 0x45dd9ca5
	state.reg2[R_8a] ^= t2 ^ state.reg2[R_39] ^ state.reg2[R_a7]
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] ^= 0x41ec4b37
	
	r1 = (state.reg2[R_9d] + 0x37b3) & 0xFFFF
	r2 = (state.reg2[R_8a] - 0xd6a) & 0xFFFF
	log.append("[ VMR[{:02X}] ] = VMR[{:02X}]".format(r1, r2))
	log.append("[ {:02X} ] = {:02X}".format(state.reg4[r1], state.reg4[r2]))
	
	state.wMem4(state.reg4[r1], state.reg4[r2])

	state.next = (state.read2(2) + 0x7e11146e) & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1DD] = ASM_0x1DD

def ASM_0x2C8(state, log):
	r1 = state.read2(0)
	log.append("VMR[{:02X}] = VMR[31] ({:02X})".format(r1, state.reg4[R_31]))
	state.reg4[r1] = state.reg4[R_31]
	
	t1 = state.read2(2) + state.reg4[R_39] + 0x356df77b
	state.reg4[R_39] -= t1
	
	state.next = t1 & 0xFFFF
	state.chEIP(+4)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C8] = ASM_0x2C8


def ASM_0x3A6(state, log):
	t1 = state.read2(4) - state.reg4[R_2c]
	state.reg4[R_39] += t1
	state.reg4[R_69] -= 0x3fe9b968
	state.reg2[R_9d] -= t1 & 0xFFFF
	
	t2 = state.read2(0)
	state.reg4[R_69] += 0x7c279797
	state.reg2[R_8a] ^= (t2 - state.reg2[R_39]) & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a] ^ 0x6a88
	state.VM_ASGN_R_R(log, r1, r2)
	
	t3 = (state.read2(2) ^ state.reg4[R_39]) + 0xf406838c
	state.reg4[R_39] ^= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A6] = ASM_0x3A6

def ASM_0x376(state, log):
	t1 = state.read2(0)
	state.reg4[R_69] &= 0x6e5b0dbc
	state.reg2[R_9d] ^= ((t1 + state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	state.reg4[R_39] += 0x1dde4fb1
	state.reg4[R_69] -= 0x24b82437
	state.reg4[R_69] -= 0x408a10c8
	state.reg4[R_39] -= state.read4(2)

	t2 = (state.read4(12) - state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] += t2
	state.reg4[R_69] |= 0x495a975d
	state.reg4[R_8c] -= t2
	state.reg4[R_a7] -= t2
	state.reg4[R_39] += state.read4(6)

	r1 = state.reg2[R_9d] ^ 0xebd7
	val = U32(state.reg4[R_8c] + 0x2cc51fb8)
	state.VM_ADD_R_V(log, r1, val)
	
	t3 = U32(state.read2(10) + 0x18541491)
	state.reg4[R_39] ^= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x376] = ASM_0x376

def ASM_0x4C8(state, log):
	r1 = state.read2(4)
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(8) - state.reg4[R_39]
	state.reg4[R_39] ^= t1
	state.reg4[R_69] ^= 0xd9ec6
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = state.read2(2)
	state.reg4[R_69] ^= 0x559094ad
	state.reg2[R_9d] += ((t2 - state.reg2[R_39]) ^ state.reg2[R_2c])
	
	r1 = (state.reg2[R_9d] + 0x4084) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xaaf8) & 0xFFFF
	
	log.append("VMR[{:02X}] = [ VMR[{:02X}] ]".format(r1, r2))
	log.append("VMR[{:02X}] = [{:02X}] ({:02X})".format(r1, state.reg4[r2], state.rMem4( state.reg4[r2] )))
	state.reg4[r1] = state.rMem4( state.reg4[r2] )
	
	t3 = state.read2(12) + state.reg4[R_39] + 0xde259aac
	state.reg4[R_39] -= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4C8] = ASM_0x4C8

def ASM_0x361(state, log):
	t1 = state.read2(0)
	state.reg4[R_39] += t1
	state.reg4[R_69] += 0x4cbe390e
	state.reg2[R_9d] ^= t1 & 0xFFFF
	
	r0 = (state.reg2[ R_9d ] + 0xc7e3) & 0xFFFF
	log.append("#push VMR[{:02X}] ({:02X})".format(r0, state.reg4[ r0 ]))
	state.push(state.reg4[ r0 ])
	
	state.reg4[R_39] += 0x5facaeba
	state.reg4[R_69] -= 0x7a2d9187
	
	r1 = state.read2(8)
	state.reg4[r1] -= 4
	log.append("VMR[{:02X}] -= 4   ({:02X})".format(r1, state.reg4[r1]))
	
	t2 = state.read2(6) ^ 0x3128bb58
	state.reg4[R_39] ^= t2

	state.next = t2 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x361] = ASM_0x361


def ASM_0x3AB(state, log):
	t1 = state.read4(0)
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x3e71c506
	
	state.reg4[R_39] -= t1
	state.reg4[R_2c] -= 0x2299385f
	state.reg4[R_39] -= 0x2299385f
	
	t2 = state.read2(8) ^ state.reg4[R_39]
	state.reg4[R_39] &= t2
	state.reg4[R_69] &= 0x61b2065a
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	t3 = (state.read4(4) ^ state.reg4[R_39]) - state.reg4[R_69]
	state.reg4[R_69] += 0x3fd96b44
	state.reg4[R_8c] -= t3
	state.reg4[R_a7] += t3
	
	r1 = (state.reg2[R_9d] + 0x249e) & 0xFFFF
	val = (state.reg4[R_8c] - 0x109c20c1) & 0xFFFFFFFF
	log.append("VMR[{:02X}] = {:02X}".format(r1, val))
	state.reg4[r1] = val
	
	t4 = (state.read2(10) + state.reg4[R_39]) ^ 0x283e08d4
	state.reg4[R_39] ^= t4

	state.next = t4 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3AB] = ASM_0x3AB

def ASM_0x198(state, log):
	r1 = state.read2(0)
	r2 = state.read2(6)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(12) + state.reg4[R_39]
	state.reg4[R_39] &= t1
	state.reg4[R_69] -= 0x6c605a16
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = (state.read2(2) - state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] ^= t2
	state.reg2[R_9d] ^= t2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xc720) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x3771) & 0xFFFF
	state.VM_ASGN_R_R(log, r1, r2)
	
	t3 = (state.read2(8) + state.reg4[R_39]) - 0xdf3ff5
	state.reg4[R_39] &= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+18)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x198] = ASM_0x198

def ASM_0x507(state, log):
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] &= 0x7bac1db
	
	state.reg4[R_39] ^= 0x2091eb36
	state.reg4[R_2c] ^= 0x2091eb36
	state.reg4[R_69] += 0x4394a7c1
	state.reg4[R_39] -= 0x4d7ea007
	state.reg4[R_2c] += state.reg4[R_39]
	
	t1 = state.read2(2) + state.reg4[R_39]
	state.reg4[R_39] &= t1
	state.reg4[R_69] &= 0x6761e3ae
	state.reg2[R_8a] -= t1 & 0xFFFF
	
	t2 = state.read2(0)
	state.reg4[R_39] -= t2 & 0xFFFF
	state.reg4[R_69] += 0x529e2b4e
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x77a0) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0xd018) & 0xFFFF

	log.append("VMR[{:02X}] = [ VMR[{:02X}] ]".format(r1, r2))
	log.append("VMR[{:02X}] = [ {:02X} ] ( {:02X} )".format(r1, state.reg4[r2], state.rMem4(state.reg4[r2])))
	state.reg4[r1] = state.rMem4( state.reg4[r2] )

	t3 = (state.read2(4) + state.reg4[R_39]) ^ 0x5081b0dd
	state.reg4[R_39] -= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x507] = ASM_0x507

def ASM_0x103(state, log):
	t1 = state.read2(6) + state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] ^= t1
	state.reg4[R_69] ^= 0x777bc0b
	state.reg2[R_9d] -= t1 & 0xFFFF
	
	t2 = state.read2(0)
	state.reg4[R_69] += 0x565273b
	state.reg2[R_8a] ^= (t2 + state.reg2[R_39]) - state.reg2[R_a7]
	state.reg4[R_39] ^= state.read4(2)
	
	r1 = (state.reg2[R_9d] +  0xabf) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x2e36) & 0xFFFF
	state.VM_AND_R_R(log, r1, r2, state.read2(8))

	state.reg4[R_39] ^= 0x4941fe11
	
	t3 = (state.read2(10) - state.reg4[R_39]) + 0xb1da235e
	state.reg4[R_39] += t3

	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x103] = ASM_0x103

def ASM_0x2ED(state, log):
	state.reg4[R_69] += 0x4a7d9914
	
	r1 = state.read2(2)
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read4(4) - state.reg4[R_69]
	state.reg4[R_39] += t1
	state.reg4[R_8c] -= t1
	
	t2 = state.read2(8) ^ state.reg4[R_2c]
	state.reg4[R_39] &= t2
	state.reg4[R_69] -= 0x4c8256d0
	state.reg2[R_9d] ^= t2 & 0xFFFF
	
	val = state.reg4[R_8c] ^ 0x2adef110
	r3 = state.reg2[R_9d] ^ 0x6ea8
	r4 = state.read2(10)

	log.append("VMR[{:02X}] = CMP VMR[{:02X}]({:02X}), {:02X}".format(r4, r3, state.reg4[r3], val))
	state.reg4[r4] = int( EFLAGS("cmp", state.reg4[r3], val) )
	
	state.reg4[R_a7] ^= 0x1e292c14
	state.reg4[R_2c] |= 0x5285bebc
	
	t3 = (state.read2(12) ^ state.reg4[R_39]) ^ 0x37125429
	state.reg4[R_39] ^= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2ED] = ASM_0x2ED

def ASM_0x270(state, log):
	t1 = state.reg4[ state.read2(14) ]
	t2 = state.reg4[ state.read2(16) ]
	t3 = state.reg4[ state.read2(20) ]
	t4 = state.reg4[ state.read2(6) ]
	t5 = state.reg4[ state.read2(12) ]
	t6 = state.reg4[ state.read2(24) ]
	state.reg4[ state.read2(10) ] = t6
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(10), state.read2(24), t6))
	state.reg4[ state.read2(22) ] = t5
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(22), state.read2(12), t5))
	state.reg4[ state.read2(4) ] = t4
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(4), state.read2(6), t4))
	state.reg4[ state.read2(2) ] = t3
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(2), state.read2(20), t3))
	state.reg4[ state.read2(0) ] = t2
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(0), state.read2(16), t2))
	state.reg4[ state.read2(18) ] = t1
	log.append("VMR[{:02X}] = VMR[{:02X}] ({:02X})".format(state.read2(18), state.read2(14), t1))
	
	t = (state.read2(8) ^ state.reg4[R_39]) + 0x1074e5f6

	state.next = t & 0xFFFF
	state.chEIP(+26)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x270] = ASM_0x270

def ASM_0xCF(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(8) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(8), uvar1))
	log.append(eflags)
	tp = state.read(10)
	op = JCC(tp)
	
	instr = state.read2(0)
	jmp = state.read4(4)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append(op + "  to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] - jmp)
	else:
		log.append(op + "  to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] + jmp)
	
	t = state.read2(11) ^ 0x6afb9ec0
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xCF] = ASM_0xCF


def ASM_0x2E8(state, log):
	t1 = state.read4(10) + state.reg4[R_39] - state.reg4[R_69]
	state.reg4[R_39] &= t1
	state.reg4[R_69] -= 0x1e55884d
	state.reg4[R_8c] ^= t1
	state.reg4[R_a7] += t1
	
	t = state.reg4[R_8c] ^ 0x3344fd8f
	state.push( t )
	log.append("#push {:02X}".format( t ))
	
	r = state.read2(4)
	state.reg4[r] -= 4
	log.append("VMR[{:02X}] -= 4   ({:02X})".format(r, state.reg4[r]))
	
	t2 = state.read2(0) + state.reg4[R_39]
	state.reg4[R_39] ^= t2
	
	state.next = t2 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2E8] = ASM_0x2E8


def ASM_0x3E6(state, log):
	t1 = state.read2(6) - state.reg4[R_2c]
	state.reg4[R_39] |= t1
	state.reg2[R_9d] += t1
	state.reg4[R_39] |= 0x3c2cbfb6
	
	t2 = state.read2(4) - state.reg4[R_39] - state.reg4[R_a7]
	state.reg4[R_39] &= t2
	state.reg4[R_69] -= 0x3b8e3b16
	state.reg2[R_8a] ^= t2
	
	r1 = (state.reg2[R_9d] + 0xe647) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x1bef) & 0xFFFF
	state.VM_ADD_R_R(log, r1, r2, state.read2(0))
	
	t3 = (state.read2(8) - state.reg4[R_39]) ^ 0x636306bf
	state.reg4[R_39] -= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3E6] = ASM_0x3E6

def ASM_0x36E(state, log):
	jmp = state.read4(4)
	state.next = state.read2(0)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append("JMP to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] - jmp)
	else:
		log.append("JMP to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] + jmp)
	log.append(";next = {:02X}".format(state.next))
	state.run = False
VMAsm[0x36E] = ASM_0x36E
VMAsm[0x3F7] = ASM_0x36E

def ASM_0x36F(state, log):
	t1 = (state.read4(2) - state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] |= t1
	state.reg4[R_69] += 0x3da64637
	state.reg4[R_8c] += t1
	state.reg4[R_a7] += t1
	
	t2 = state.read2(0) - state.reg4[R_39] + state.reg4[R_2c]
	state.reg4[R_39] -= t2
	state.reg2[R_9d] ^= t2 & 0xFFFF
	state.reg4[R_39] &= 0x6033cec3
	state.reg4[R_69] |= 0x777dc2af
	
	val = U32(state.reg4[R_8c] + 0xa538a861)
	r = state.reg2[R_9d] ^ 0x7b80
	efl = state.read2(10)
	state.VM_CMP_R_V(log, r, val, efl)
	
	state.reg4[R_69] += 0x6501b111
	
	t3 = (state.read2(6) ^ state.reg4[R_39]) + 0xcb6503e3
	state.reg4[R_39] &= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x36F] = ASM_0x36F


def ASM_0x174(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(8) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(8), uvar1))
	log.append(eflags)
	tp = state.read(10)
	op = JCC(tp)
	
	instr = state.read2(0)
	jmp = state.read4(4)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append(op + "  to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] - jmp)
	else:
		log.append(op + "  to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] + jmp)
	
	t = state.read2(11) ^ 0x4eb27c14
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x174] = ASM_0x174

def ASM_0x17E(state, log):
	state.reg4[ R_39 ] |= 0x2d13c801
	state.reg4[ R_69 ] &= 0x23353a2c
	
	t1 = (state.read2(2) ^ state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] &= t1
	state.reg4[R_69] |= 0x78e23a2
	state.reg2[R_9d] ^= t1 & 0xFFFF
	
	t2 = (state.read4(6) + state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] |= t2
	state.reg4[R_69] += 0x1d30da2b
	state.reg4[R_8c] ^= t2
	
	r1 = state.reg2[R_9d] 
	val = U32(state.reg4[R_8c] + 0x58541bd5)
	
	log.append("VMR[{:02X}] = {:02X}".format(r1, val))
	state.reg4[r1] = val
	
	t3 = (state.read2(0) ^ state.reg4[R_39]) + 0x858122a3
	state.reg4[R_39] -= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x17E] = ASM_0x17E

def ASM_0x1AC(state, log):
	t1 = state.read4(4) + state.reg4[R_69]
	state.reg4[ R_8c ] += t1
	state.reg4[ R_a7 ] ^= t1
	state.reg4[ R_2c ] &= 0x4def4cf2
	
	t2 = state.read2(2) ^ state.reg4[R_39]
	state.reg4[R_39] &= t2
	state.reg4[R_69] ^= 0x19f273f8
	state.reg2[R_9d] += t2 & 0xFFFF
	state.reg4[R_2c] -= 0x50c93f16
	state.reg4[R_69] -= 0x50c93f16
	
	r1 = state.reg2[R_9d] ^ 0xca79
	val = state.reg4[R_8c] ^ 0x7b52b80c
	state.VM_ADD_R_V(log, r1, val, state.read2(8))
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] &= 0x2a035df2
	
	t3 = (state.read2(0) + state.reg4[R_39]) + 0x4e06cc94

	state.next = t3 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1AC] = ASM_0x1AC

def ASM_0x450(state, log):
	r1 = state.read2(6)
	r2 = state.read2(8)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(0) - state.reg4[R_a7]
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] += 0x2beefa54
	state.reg2[ R_8a ] ^= t1 & 0xFFFF
	state.reg4[ R_a7 ] ^= state.reg4[R_69]
	state.reg4[ R_a7 ] += 0x3e4dd9ae
	
	t2 = state.read2(4) ^ state.reg4[R_39]
	state.reg4[R_39] &= t2
	state.reg4[R_69] -= 0x771167e
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x4807
	r2 = (state.reg2[R_8a] + 0x271a) & 0xFFFF
	
	log.append("VMR[{:02X}] -= VMR[{:02X}]   ({:02X} -= {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1]-state.reg4[r2])))
	state.reg4[r1] -=  state.reg4[r2]
	
	t3 = state.read2(2) + 0xfacbc045
	state.reg4[R_39] += t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x450] = ASM_0x450

def ASM_0x29B(state, log):
	t1 = state.read2(6)
	state.reg4[ R_69 ] -= 0x5aa149d4
	state.reg2[ R_8a ] -= (t1 + state.reg2[R_39] - state.reg2[R_a7])
	
	t2 = state.read2(10) - state.reg4[R_2c]
	state.reg4[ R_39 ] |= t2
	state.reg4[ R_69 ] -= 0x2ae96cc4
	state.reg2[ R_9d ] ^= t2 & 0xFFFF
	
	r1 = (state.reg2[ R_9d ] + 0xb89e) & 0xFFFF
	r2 = (state.reg2[ R_8a ] + 0xb70e) & 0xFFFF
	state.VM_ADD_R_R(log, r1, r2, state.read2(8))
	
	state.reg4[R_39] -= state.read4(2)
	
	t3 = state.read2(0) + state.reg4[R_39]
	state.reg4[R_39] &= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x29B] = ASM_0x29B

def ASM_0xAF(state, log):
	state.reg4[R_2c] |= state.reg4[R_39]
	
	t1 = U32(state.read4(4) + state.reg4[R_39] - state.reg4[R_69])
	state.reg4[R_39] |= t1
	state.reg4[R_69] ^= 0x5b9388e8
	state.reg4[R_8c] += t1
	
	t2 = U32(state.read2(0) - state.reg4[R_39] + state.reg4[R_2c])
	state.reg4[R_39] |= t2
	state.reg4[R_69] -= 0x6a2b1fd1
	state.reg2[R_9d] += t2 & 0xFFFF
	
	r1 = state.reg2[ R_9d ]
	val = U32(state.reg4[ R_8c ] + 0x574c2cc1)
	state.VM_ASGN_R_V(log, r1, val)
	
	t3 = U32(state.read2(8) - state.reg4[R_39]) ^ 0x2cd21358
	state.reg4[R_39] -= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xAF] = ASM_0xAF

def ASM_0x3FE(state, log):
	t1 = state.read2(6) + state.reg4[R_a7]
	state.reg4[R_39] &= t1
	state.reg4[R_69] -= 0xed80add
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = state.read2(4) ^ state.reg4[R_39]
	state.reg4[R_39] ^= t2
	state.reg4[R_69] |= 0x1531c53b
	state.reg2[R_9d] += t2 & 0xFFFF
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] |= 0x3cfe91e5

	r1 = (state.reg2[R_9d] + 0x80f5) & 0xFFFF
	r2 = state.reg2[R_8a]
	
	log.append("VMR[{:02X}] -= VMR[{:02X}]   ({:02X} -= {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1]-state.reg4[r2])))
	state.reg4[r1] -= state.reg4[r2]
	
	t3 = (state.read2(10) ^ state.reg4[R_39]) ^ 0xe646e3e
	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3FE] = ASM_0x3FE

def ASM_0x98(state, log):
	jmp = state.read4(4)
	state.next = state.read2(0)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append("JMP to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] - jmp)
	else:
		log.append("JMP to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] + jmp)
	log.append(";next = {:02X}".format(state.next))
	state.run = False
VMAsm[0x98] = ASM_0x98


def ASM_0x3B4(state, log):
	t1 = state.read4(8)
	state.reg4[R_2c] += 0x428e79f2
	state.reg4[R_39] += t1
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] &= 0x39e28479
	
	t2 = (state.read4(12) ^ state.reg4[R_39]) - state.reg4[R_69]
	state.reg4[R_39] += t2
	state.reg4[R_8c] -= t2
	state.reg4[R_a7] ^= t2
	
	t3 = (state.read2(6) + state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] += t3
	state.reg4[R_69] -= 0x2451251f
	state.reg2[R_9d] ^= t3
	
	t = state.read4(0)
	
	r1 = state.reg2[R_9d] ^ 0x5afb
	val = U32(state.reg4[R_8c] + 0x1b0ab308)
	state.VM_ADD_R_V(log, r1, val)
	
	state.reg4[R_39] &= t
	
	t4 = (state.read2(4) - state.reg4[R_39]) + 0xac3dec
	state.reg4[R_39] |= t4
	
	state.next = t4 & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3B4] = ASM_0x3B4

def ASM_0x239(state, log):
	state.reg4[R_2c] ^= 0x2c80ded4
	state.reg4[R_39] ^= state.read4(4)
	
	t1 = state.read4(8) + state.reg4[R_69]
	state.reg4[R_39] ^= t1
	state.reg4[R_69] &= 0x2cfd36bf
	state.reg4[R_8c] ^= t1
	state.reg4[R_a7] ^= t1
	state.reg4[R_39] &= 0x44d62a74
	
	val = state.reg4[R_8c] ^ 0x320514fa
	state.push(val)
	log.append("#push {:02X}".format(val))
	
	r1 = state.read2(2)
	state.reg4[r1] -= 4
	log.append("VMR[{:02X}] -= 4 ({:02X})".format(r1, state.reg4[r1]))
	
	t2 = state.read2(0) ^ state.reg4[R_39] ^ 0x2451d2c6
	state.reg4[R_39] -= t2
	
	state.next = t2 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x239] = ASM_0x239


def ASM_0x349(state, log):
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] &= 0x283aecad
	
	t1 = state.read2(4) - state.reg4[R_a7]
	state.reg4[R_39] &= t1
	state.reg2[R_8a] += t1 & 0xFFFF
	t2 = state.read2(2)
	state.reg4[R_69] |= 0x783f5c17
	state.reg2[R_9d] ^= t2 + state.reg2[R_39] + state.reg2[R_2c]
	state.reg4[R_39] &= state.read4(6)
	
	r1 = state.reg2[R_9d] ^ 0xf5d2
	r2 = (state.reg2[R_8a] + 0xa704) & 0xFFFF
	val = state.rMem4(state.reg4[r2])
	log.append("VMR[{:02X}] = [ VMR[{:02X}] ]   ([{:02X}]) ({:02X})".format(r1, r2, state.reg4[r2], val))
	state.reg4[r1] = val
	
	state.reg4[R_2c] += 0x42026c2a
	
	t3 = state.read2(0) ^ 0x35c88a95
	state.reg4[R_39] ^= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x349] = ASM_0x349

def ASM_0x9B(state, log):
	r1 = state.read2(10)
	r2 = state.read2(8)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(0)
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] &= 0x3a302081
	state.reg2[ R_9d ] += t1
	
	t2 = state.read4(4)
	state.reg4[R_8c] -= ((t2 - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_69] ^= 0xdd40461
	
	val = U32(state.reg4[R_8c] + 0x1d0bc1b3)
	r1 = (state.reg2[R_9d] + 0xeab) & 0xFFFF
	state.VM_ADD_R_V(log, r1, val, state.read2(12))
	
	state.reg4[ R_39 ] += 0x3b3f9bf5
	state.reg4[ R_69 ] += 0x3b3f9bf5
	
	t3 = state.read2(2) - state.reg4[R_39]
	state.reg4[R_39] |= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x9B] = ASM_0x9B

def ASM_0x6C(state, log):
	state.reg4[R_a7] += state.reg4[R_69]
	
	t1 = (state.read2(6) - state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= t1
	state.reg4[R_69] &= 0x676e5eb7
	state.reg2[R_9d] ^= t1
	
	t2 = (state.read2(2) ^ state.reg4[R_39]) - state.reg4[R_a7]
	state.reg4[R_39] += t2
	state.reg4[R_69] ^= 0x36c9f732
	state.reg2[R_8a] ^= t2
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] |= 0x4a57a1a4
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_a7] += 0x625479cb
	
	r2 = (state.reg2[R_8a] + 0xd06c) & 0xFFFF
	r1 = state.reg2[R_9d]
	
	val = state.rMem4(state.reg4[r1])
	
	r3 = state.read2(4)
	
	log.append("VMR[{:02X}] = CMP [VMR[{:02X}]], VMR[{:02X}]   ([{:02X}], {:02X})  ({:02X})".format(r3, r1, r2, state.reg4[r1], state.reg4[r2], val))

	state.reg4[r3] = int( EFLAGS("cmp", val, state.reg4[r2]) )
	
	t = state.read2(0) ^ 0x19fa620c
	state.reg4[ R_39 ] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x6C] = ASM_0x6C


def ASM_0x14(state, log):
	t1 = (state.read2(4) + state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] |= t1
	state.reg4[R_69] ^= 0x5256b98e
	state.reg2[R_9d] -= t1
	
	r = state.reg2[R_9d] ^ 0xFF48
	val = state.rMem4(state.reg4[r])
	log.append("#push [ VMR[{:02X}] ] ({:02X})".format(r, val))	
	state.push(val)
	
	t = state.read2(2)
	log.append("VMR[{:02X}] -= 4 ({:02X})".format(t, U32(state.reg4[t] - 4)))
	state.reg4[t] -= 4
	
	state.reg4[R_2c] |= 0x7fe8ab9e
	
	t = (state.read2(0) + state.reg4[R_39]) ^ 0x2e97d047
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x14] = ASM_0x14

def ASM_0x3D1(state, log):
	t1 = (state.read4(8) + state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] ^= t1
	state.reg4[R_69] ^= 0x1b223ddc
	state.reg4[R_8c] -= t1
	state.reg4[R_a7] -= t1
	
	t2 = (state.read2(0) + state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] ^= t2
	state.reg2[R_9d] ^= t2
	
	t = state.read2(2) + state.reg4[R_39] + 0xd76501a4
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3D1] = ASM_0x3D1

def ASM_0x7C(state, log):
	t1 = (state.read4(4) - state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_69] &= 0x15c6a6f6
	state.reg4[R_8c] += t1
	state.reg4[R_a7] -= t1
	
	t2 = (state.read2(0) + state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] &= t2
	state.reg4[R_69] += 0xf8c2ca2
	state.reg2[R_9d] += t2
	
	val = U32(state.reg4[R_8c] + 0x4dcbba68)
	r1 = state.reg2[R_9d] ^ 0xa750
	
	log.append("VMR[{:02X}] -= {:02X}   ({:02X} -= {:02X}) ({:02X})".format(r1, val, state.reg4[r1], val, U32(state.reg4[r1]-val)))
	state.reg4[r1] -= val
	
	r2 = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r2))
	
	state.reg4[R_39] += state.read4(12)
	
	t = state.read2(10) + state.reg4[R_39] + 0x8ac1cfe8
	state.next = t & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x7C] = ASM_0x7C


def ASM_0x28B(state, log):
	r1 = state.read2(6)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = state.read2(0) - state.reg4[R_2c]
	state.reg4[R_39] ^= t1
	state.reg2[R_9d] -= t1 & 0xFFFFF
	state.reg2[R_8a] -= (state.read2(8) - state.reg2[R_a7]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x15cf) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_ADD_R_R(log, r1, r2)
	
	t2 = state.read2(2) ^ state.reg4[R_39]
	state.reg4[R_39] ^= t2
	
	state.next = t2 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x28B] = ASM_0x28B


def ASM_0x190(state, log):
	t1 = (state.read4(0) + state.reg4[R_39]) ^ state.reg4[R_69]
	state.reg4[R_39] |= t1
	state.reg4[R_69] &= 0x4ccb9779
	state.reg4[R_8c] += t1
	state.reg4[R_a7] -= t1
	
	r1 = state.read2(8)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)
	
	
	val = state.reg4[R_8c] ^ 0x1d450bda
	log.append("#push {:02X}".format(val))	
	state.push(val)
	
	t = state.read2(10)
	log.append("VMR[{:02X}] -= 4 ({:02X})".format(t, U32(state.reg4[t] - 4)))
	state.reg4[t] -= 4
	
	t = state.read2(6) + state.reg4[R_39] + 0x366f0e40
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x190] = ASM_0x190


def ASM_0x2FC(state, log):
	t1 = (state.read2(2) + state.reg4[R_39]) - state.reg4[R_a7]
	state.reg4[R_39] -= t1
	state.reg4[R_69] -= 0x266c2141
	state.reg2[R_8a] -= t1 & 0xFFFF
	
	t2 = (state.read2(6) + state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] ^= t2
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x53dfceeb
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	state.VM_ASGN_R_R(log, r1, r2)
	
	state.reg4[R_2c] &= 0x3698286e

	t = (state.read2(8) - state.reg4[R_39]) ^ 0x448804b8

	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2FC] = ASM_0x2FC

def ASM_0x40(state, log):
	state.reg4[R_2c] |= 0x6ca2f8de
	t1 = state.read2(4)
	state.reg4[R_69] |= 0x6ca2f8de
	state.reg2[R_8a] -= t1 & 0xFFFF
	
	t2 = (state.read2(0) - state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] += t2
	state.reg2[R_9d] -= t2 & 0xFFFF

	r1 = (state.reg2[R_9d] + 0x9336) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x74c3) & 0xFFFF
	state.VM_ADD_RM_R(log, r1, r2, state.read2(6)) #[r1] += r2
	
	t3 = (state.read2(2) ^ state.reg4[R_39]) ^ 0x2b2481a1
	state.reg4[R_39] += t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x40] = ASM_0x40

def ASM_0x4B(state, log):
	t1 = state.read2(2) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] += t1
	state.reg4[R_69] ^= 0x3df6f533
	state.reg2[R_9d] -= t1 & 0xFFFF
	
	r = state.reg2[R_9d]
	addr = state.reg4[ r ]
	val = state.rMem4(addr)
	log.append("#push [VMR[{:02X}]] ([{:02X}]) ({:02X})".format(r, addr, val))
	state.push(val)
	
	state.reg4[R_39] |= state.read4(4)
	
	r = state.read2(0)
	state.reg4[ r ] -= 4
	log.append("VMR[{:02X}] -= 4   ({:02X})".format(r, state.reg4[ r ]))
		
	t3 = (state.read2(12) ^ state.reg4[R_39]) + 0xade8c5ed
	state.reg4[R_39] |= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4B] = ASM_0x4B


def ASM_0x471(state, log):
	t1 = (state.read2(0) + state.reg4[R_39]) ^ state.reg4[R_a7]
	state.reg4[R_39] -= t1
	state.reg4[R_69] &= 0xa0c3b9c
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = (state.read2(2) + state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] |= t2
	state.reg4[R_69] -= 0x252bd360
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	
	r1 = state.reg2[R_9d] ^ 0x9f57
	r2 = (state.reg2[R_8a] + 0xe263) & 0xFFFF
	log.append("VMR[{:02X}] -= {:02X} ({:02X} -= {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1] - state.reg4[r2])))
	state.reg4[r1] -= state.reg4[r2]
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] &= 0x1f80f5f5
	
	r = state.read2(6)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = U32(state.read2(4) - state.reg4[R_39] + 0x10c21f73)
	state.reg4[R_39] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x471] = ASM_0x471


def ASM_0x72(state, log):
	t1 = state.read2(6) + state.reg4[R_2c]
	state.reg4[R_39] -= t1
	state.reg4[R_69] -= 0x6702b672
	state.reg2[R_9d] ^= t1 & 0xFFFF
	
	t2 = (state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_a7]
	state.reg4[R_39] += t2
	state.reg4[R_69] |= 0x2e46d1fb
	state.reg2[R_8a] += t2 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0xbec6) & 0xFFFF
	log.append("VMR[{:02X}] ^= VMR[{:02X}] ({:02X} ^= {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], state.reg4[r1] ^ state.reg4[r2]))
	state.reg4[r1] ^= state.reg4[r2]
	
	r = state.read2(4)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = state.read2(2) + state.reg4[R_39] + 0x768bc705

	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x72] = ASM_0x72

def ASM_0x482(state, log):
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x2086c3bb
	
	t1 = (state.read4(0) ^ state.reg4[R_39]) - state.reg4[R_69]
	state.reg4[R_39] -= t1
	state.reg4[R_69] |= 0x13bb9640
	state.reg4[R_8c] += t1
	state.reg4[R_a7] -= t1
	
	t2 = (state.read2(6) - state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] &= t2
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	v2 = state.reg4[R_8c] ^ 0x4bb520e5
	r1 = state.reg2[R_9d]
	addr = state.reg4[r1]
	v1 = state.rMem4(addr)
	res = U32(v1 - v2)
	log.append("[VMR[{0:02X}]] -= {1:02X} ([{2:02X}] -= {1:02X}) ({3:02X} -= {1:02X}) ({4:02X})".format(r1, v2, addr, v1, res))
	state.wMem4(addr, res)
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = (state.read2(4) ^ state.reg4[R_39]) + 0x2dd1829e
	state.reg4[R_39] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x482] = ASM_0x482


def ASM_0x1B4(state, log):
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x2b6cc35b
	
	t1 = state.read2(6)
	state.reg4[R_39] -= t1
	state.reg4[R_69] += 0x2a124026
	state.reg2[R_9d] -= t1 & 0xFFFF
	
	t2 = (state.read4(2) ^ state.reg4[R_39])
	state.reg4[R_39] ^= t2
	state.reg4[R_69] &= 0x3e094b03
	state.reg4[R_8c] += t2
	state.reg4[R_a7] |= t2
	
	v = state.reg4[R_8c]
	r1 = state.reg2[R_9d]
	state.VM_ADD_RM_V(log, r1, v, state.read2(10)) # [r] += v

	
	t = (state.read2(8) - state.reg4[R_39]) + 0x7b3690e4

	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1B4] = ASM_0x1B4


def ASM_0x343(state, log):
	t1 = state.read2(6) - state.reg4[R_39] - state.reg4[R_2c]
	state.reg4[R_39] += t1
	state.reg4[R_69] |= 0x3b8b7b6c
	state.reg2[R_9d] ^= t1 & 0xFFFF
	state.reg2[R_8a] ^= (state.read2(10) + state.reg2[R_39]) & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	state.VM_ADD_R_R(log, r1, r2, state.read2(8))
	
	state.reg4[R_39] += 0x5dd482ea
	
	t = (state.read2(2) ^ state.reg4[R_39]) ^ 0x6fe4b32b
	state.reg4[R_39] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x343] = ASM_0x343


def ASM_0x21E(state, log):
	t1 = (state.read2(8) - state.reg4[R_39]) ^ state.reg4[R_a7]
	state.reg4[R_39] &= t1
	state.reg2[R_8a] ^= t1 & 0xFFFF
	
	t2 = (state.read2(10) ^ state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] += t2
	state.reg4[R_69] |= 0x3108f615
	state.reg2[R_9d] += t2 & 0xFFFF
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] -= 0x56dc7b6c
	
	state.reg4[R_2c] -= state.reg4[R_39]
	
	r1 = state.reg2[R_9d] ^ 0x4307
	r2 = (state.reg2[R_8a] + 0x20a2) & 0xFFFF
	addr = state.reg4[r2]
	val = state.rMem4(addr)
	res = state.reg4[r1] ^ val
	log.append("VMR[{0:02X}] ^= [VMR[{1:02X}]] ({2:02X} ^= [{3:02X}]) ({2:02X} ^= {4:02X}) ({5:02X})".format(r1, r2, state.reg4[r1], addr, val, res))
	state.reg4[r1] = res
	
	r = state.read2(6)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = (state.read2(0) - state.reg4[R_39]) + 0x7884e254
	state.reg4[R_39] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x21E] = ASM_0x21E


def ASM_0x29D(state, log):
	t1 = (state.read2(0) + state.reg4[R_39]) ^ state.reg4[R_a7]
	state.reg4[R_39] += t1
	state.reg2[R_8a] -= t1 & 0xFFFF
	state.reg4[R_39] |= 0x409930a1
	state.reg4[R_69] &= 0x7567b610
	
	t2 = (state.read2(4) + state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] |= t2
	state.reg4[R_69] += 0x3e467e7
	state.reg2[R_9d] += t2 & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x3645
	r2 = (state.reg2[R_8a] + 0xaee4) & 0xFFFF
	addr = state.reg4[r2]
	val = state.rMem4(addr)
	res = U32(state.reg4[r1] - val)
	log.append("VMR[{0:02X}] -= [VMR[{1:02X}]] ({2:02X} -= [{3:02X}]) ({2:02X} -= {4:02X}) ({5:02X})".format(r1, r2, state.reg4[r1], addr, val, res))
	state.reg4[r1] = res
	
	state.reg4[R_39] ^= 0x8de5046
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	state.reg4[R_39] ^= 0x1448e775
	state.reg4[R_69] += 0x28c09877
	
	t = (state.read2(6) - state.reg4[R_39]) + 0x9ab98f9e
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x29D] = ASM_0x29D


def ASM_0x3B9(state, log):
	t1 = (state.read2(0) - state.reg4[R_39])
	state.reg4[R_39] += t1
	state.reg4[R_69] += 0x663d6b21
	state.reg2[R_9d] += t1 & 0xFFFF
	state.reg4[R_2c] ^= 0x2bc56a61
	
	t2 = (state.read4(4) ^ state.reg4[R_39])
	state.reg4[R_39] += t2
	state.reg4[R_69] -= 0x2488c30a
	state.reg4[R_8c] ^= t2
	state.reg4[R_a7] &= t2
	
	v = state.reg4[R_8c]
	r = (state.reg2[R_9d] + 0xe589) & 0xFFFF
	state.VM_ADD_RM_V(log, r, v, state.read2(12)) #[r] += v
	
	t = (state.read2(8) + state.reg4[R_39])
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3B9] = ASM_0x3B9


def ASM_0x223(state, log):
	state.reg4[R_2c] |= 0x6d19b717
	
	r1 = state.read2(2)
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = (state.read2(6) + state.reg4[R_39])
	state.reg4[R_39] ^= t1
	state.reg4[R_69] -= 0x2f099730
	state.reg2[R_9d] ^= t1 & 0xFFFF
	
	t2 = (state.read(8) ^ state.reg4[R_39]) + state.reg4[R_69]
	state.reg4[R_39] ^= t2
	state.reg4[R_8c] -= t2
	state.reg4[R_a7] ^= t2
	
	r = state.reg2[R_9d]
	
	t = U32(state.reg4[R_8c] + 0x91a23270)
	state.VM_LSH_R_V(log, r, t)
	
	t = U32(state.read2(4) - state.reg4[R_39])
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+11)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x223] = ASM_0x223


def ASM_0xA5(state, log):
	state.reg4[R_39] += state.read4(0)
		
	t1 = (state.read4(12) ^ state.reg4[R_69])
	state.reg4[R_39] -= t1
	state.reg4[R_8c] -= t1
	state.reg4[R_a7] -= t1
	state.reg4[R_39] |= state.read4(6)
	state.reg4[R_39] -= 0x5ceb16a4
	
	t2 = (state.read2(4) + state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] += t2
	state.reg2[R_9d] += t2 & 0xFFFF
		
	r = (state.reg2[R_9d] + 0x1a91) & 0xFFFF
	val = state.reg4[R_8c] ^ 0x3f895941
	res = state.reg4[r] ^ val
	log.append("VMR[{0:02X}] ^= {1:02X} ({2:02X} ^= {1:02X}) ({3:02X})".format(r, val, state.reg4[r], res))
	state.reg4[r] = res
	
	t = U32(state.read2(10) + state.reg4[R_39])
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xA5] = ASM_0xA5


def ASM_0x14C(state, log):
	state.reg4[R_69] &= 0x7881cbe4
		
	t1 = (state.read2(2) ^ state.reg4[R_39]) + state.reg4[R_a7]
	state.reg4[R_39] &= t1
	state.reg4[R_69] -= 0x7ce37774
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = (state.read2(0) - state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] += t2
	state.reg4[R_69] -= 0x799efaa4
	state.reg2[R_9d] += t2 & 0xFFFF
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] ^= 0xe782f2c
	
	r1 = (state.reg2[R_9d] - 0xef8) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xac3) & 0xFFFF
	state.VM_ADD_R_R(log, r1, r2)
	
	state.reg4[R_2c] |= 0x7d7a375b
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] &= 0x4d1f5b1e
	
	t = state.read2(6) + state.reg4[R_39]
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x14C] = ASM_0x14C


def ASM_0x378(state, log):
	t1 = (state.read4(10) ^ state.reg4[R_39]) - state.reg4[R_69]
	state.reg4[R_39] += t1
	state.reg4[R_69] -= 0x9e7eb5
	state.reg4[R_8c] += t1
	state.reg4[R_a7] &= t1
	state.reg4[R_a7] ^= 0x323c2935
	
	t2 = (state.read2(4) + state.reg4[R_39])
	state.reg4[R_39] |= t2
	state.reg4[R_69] ^= 0x63ab0208
	state.reg2[R_9d] += t2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x7016) & 0xFFFF
	val = state.reg4[R_8c]
	res = U32(state.reg4[r1] - val)
	log.append("VMR[{0:02X}] -= {1:02X} ({2:02X} -= {1:02X}) ({3:02X})".format(r1, val, state.reg4[r1], res))
	state.reg4[r1] = res
	
	state.reg4[R_39] &= state.read4(0)
	state.reg4[R_69] -= 0x316c69b6
	
	r = state.read2(6)
	log.append("VMR[{:02X}] = eflags".format(r))

	t = (state.read2(8) ^ state.reg4[R_39]) + 0xd471b56a

	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x378] = ASM_0x378

def ASM_0xB5(state, log):
	state.reg4[R_a7] += state.reg4[R_69]
	
	r1 = state.read2(1)
	r2 = state.read2(9)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = (state.read(0) + state.reg4[R_39]) - state.reg4[R_69]
	state.reg4[R_39] &= t1
	state.reg4[R_69] ^= 0xb5fa31f
	state.reg4[R_8c] ^= t1
	state.reg4[R_a7] |= t1
	
	t2 = (state.read2(5) - state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] += t2
	state.reg4[R_69] ^= 0x21f42309
	state.reg2[R_9d] -= t2 & 0xFFFF
	
	r = state.reg2[R_9d] ^ 0x7a12
	
	t = U32(state.reg4[R_8c] + 0x5c429f39)
	if ( t & 0x1F ):
		res = U32(state.reg4[r] >> (t & 0x1F))
		log.append("VMR[{0:02X}] >>= {1:02X} ({2:02X} >>= {1:02X}) ({3:02X})".format(r, (t & 0x1F), state.reg4[r], res))
		state.reg4[r] = res
	
	r = state.read2(3)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = U32(state.read2(7) - state.reg4[R_39]) + 0x52c63463
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+11)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xB5] = ASM_0xB5


def ASM_0x00(state, log):
	t1 = (state.read2(14) ^ state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] |= t1
	state.reg4[R_69] -= 0x48671d0d
	state.reg2[R_9d] += t1 & 0xFFFF
	state.reg4[R_39] &= state.read4(8)
	
	t2 = (state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_a7]
	state.reg4[R_39] &= t2
	state.reg4[R_69] -= 0x223952a1
	state.reg2[R_8a] -= t2 & 0xFFFF
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] -= 0x4f28f55f
	
	r1 = (state.reg2[R_9d] + 0x4752) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x62d2) & 0xFFFF
	res = state.reg4[r1] | state.reg4[r2]
	log.append("VMR[{:02X}] |= VMR[{:02X}]   ({:02X} |= {:02X})  ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res))
	state.reg4[r1] = res

	t = U32(state.read2(6) ^ state.reg4[R_39]) ^ 0x508fe882
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x00] = ASM_0x00

def ASM_0x187(state, log):
	t1 = (state.read2(10)) + state.reg4[R_2c]
	state.reg4[R_39] += t1
	state.reg4[R_69] ^= 0x2689a005
	state.reg2[R_9d] += t1 & 0xFFFF
	
	state.reg4[R_39] |= state.read4(2)
	
	r = (state.reg2[R_9d] + 0xa788) & 0xFFFF
	state.VM_NEG_R(log, r, state.read2(8))
	
	state.reg4[R_69] -= 0x23d69759
	state.reg4[R_a7] &= state.reg4[R_69]

	t = U32(state.read2(0) ^ state.reg4[R_39]) ^ 0x4b6bf3c1
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x187] = ASM_0x187


def ASM_0x4EA(state, log):
	t1 = (state.read2(0) - state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] |= t1
	state.reg4[R_69] &= 0x63db057b
	state.reg2[R_9d] -= t1 & 0xFFFF
	state.reg4[R_39] |= 0x3b4ca3c4
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x3b4ca3c4
	
	t2 = state.read2(4)
	state.reg4[R_69] &= 0x635bc238
	state.reg2[R_8a] -= (t2 + state.reg2[R_a7]) & 0xFFFF
	state.reg4[R_39] += 0x16d75dce
	state.reg4[R_69] |= 0x4cd2c680
	
	r1 = (state.reg2[R_9d] + 0xba58) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_ADD_R_R(log, r1, r2, state.read2(2))

	t = U32(state.read2(6) ^ state.reg4[R_39]) + 0x93d8252d
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4EA] = ASM_0x4EA

def ASM_0x2A2(state, log):
	t1 = (state.read2(6)) ^ state.reg4[R_39]
	state.reg4[R_39] |= t1
	state.reg4[R_69] |= 0x11f3c590
	state.reg2[R_9d] -= t1 & 0xFFFF

	t2 = state.read4(2) - state.reg4[R_69]
	state.reg4[R_39] &= t2
	state.reg4[R_69] |= 0x3a40b342
	state.reg4[R_8c] ^= t2
	
	val = state.reg4[R_8c] ^ 0x26e3bcdc
	r = (state.reg2[R_9d] ^ 0x3090) & 0xFFFF
	ad = state.reg4[r]
	v = state.rMem4(ad)
	res = U32(v - val)
	log.append("[VMR[{0:02X}]] -= {1:02X}  ([{2:02X}] -= {1:02X})  ({3:02X} -= {1:02X}) ({4:02X})".format(r, val, ad, v, res))
	state.wMem4(ad, res)

	r = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r))

	t = U32(state.read2(8) ^ state.reg4[R_39]) ^ 0x27e5db34
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2A2] = ASM_0x2A2


def ASM_0x2B8(state, log):
	t1 = state.read2(1) ^ state.reg4[R_2c]
	state.reg4[R_39] |= t1
	state.reg2[R_9d] -= t1
	
	t2 = state.read(0) ^ state.reg4[R_39]
	state.reg4[R_39] |= t2
	state.reg4[R_69] += 0x76236942
	state.reg4[R_8c] -= t2
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] |= 0x264a60cf
	state.reg4[R_39] ^= 0x40ab39b3
	
	r = state.reg2[R_9d] ^ 0xb59f
	t = state.reg4[R_8c]
	
	if ( t & 0x1F ):
		res = U32(state.reg4[r] >> (t & 0x1F))
		log.append("VMR[{0:02X}] >>= {1:02X} ({2:02X} >>= {1:02X}) ({3:02X})".format(r, (t & 0x1F), state.reg4[r], res))
		state.reg4[r] = res
	
	t = U32(state.read2(5) - state.reg4[R_39]) ^ 0x36606826
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+7)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2B8] = ASM_0x2B8


def ASM_0x4B0(state, log):
	state.reg2[R_9d] ^= state.read2(6) ^ state.reg2[R_39]
	state.reg4[R_69] += 0x3704b01c
	t = state.reg4[R_69]
	
	r = (state.reg2[R_9d] + 0xfe14) & 0xFFFF
	v = state.reg4[r]
	res = U32(v + 1)
	
	log.append("VMR[{0:02X}] += 1 ({1:02X} += 1) ({2:02X})".format(r, v, res))
	
	state.reg4[r] = res
	
	state.reg4[R_a7] ^= t
	state.reg4[R_a7] += 0x42b439
	
	r = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r))

	t = U32(state.read2(2) - state.reg4[R_39])
	state.reg4[R_39] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4B0] = ASM_0x4B0


def ASM_0x3C6(state, log):
	state.reg4[R_2c] &= state.reg4[R_39]
	
	t = (state.read2(4) - state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg4[R_69] &= 0x56d5127
	state.reg2[R_9d] -= t & 0xFFFF
	state.reg4[R_39] ^= state.read4(0)
	
	r = (state.reg2[R_9d] ^ 0x5c) & 0xFFFF
	v = state.reg4[r]
	res = U32(v - 1)
	
	log.append("VMR[{0:02X}] -= 1 ({1:02X} -= 1) ({2:02X})".format(r, v, res))
	
	state.reg4[r] = res
	
	t = U32(state.read2(6) - state.reg4[R_39]) + 0xe18d856
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3C6] = ASM_0x3C6


def ASM_0x3A2(state, log):
	t = (state.read2(4) + state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= t
	state.reg4[R_69] ^= 0x6986e282
	state.reg2[R_9d] -= t & 0xFFFF
	
	t = (state.read4(6) ^ state.reg4[R_39]) + state.reg4[R_69]
	state.reg4[R_39] |= t
	state.reg4[R_69] -= 0x639bc368
	state.reg4[R_8c] += t
	
	r = state.reg2[R_9d]
	val = U32(state.reg4[R_8c] + 0xb6c5c633)
	res = U32(state.reg4[r] & val)
	log.append("VMR[{0:02X}] &= {3:02X} ({1:02X} &= {3:02X}) ({2:02X})".format(r, state.reg4[r], res, val))
	state.reg4[r] = res
	
	state.reg4[R_2c] -= 0x472a707a
	
	r = state.read2(12)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x242bf086
	
	t = U32(state.read2(0) - state.reg4[R_39]) ^ 0x3c535d21
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A2] = ASM_0x3A2


def ASM_0x219(state, log):
	state.reg4[R_69] ^= 0x71fcc201
	t = (state.read2(6) + state.reg4[R_39]) ^ state.reg4[R_a7]
	state.reg4[R_39] -= t
	state.reg4[R_69] -= 0xb173cfa
	state.reg2[R_8a] += t & 0xFFFF
	
	t = (state.read2(2) + state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] ^= t
	state.reg2[R_9d] ^= t & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x9439
	r2 = (state.reg2[R_8a] - 0x4ce) & 0xFFFF
	res = U32(state.reg4[r1] ^ state.reg4[r2])
	log.append("VMR[{0:02X}] ^= VMR[{1:02X}] ({2:02X} ^= {3:02X}) ({4:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res))
	state.reg4[r1] = res

	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x4c1480c1
	
	t = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x219] = ASM_0x219


def ASM_0x344(state, log):
	state.reg4[R_39] += 0x58be6304
	
	r1 = state.read2(10)
	r2 = state.read2(6)
	state.VM_XCHG_R_R(log, r1, r2)
	
	state.reg4[R_69] += 0x2d3cd5e0
	t = U32((state.read2(2) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= t
	state.reg4[R_69] |= 0x5cf7ce4e
	state.reg2[R_9d] ^= t & 0xFFFF
	state.reg2[R_8a] ^= state.read2(4) ^ state.reg2[R_39] ^ state.reg2[R_a7]
	
	r1 = (state.reg2[R_9d] + 0x46ae) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xed42) & 0xFFFF
	t = state.reg4[r1]
	v = state.reg4[r2] & 0x1f
	if v:
		res = U32(t << v)
		log.append("VMR[{0:02X}] <<= VMR[{1:02X}] ({2:02X} <<= {3:02X}) ({4:02X})".format(r1, r2, t, v, res))
		state.reg4[r1] = res
		
		r = state.read2(8)
		log.append("VMR[{:02X}] = eflags".format(r))
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x4c1480c1
	
	t = U32(state.read2(0) ^ state.reg4[R_39])
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x344] = ASM_0x344

def ASM_0x4E(state, log):
	state.reg4[R_69] -= 0x797cd8db
	state.reg4[R_39] -= 0x54636d42
	state.reg4[R_69] -= 0x4c9e0912
	
	t = (state.read2(4) - state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg4[R_69] &= 0xbfef463
	state.reg2[R_9d] ^= t & 0xFFFF
	state.reg4[R_39] ^= 0x47b7c9f1
	
	t = (state.read2(0) + state.reg4[R_39]) + state.reg4[R_a7]
	state.reg4[R_39] ^= t
	state.reg4[R_69] -= 0x87ba5a6
	state.reg2[R_8a] += t & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x5d2d
	r2 = (state.reg2[R_8a] + 0xdf7a) & 0xFFFF
	adr = state.reg4[r2]
	val = state.rMem4(adr)
	res = U32(state.reg4[r1] - val)
	log.append("VMR[{0:02X}] -= [VMR[{2:02X}]] ({1:02X} -= [{3:02X}]) ({1:02X} -= {4:02X}) ({5:02X})".format(r1, state.reg4[r1], r2, adr, val, res))
	state.reg4[r1] = res

	r = state.read2(2)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = U32(state.read2(6) ^ state.reg4[R_39] ^ 0x64c8fd8b)
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4E] = ASM_0x4E


def ASM_0x3D2(state, log):
	r1 = state.read2(10)
	r2 = state.read2(14)
	state.VM_XCHG_R_R(log, r1, r2)

	t = state.read2(8)
	state.reg4[R_69] &= 0x400e4ab2
	state.reg2[R_8a] -= (t + state.reg2[R_39]) & 0xFFFF
	
	t = (state.read2(6) )
	state.reg4[R_69] += 0xc38d675
	state.reg2[R_9d] ^= (t + state.reg2[R_39] - state.reg2[R_2c]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x5db8) & 0xFFFF
	r2 = state.reg2[R_8a]
	res = U32(state.reg4[r1] - state.reg4[r2])
	r = state.read2(0)
	log.append("VMR[{5:02X}] =  CMP  VMR[{0:02X}], VMR[{1:02X}] ({2:02X}, {3:02X}) ({4:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res, r))
	
	t = U32(state.read2(4) + state.reg4[R_39] + 0x5710755f)
	
	state.next = t & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3D2] = ASM_0x3D2


def ASM_0x336(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(8) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(8), uvar1))
	log.append(eflags)
	tp = state.read(10)
	op = JCC(tp)
	
	instr = state.read2(0)
	jmp = state.read4(4)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append(op + "  to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] - jmp)
	else:
		log.append(op + "  to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] + jmp)
	
	t = state.read2(11) ^ state.reg4[R_39]
	state.reg4[R_39] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x336] = ASM_0x336


def ASM_0x34D(state, log):
	state.reg4[R_a7] |= 0x83586b5
	
	t = U32( state.read2(2) - state.reg4[R_39] - state.reg4[R_2c] )
	state.reg4[R_39] += t
	state.reg4[R_69] ^= 0x3b27a017
	state.reg2[R_9d] += t & 0xFFFF
	state.reg4[R_a7] -= state.reg4[R_69]
	
	r = (state.reg2[R_9d] + 0x4b5b) & 0xFFFF
	v = state.reg4[r]
	res = U32(v + 1)
	log.append("VMR[{0:02X}] += 1 ({1:02X} += 1) ({2:02X})".format(r, v, res))
	state.reg4[r] = res
	
	state.reg4[R_a7] |= 0x6a3cbd74
	
	t = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+4)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x34D] = ASM_0x34D


def ASM_0x480(state, log):
	state.reg4[R_a7] &= state.reg4[R_69]
	
	t = U32( state.read2(0) + state.reg4[R_39] )
	state.reg4[R_39] |= t
	state.reg2[R_9d] ^= t & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x9473) & 0xFFFF
	v = state.reg4[r]
	res = U32(~v)
	log.append("VMR[{0:02X}] ~= VMR[{0:02X}] ({1:02X}) ({2:02X})".format(r, v, res))
	state.reg4[r] = res
	
	state.reg4[R_69] |= 0x35439d1d
	
	t = U32(state.read2(2) ^ 0x4748020a)
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+4)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x480] = ASM_0x480

def ASM_0x290(state, log):
	jmp = state.read4(4)
	state.next = state.read2(0)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append("JMP to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] - jmp)
	else:
		log.append("JMP to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] + jmp)
	log.append(";next = {:02X}".format(state.next))
	state.run = False
VMAsm[0x290] = ASM_0x290


def ASM_0x147(state, log):
	t = U32((state.read(8) - state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_69] &= 0x21ae96c3
	state.reg4[R_8c] -= t
	state.reg4[R_a7] &= t
	
	t = U32((state.read2(11) + state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] &= t
	state.reg4[R_69] |= 0x6e289258
	state.reg2[R_9d] ^= t & 0xFFFF
	state.reg4[R_69] ^= 0x28f874c0
	
	
	
	r = state.reg2[R_9d]
	t = state.reg4[r]
	v = state.reg4[R_8c] & 0x1f
	state.VM_LSH_R_V(log, r, v, state.read2(0))
	
	t = U32(state.read2(6) + 0x648b77d2)
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x147] = ASM_0x147


def ASM_0x2C7(state, log):
	r1 = state.read2(10)
	r2 = state.read2(8)
	state.VM_XCHG_R_R(log, r1, r2)

	t = U32(state.read4(4) + state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] ^= t
	state.reg4[R_69] &= 0x7608d9de
	state.reg4[R_8c] ^= t
	state.reg4[R_a7] &= t
	
	t = (state.read2(2) )
	state.reg4[R_39] ^= t
	state.reg4[R_69] ^= 0x202d9c7f
	state.reg2[R_9d] ^= t & 0xFFFF
		
	r = (state.reg2[R_9d] + 0x31ad) & 0xFFFF
	v = state.reg4[R_8c] ^ 0x5d42cbd0
	res = U32(state.reg4[r] ^ v)
	log.append("VMR[{0:02X}] ^= {1:02X} ({2:02X} ^= {1:02X}) ({3:02X})".format(r, v, state.reg4[r], res))
	state.reg4[r] = res
	
	t = U32(state.read2(0) + 0x986cb6ff)
	state.reg4[R_39] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C7] = ASM_0x2C7


def ASM_0x2BC(state, log):
	t = state.read2(6) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] += t
	state.reg4[R_69] += 0x417d56ec
	state.reg2[R_9d] += t & 0xFFFF
	state.reg4[R_69] += 0x24a5b513
	
	t = U32((state.read2(0) ^ state.reg4[R_39] ) + state.reg4[R_69])
	state.reg4[R_39] -= t
	state.reg4[R_69] += 0x2df61311
	state.reg4[R_8c] ^= t
	state.reg4[R_a7] += t
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_a7] &= 0x64f0438e
	
	t = U32(state.read2(4) ^ state.reg4[R_39])
	state.reg4[R_39] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2BC] = ASM_0x2BC

def ASM_0x169(state, log):
	r1 = state.read2(0)
	r2 = state.read2(6)
	state.VM_XCHG_R_R(log, r1, r2)

	t = state.read2(10)
	state.reg4[R_69] &= 0x563cd57f
	state.reg2[R_8a] += (t + state.reg2[R_39] - state.reg2[R_a7]) & 0xFFFF
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_a7] |= 0x4d63a121
	
	t = U32(state.read2(4) - state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg4[R_69] -= 0x65c85e7f
	state.reg2[R_9d] ^= t & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x4614
	r2 = state.reg2[R_8a]
	res = U32(state.reg4[r1] & state.reg4[r2])
	r = state.read2(2)
	log.append("VMR[{5:02X}] =  TEST  VMR[{0:02X}] & VMR[{1:02X}] ({2:02X} & {3:02X}) ({4:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res, r))
	
	t = U32(state.read2(8) - state.reg4[R_39])
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x169] = ASM_0x169


def ASM_0x3A7(state, log):
	t = U32(state.read2(0) + state.reg4[R_39] - state.reg4[R_a7])
	state.reg4[R_39] ^= t
	state.reg4[R_69] += 0x3e92dee4
	state.reg2[R_8a] -= t & 0xFFFF
	
	t = U32(state.read2(2) ^ state.reg4[R_39]) + state.reg4[R_2c]
	state.reg4[R_39] ^= t
	state.reg4[R_69] ^= 0x2ab2a8dc
	state.reg2[R_9d] ^= t & 0xFFFF
	state.reg4[R_2c] |= 0x21a17deb
	
	r1 = state.reg2[R_9d] ^ 0xf1a
	r2 = (state.reg2[R_8a] - 0xcad) & 0xFFFF
	adr = state.reg4[r2]
	b = state.rMem1(adr)
	log.append("VMR[{0:02X}] = b, [VMR[{1:02X}]]  (VMR[{0:02X}] = [{2:02X}]) ({3:02X})".format(r1, r2, adr, b))
	state.reg4[r1] = b
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x3d6259c
	
	t = U32(state.read2(6) - state.reg4[R_39]) ^ 0x3effa086
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A7] = ASM_0x3A7

def ASM_0x502(state, log):
	t = U32(state.read2(10) ^ state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg2[R_9d] ^= t & 0xFFFF
	state.reg4[R_69] -= 0x1d67fb41
	
	t = U32(state.read2(8) ^ state.reg4[R_39])
	state.reg4[R_39] ^= t
	state.reg4[R_69] &= 0x71896510
	state.reg2[R_8a] ^= t & 0xFFFF
	state.reg4[R_2c] += state.reg4[R_39]
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0x56d6) & 0xFFFF
	adr = state.reg4[r1]
	b = state.reg1[r2]
	log.append("b, [VMR[{0:02X}]] = b, VMR[{1:02X}]  ([{2:02X}] = {3:02X})".format(r1, r2, adr, b))
	state.wMem1(adr, b)
	
	t = U32(state.read2(4) + state.reg4[R_39] + 0x7b3454e7)
	state.reg4[R_39] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x502] = ASM_0x502


def ASM_0x500(state, log):
	t = U32(state.read4(4) + state.reg4[R_39] - state.reg4[R_69])
	state.reg4[R_39] ^= t
	state.reg4[R_8c] += t
	state.reg4[R_a7] |= t
	
	t = U32(state.read2(0) - state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg2[R_9d] -= t & 0xFFFF
	state.reg4[R_2c] ^= 0x2825ac9e
	
	r = state.reg2[R_9d]
	val = state.reg4[R_8c]
	efl = state.read2(8)
	state.VM_AND_R_V(log, r, val, efl)
	
	t = U32(state.read2(2) + 0x1c87f5f1)
	state.reg4[R_39] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x500] = ASM_0x500

def ASM_0x141(state, log):
	r1 = state.read2(6)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)

	t = U32(state.read2(2) + state.reg4[R_39])
	state.reg4[R_39] |= t
	state.reg4[R_69] |= 0x26909ad3
	state.reg2[R_8a] += t & 0xFFFF
	
	t = state.read2(0) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= t
	state.reg4[R_69] |= 0x28c9ebd
	state.reg2[R_9d] -= t & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x8481
	adr = state.reg4[r1]
	r2 = state.reg2[R_8a] ^ 0xeba8
	b = state.reg1[r2]
	log.append("b, [VMR[{0:02X}]] = VMR[{1:02X}]  ([{2:02X}] = {3:02X})".format(r1, r2, adr, b))
	state.wMem1(adr, b)
	
	t = U32((state.read2(8) ^ state.reg4[R_39]) + 0xcb5d945d)
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x141] = ASM_0x141


def ASM_0x1D3(state, log):
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] += 0x7ce9ac21
	
	t = U32(state.read4(4) + state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] += t
	state.reg4[R_69] |= 0x68cf28fe
	state.reg4[R_8c] -= t
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] |= 0x6d3e1f92
	
	t = U32(state.read2(0) + state.reg4[R_2c])
	state.reg4[R_39] |= t
	state.reg4[R_69] -= 0x558019a0
	state.reg2[R_9d] += t & 0xFFFF
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] &= 0x265e0a76
	
	r = state.reg2[R_9d]
	val = state.reg4[R_8c]
	v = state.reg4[r]
	res = v & val
	log.append("VMR[{0:02X}] &= {1:02X}  ({2:02X} &= {1:02X}) ({3:02X})".format(r, val, v, res))
	state.reg4[r] = res
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t = U32((state.read2(2) + state.reg4[R_39]) ^ 0x1c3d87d8)
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1D3] = ASM_0x1D3


def ASM_0x108(state, log):
	t = U32(state.read4(12) - state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] ^= t
	state.reg4[R_8c] += t
	state.reg4[R_a7] &= t
	state.reg4[R_2c] |= 0x726c23d6
	state.reg4[R_39] += state.read4(4)
	
	t = U32(state.read2(0) ^ state.reg4[R_2c])
	state.reg4[R_39] ^= t
	state.reg4[R_69] |= 0x4ed115d9
	state.reg2[R_9d] ^= t & 0xFFFF
	
	r = (state.reg2[R_9d] + 0xd7d1) & 0xFFFF
	val = U32(state.reg4[R_8c] + 0xd058da9c)
	v = state.reg4[r]
	res = U32(v - val)
	r4 = state.read2(10)
	log.append("VMR[{0:02X}] = CMP VMR[{1:02X}], {2:02X}   ({3:02X}, {2:02X})  ({4:02X})".format(r4, r, val, v, res))
	
	state.reg4[r4] = int( EFLAGS("cmp", v, val) )
	
	t = U32(state.read2(8) ^ 0x7aed0b45)
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x108] = ASM_0x108


def ASM_0x429(state, log):
	t = U32((state.read2(0) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] += t
	state.reg4[R_69] += 0x648d2ac3
	state.reg2[R_9d] -= t & 0xFFFF
	
	r = state.reg2[R_9d]
	val = state.reg4[r]
	ibase = state.reg4[R_ImgBase]
	res = U32(val + ibase)
	log.append("VMR[{0:02X}] += IMGBASE {1:02X} ({2:02X} += {1:02X}) ({3:02X})".format(r, ibase, val, res))
	state.reg4[r] = res
	
	t = U32(state.read2(2) + state.reg4[R_39]) ^ 0x4433a942
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+4)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x429] = ASM_0x429


def ASM_0x276(state, log):
	state.reg4[R_69] -= 0x3aed73b4
	
	r = state.read2(8)
	p = state.reg4[r]
	state.push(p)
	log.append("#push VMR[{:02X}] ({:02X})".format(r, p))
	
	r = state.read2(6)
	v = state.reg4[r]
	res = U32(v - 4)
	log.append("VMR[{:02X}] -= 4 (={:02X})".format(r, res))
	state.reg4[r] = res
	
	state.reg4[R_39] ^= 0x199a3778
	
	t = U32(state.read2(0) + 0xf55a24c5)
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x276] = ASM_0x276


def ASM_0x4F2(state, log):
	t = state.read2(0) ^ state.reg4[R_39]
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+2)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F2] = ASM_0x4F2

def ASM_0x493(state, log):
	of = state.read2(4)
	r = state.read2(6)
	val = state.reg4[r]
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = {:02X} (VMR[{:02X}])".format(of, val, r))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x493] = ASM_0x493
VMAsm[0x173] = ASM_0x493


def ASM_0x203(state, log):
	t = U32(state.read(0) - state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] |= t
	state.reg4[R_69] -= 0x254a0888
	state.reg4[R_8c] -= t
	
	t = U32(state.read2(1) + state.reg4[R_39]) ^ state.reg4[R_2c]
	state.reg4[R_39] |= t
	state.reg4[R_69] += 0x3d648d47
	state.reg2[R_9d] ^= t & 0xFFFF
	
	v = U32(state.reg4[R_8c] + 0x101072b6) & 0x1F
	r = (state.reg2[R_9d] + 0xba3d) & 0xFFFF
	state.VM_LSH_R_V(log, r, v)
	
	state.reg4[R_69] += 0x7b28a6a0
	
	t = state.read2(5) ^ state.reg4[R_39]
	state.reg4[R_39] -= t
	state.next = t & 0xFFFF
	state.chEIP(+7)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x203] = ASM_0x203


def ASM_0x235(state, log):
	t = U32((state.read2(2) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] |= t
	state.reg4[R_69] &= 0x45ea5988
	state.reg2[R_8a] -= t & 0xFFFF
	
	t = U32(state.read2(6))
	state.reg4[R_39] &= t
	state.reg4[R_69] |= 0x1192e15
	state.reg2[R_9d] -= t & 0xFFFF
	state.reg4[R_39] ^= 0x713afe20
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a] ^ 0xd483
	state.VM_ADD_RM_R(log, r1, r2, state.read2(0)) # [r1] += r2
	
	t = U32((state.read2(4) ^ state.reg4[R_39]) + 0xbd7fe496)
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x235] = ASM_0x235


def ASM_0x282(state, log):
	r1 = state.read2(3)
	r2 = state.read2(7)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t1 = U32((state.read(2) - state.reg4[R_39])) ^ state.reg4[R_69]
	state.reg4[R_39] += t1
	state.reg4[R_8c] ^= t1	
	state.reg4[R_a7] -= t1
	
	t2 = state.read2(5)
	state.reg4[R_69] += 0x213394f9
	state.reg2[R_9d] += ((t2 + state.reg2[R_39]) ^ state.reg2[R_2c]) & 0xFFFF
	
	r = (state.reg2[R_9d] + 0xddeb) & 0xFFFF
	t = U32(state.reg4[R_8c] ^ 0x243fbfef) & 0x1F
	if ( t ):
		res = U32(state.reg4[r] >> t)
		log.append("VMR[{0:02X}] >>= {1:02X} ({2:02X} >>= {1:02X}) ({3:02X})".format(r, t, state.reg4[r], res))
		state.reg4[r] = res
	
	r = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] ^= 0x1e6d6cc6
	
	t = U32(state.read2(9) + 0xa4ff9650)
	
	state.next = t & 0xFFFF
	state.chEIP(+11)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x282] = ASM_0x282



def ASM_0x43A(state, log):
	t = state.read(0)
	of = state.read(1)
	v1 = state.read4(7)
	v2 = state.read4(3)
	
	ImgBase = state.reg4[R_ImgBase]
	
	rm1 = state.rMem4( of + v1 + ImgBase )
	rm2 = v2 + ImgBase
	
	log.append(";CMP {} ({:02X}[{:02X}]){:02X} {:02X}".format(t, v1, of, rm1, rm2))
	if (t == 1 or t == 2) and (rm1 != rm2):
		a = of + v1 + ImgBase
		log.append(";rebase {:02X})".format(a))
		val = state.rMem4(a)
		state.wMem4(a, val - state.reg4[R_OldBase] + ImgBase)
		
		if t == 2:
			a = state.read(2) + v1 + ImgBase
			log.append(";rebase {:02X})".format(a))
			val = state.rMem4(a)
			state.wMem4(a, val - state.reg4[R_OldBase] + ImgBase)
	   
	
	val = v1 + state.reg4[R_ImgBase]
	adr = state.read2(11)
	state.wMem4(state.esp + adr, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(adr, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x43A] = ASM_0x43A
VMAsm[0x241] = ASM_0x43A


def ASM_0x3D(state, log):
	t = U32(state.read2(0) + state.reg4[R_2c])
	state.reg4[R_39] += t
	state.reg4[R_69] |= 0x5cbd277a
	state.reg2[R_9d] += t & 0xFFFF
	
	r = state.reg2[R_9d]
	a = state.reg4[r]
	v = state.rMem4(a)
	log.append("[VMR[{0:02X}]] -= 1 ([{1:02X}] -= 1) ({2:02X} -= 1) ({3:02X})".format(r, a, v, U32(v - 1)))
	state.wMem4(a, U32(v-1))
	
	state.reg4[R_39] |= state.read4(2)
	
	t = U32(state.read2(6) + state.reg4[R_39]) ^ 0x6c6dc0a4
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3D] = ASM_0x3D


def ASM_0x2D7(state, log):
	state.reg4[ R_69 ] |= 0x4796398c
	
	r1 = state.read2(2)
	r2 = state.read2(6)
	
	if (state.reg4[ R_69 ] & 1):
		state.reg4[ R_69 ] ^= 0x38c16a34

	state.VM_POP_R(log, r1)

	state.VM_ADD_R_V(log, r2, 4)
	
	state.reg4[ R_39 ] ^= 0x7a2e71d9
	state.reg4[ R_69 ] ^= 0x7a2e71d9
	
	t = state.read2(0) ^ state.reg4[ R_39 ]
	state.reg4[ R_39 ] ^= t
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2D7] = ASM_0x2D7


def ASM_0x132(state, log):
	state.reg4[R_2c] ^= state.reg4[ R_39 ]
	state.reg2[R_9d] += (state.read2(3) - state.reg2[ R_39 ] + state.reg2[ R_2c ]) & 0xFFFF
	
	t = U32(state.read(2) - state.reg4[ R_39 ]) ^ state.reg4[ R_69 ]
	state.reg4[R_39] &= t
	state.reg4[R_69] |= 0x5f2d4a0c
	state.reg4[R_8c] ^= t
	state.reg4[R_a7] -= t
	
	r = state.reg2[R_9d]
	b = (state.reg1[R_8c] + 0x1e) & 0xFF
	v = state.reg1[r]
	res = (v + b) & 0xFF
	log.append("b, VMR[{0:02X}] += {1:02X} ({2:02X} += {1:02X}) ({3:02X})".format(r, b, v, res))
	state.reg1[r] = res

	t = U32(state.read2(0) + state.reg4[ R_39 ]) ^ 0xd3d1b0f
	state.reg4[ R_39 ] -= t
	state.next = t & 0xFFFF
	state.chEIP(+5)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x132] = ASM_0x132


def ASM_0x437(state, log):
	t = state.read2(2) ^ state.reg4[R_2c]
	state.reg4[R_39] -= t
	state.reg2[R_9d] -= t & 0xFFFF
	state.reg4[R_39] ^= 0x57d37039
	state.reg4[R_a7] ^= 0x57d37039
	
	t = state.read2(4) ^ state.reg4[R_a7]
	state.reg4[R_39] ^= t
	state.reg4[R_69] ^= 0x7d06a801
	state.reg2[R_8a] += t & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x63d1
	r2 = state.reg2[R_8a] ^ 0xea82
	v1 = state.reg1[r1]
	v2 = state.reg1[r2]
	res = v1 ^ v2
	log.append("b, VMR[{0:02X}] ^= VMR[{1:02X}] ({2:02X} ^= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
	state.reg1[r1] = res
	
	r = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r))

	t = state.read2(6)
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x437] = ASM_0x437


def ASM_0x1ED(state, log):
	state.reg4[R_69] -= 0x49a3d731
	
	r1 = state.read2(0)
	r2 = state.read2(2)
	state.VM_XCHG_R_R(log, r1, r2)
	
	t = state.read2(6) ^ state.reg4[R_2c]
	state.reg4[R_39] += t
	state.reg4[R_69] ^= 0x5c96f2b0
	state.reg2[R_9d] -= t & 0xFFFF
	
	t = U32(state.read2(12) - state.reg4[R_39])
	state.reg4[R_39] += t
	state.reg4[R_69] += 0x52d1bd85
	state.reg2[R_8a] += t & 0xFFFF
	state.reg4[R_69] += 0x1c822460
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] &= 0x55553f2d
	
	r1 = (state.reg2[R_9d] + 0x736f) & 0xFFFF
	r2 = state.reg2[R_8a] ^ 0xb6e8
	a = state.reg4[r2]
	v = state.rMem1(a)
	log.append("b, VMR[{0:02X}] = [VMR[{1:02X}]] ([{2:02X}]) ({3:02X})".format(r1, r2, a, v))
	state.reg1[r1] = v
	
	state.reg4[R_39] ^= state.read4(8)
	
	t = U32(state.read2(4) + state.reg4[R_39] + 0x8145d49b)
	state.reg4[R_39] += t
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1ED] = ASM_0x1ED


def ASM_0x372(state, log):
	ImgBase = state.reg4[R_ImgBase]
	
	of = state.read2(4)
	ad1 = state.read4(6) + ImgBase
	ad2 = state.read4(0) + ImgBase
	
	adr = state.esp + of
	state.wMem4(adr, ad1)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, ad1))
	
	state.wMem4(adr + 4, ad2)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, ad2))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x372] = ASM_0x372


def ASM_0x3D9(state, log):
	ImgBase = state.reg4[R_ImgBase]
	
	of = state.read2(4)
	ad1 = state.read4(6) + ImgBase
	ad2 = state.read4(0) + ImgBase
	
	adr = state.esp + of
	state.wMem4(adr, ad1)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, ad1))
	
	state.wMem4(adr + 4, ad2)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, ad2))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x3D9] = ASM_0x3D9


def ASM_0x38E(state, log):
	ImgBase = state.reg4[R_ImgBase]
	
	of = state.read2(4)
	ad1 = state.read4(0) + ImgBase
	
	adr = state.esp + of
	state.wMem4(adr, ad1)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, ad1))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x38E] = ASM_0x38E

def ASM_0x1CD(state, log):
	uVar4 = U32((state.read4(6)) + state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] |= uVar4
	state.reg4[R_69] += 0xae04c61
	state.reg4[R_8c] ^= uVar4
	state.reg4[R_a7] -= uVar4
	uVar1 = (state.read2(4))
	state.reg4[R_69] += 0x580ac4ef
	state.reg2[R_9d] += (uVar1 ^ state.reg2[R_39]) & 0xFFFF
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] += 0x39d1161b
	state.reg4[R_2c] ^= state.reg4[R_39]
	
	val = state.reg4[R_8c] ^ 0x134c1b9f
	r = (state.reg2[R_9d] + 0x1de2) & 0xFFFF
	adr = state.reg4[r]
	cv = state.rMem4(adr)
	r2 = state.read2(0)
	
	log.append("VMR[{:02X}] = CMP [VMR[{:02X}]]([{:02X}] -> {:02X}), {:02X}".format(r2, r, adr, cv, val))
	state.reg4[r2] = int( EFLAGS("cmp", cv, val) )

	if (state.reg4[R_69] & 1):
		state.reg4[R_69] += -0x3e22a7b2
	
	t = U32((state.read2(2)) + 0x3b4c4ff9)
	state.reg4[R_39] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1CD] = ASM_0x1CD

def ASM_0x383(state, log):
	state.reg4[R_2c] |= state.reg4[R_39]
	state.reg4[R_2c] += -0x45b3c57b
	uVar3 = U32((state.read4(4) + state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] += -0x45b3c57b
	state.reg4[R_8c] -= uVar3
	uVar1 = state.read2(0)
	state.reg4[R_69] |= 0x62e12dc0
	state.reg2[R_9d] += ((uVar1 ^ state.reg2[R_39]) + state.reg2[R_2c]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] ^ 0x6d63) & 0xFFFF
	adr = state.reg4[r1]
	val = state.reg4[R_8c] ^ 0x51c32603
	cv = state.rMem4(adr)
	res = cv & val
	log.append("[VMR[{0:02X}]] &= {1:02X} ([{2:02X}] &= {1:02X}) ({3:02X} &= {1:02X}) {4:02X}".format(r1, val, adr, cv, res))
	state.wMem4(adr, res)
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
		 
	t = ((state.read2(2)) ^ 0x2abfa4) & 0xFFFF
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x383] = ASM_0x383

def ASM_0xA8(state, log):
	r1 = state.read2(0)
	r2 = state.read2(4)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar5 = (state.read4(8))
	state.reg4[R_39] += uVar5
	state.reg4[R_69] += 0x410ae1e1
	state.reg4[R_8c] += uVar5
	state.reg4[R_a7] &= uVar5
	
	uVar1 = (state.read2(6))
	state.reg4[R_69] |= 0xfdfa20f
	state.reg2[R_9d] -= (uVar1 ^ state.reg2[R_39])
	
	val = state.reg4[R_8c] + 0x26f27f36
	r = (state.reg2[R_9d] + 0xcf84) & 0xFFFF
	adr = state.reg4[r]
	cv = state.rMem4(adr)
	r2 = state.read2(12)
	
	log.append("VMR[{:02X}] = CMP [VMR[{:02X}]]([{:02X}] -> {:02X}), {:02X}".format(r2, r, adr, cv, val))
	state.reg4[r2] = int( EFLAGS("cmp", cv, val) )
	
	t = U32(((state.read2(2)) ^ state.reg4[R_39]) + 0x9a7a9a73)
	state.reg4[R_39] |= t
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xA8] = ASM_0xA8

def ASM_0x4D8(state, log):
	sVar1 = state.read2(0)
	state.reg4[R_69] += 0x5f6fab10
	state.reg2[R_8a] += (sVar1 + state.reg4[R_39] + state.reg4[R_a7]) & 0xFFFF
	
	iVar8 = (state.read2(4)) + state.reg4[R_39] + state.reg4[R_2c]
	state.reg4[R_39] -= iVar8
	state.reg4[R_69] ^= 0x71ba05fb
	state.reg2[R_9d] += iVar8 & 0xFFFF
	state.reg4[R_39] &= (state.read4(6))
	
	r1 = (state.reg2[R_9d] + 0xed73) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x2cc0) & 0xFFFF
	
	state.VM_ADD_R_RM(log, r1, r2, state.read2(2)) #r1 += [r2]
	
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] |= 0x3e584b7f
	state.reg4[R_39] |= 0x1717e289
	
	t = (state.read2(10)) ^ state.reg4[R_39]
	state.reg4[R_39] |= t
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4D8] = ASM_0x4D8

def ASM_0x42(state, log):
	iVar2 = U32(((state.read2(1)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] |= 0x410c62e
	state.reg2[R_9d] += iVar2 & 0xFFFF
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] |= 0x3b02b2b4
	
	uVar1 = U32(state.read(0) + state.reg4[R_39])
	state.reg4[R_8c] += uVar1
	state.reg4[R_a7] ^= uVar1
	
	r = (state.reg2[R_9d] + 0x5c60) & 0xFFFF
	b = state.reg1[R_8c]
	state.VM_ASGN_BRM_B(log, r, b)
	t = U32((state.read2(7)) + state.reg4[R_39])
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+9)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x42] = ASM_0x42

def ASM_0x170(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(8) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(8), uvar1))
	log.append(eflags)
	tp = state.read(10)
	op = JCC(tp)
	
	instr = state.read2(0)
	jmp = state.read4(4)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append(op + "  to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] - jmp)
	else:
		log.append(op + "  to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, instr))
		state.AddRoute(instr, state.reg4[R_EIP] + jmp)
	
	t = U32(state.read2(11) - state.reg4[R_39] + 0x2af98c69)
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x170] = ASM_0x170

def ASM_0x273(state, log):
	num = state.read4(0)
	
	frm = state.esp + 0x28
	to = frm + num
	
	if num != 0:
		num = 10
	
	while num != 0:
		val = state.rMem4(frm)
		log.append("#[esp+{:02X}h] = [esp+{:02X}h] ({:02X})".format(to - state.esp, frm - state.esp, val))
		state.wMem4(to, val)
		
		frm -= 4
		to -= 4
		num -= 1
	
	of = state.read4(0)
	res = U32(state.esp + of)
	log.append("#esp += {:02X} ({:02X})".format(of, res))
	state.esp = res
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append("#esp += 4")
	state.esp += 4
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x273] = ASM_0x273

def ASM_0x364(state, log):
	r1 = (state.read2(3))
	r2 = (state.read2(9))
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = state.read2(0)
	r2 = (state.read2(11))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = (state.read2(5)) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] += uVar3
	state.reg4[R_69] |= 0x1ef890c1
	state.reg2[R_9d] += uVar3 & 0xFFFF
	state.reg4[R_39] += 0x7d419ae2
	state.reg4[R_a7] += 0x7d419ae2
	
	uVar3 = U32(U32(state.read(2) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] += 0x21470cde
	state.reg4[R_8c] ^= uVar3
	state.reg4[R_a7] &= uVar3
	state.reg4[R_39] -= 0x6bc4f07d
	
	r = state.reg2[R_9d] ^ 0x1e36
	b = (state.reg4[R_8c] + 0x18) & 0xFF
	
	state.VM_ASGN_BRM_B(log, r, b)
	
	t = U32((state.read2(7)) + state.reg4[R_39] + 0x17519319)
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x364] = ASM_0x364

def ASM_0x1DE(state, log):
	uVar2 = U32(state.read2(9) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] += 0x5b98b0a0
	state.reg2[R_9d] -= uVar2 & 0xFFFF
	uVar2 = U32((state.read(4) + state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] |= 0x6cf07732
	state.reg4[R_8c] += uVar2
	state.reg4[R_a7] ^= uVar2
	
	r1 = (state.reg2[R_9d] + 0x27f4) & 0xFFFF
	v = state.reg1[r1]
	b = state.reg1[R_8c] ^ 1
	res = v & b
	efl = state.read2(0)
	log.append("VMR[{:02X}] = EFLAGS AND TEST b, VMR[{:02X}]({:02X}), {:02X} ({:02X})".format(efl, r1, v, b, res))
	
	state.reg4[R_39] -= (state.read4(5))
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x1ddefb35
	
	uVar2 = U32(((state.read2(2)) - state.reg4[R_39]) + 0x80f934a)
	state.reg4[R_39] &= uVar2
	state.next = uVar2 & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1DE] = ASM_0x1DE

def ASM_0x01(state, log):
	state.reg4[R_69] &= 0x33ac9bdd
	uVar2 = U32(((state.read2(6)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] |= 0x240b5474
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	sVar1 = (state.read2(2))
	state.reg4[R_69] += -0x7231a9b6
	state.reg2[R_8a] += (sVar1 + state.reg2[R_39] + state.reg2[R_a7]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xa64b) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_ASGN_WR_WR(log, r1, r2)

	t = (state.read2(4)) + state.reg4[R_39] + 0x3b82c321
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x01] = ASM_0x01

def ASM_0x8E(state, log):
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] |= 0x34369b8c
	sVar1 = (state.read2(4))
	state.reg4[R_69] &= 0x8027b3c
	state.reg2[R_9d] -= ((sVar1 - state.reg2[R_39]) + state.reg2[R_2c]) & 0xFFFF
	
	iVar4 = U32(((state.read2(6)) - state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] += iVar4
	state.reg4[R_69] &= 0x6760c16e
	state.reg2[R_8a] += iVar4 & 0xFFFF
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x25c5b230
	
	r1 = (state.reg2[R_9d] + 0xbc26) & 0xFFFF
	r2 = state.reg2[R_8a] ^ 0xa639
	state.VM_SUB_BR_BR(log, r1, r2)
	
	state.reg4[R_2c] += 0xc785103
	state.reg4[R_39] += -0x1e8c85cf
	
	t = U32(((state.read2(8)) - state.reg4[R_39]) + 0x242c51ff)
	state.reg4[R_39] -= t
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x8E] = ASM_0x8E

def ASM_0x3C(state, log):
	r1 = (state.read2(2))
	r2 = state.read2(0x12)
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(0xe))
	r2 = (state.read2(10))
	state.VM_XCHG_R_R(log, r1, r2)
	iVar5 = U32((state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] += iVar5
	state.reg4[R_69] |= 0x18aaeb7a
	state.reg2[R_8a] -= iVar5 & 0xFFFF
	state.reg4[R_39] ^= (state.read4(4))
	
	iVar5 = U32(((state.read2(0xc)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] -= iVar5
	state.reg4[R_69] += -0x1f28631a
	state.reg2[R_9d] ^= iVar5 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0x4c2a) & 0xFFFF
	state.VM_AND_R_R(log, r1, r2, state.read2(8))
	
	t = U32(((state.read2(0x14)) - state.reg4[R_39]) + 0xbd8d355a)
	state.reg4[R_39] -= t
	state.next = t & 0xFFFF
	state.chEIP(+0x16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3C] = ASM_0x3C

def ASM_0x13D(state, log):
	r1 = (state.read2(2))
	r2 = (state.read2(8))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar1 = state.read2(0)
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] ^= 0x2ac7da3e
	state.reg2[R_9d] += uVar1
	state.reg4[R_2c] |= state.reg4[R_39]
	state.reg4[R_2c] += 0x767f8107
	
	uVar3 = U32((state.read2(6) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] ^= uVar3
	state.reg4[R_69] += 0x767f8107
	state.reg2[R_8a] += uVar3 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x3b78) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x39a0) & 0xFFFF
	state.VM_ASGN_BR_BR(log, r1, r2)

	t = state.read2(4)
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x13D] = ASM_0x13D

def ASM_0x4E7(state, log):
	uVar1 = U32(state.read2(1) + state.reg4[R_39])
	state.reg4[R_39] |= uVar1
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] &= 0x10d5413a
	
	iVar2 = U32((state.read(0) ^ state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_69] += 0x79a50170
	state.reg4[R_8c] += iVar2
	state.reg4[R_a7] += iVar2
	
	t = U32(state.read2(3) + state.reg4[R_39])
	state.reg4[R_39] -= t
	state.next = t & 0xFFFF
	state.chEIP(+5)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4E7] = ASM_0x4E7

def ASM_0x1FF(state, log):
	uVar1 = state.read2(0)
	state.reg4[R_69] += -0x69faa832
	state.reg2[R_8a] += (uVar1 ^ state.reg2[R_39]) & 0xFFFF
	
	uVar2 = (state.read2(10)) ^ state.reg4[R_39]
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] ^= 0x7153ffb6
	state.reg2[R_9d] ^= uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x4410) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x573b) & 0xFFFF
	v1 = state.reg4[r1]
	v2 = state.reg4[r2]
	efl = state.read2(8)
	res = v1 & v2
	log.append("VMR[{:02X}] = EFLAGS AND TEST VMR[{:02X}]({:02X}), VMR[{:02X}]({:02X}) ({:02X})".format(efl, r1, v1, r2, v2, res))
	
	state.reg4[R_39] &= (state.read4(4))

	t = U32(state.read2(2) + state.reg4[R_39] + 0x55c51532)
	state.reg4[R_39] ^= t
	state.next = t & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1FF] = ASM_0x1FF

def ASM_0x417(state, log):
	uVar2 = (state.read2(2)) ^ state.reg4[R_39]
	state.reg4[R_39] += uVar2
	state.reg4[R_69] += 0x7dae1225
	state.reg2[R_9d] ^= uVar2 & 0xFFFF
	
	uVar2 = (state.read4(10))
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] += 0xcc27096
	state.reg4[R_8c] -= uVar2
	state.reg4[R_a7] |= uVar2
	
	v2 = U32(state.reg4[R_8c] + 0xbe361304)
	r = (state.reg2[R_9d] + 0x2fae) & 0xFFFF
	v1 = state.reg4[r]
	efl = (state.read2(8))
	res = v1 & v2
	log.append("VMR[{:02X}] = EFLAGS AND TEST VMR[{:02X}]({:02X}), {:02X} ({:02X})".format(efl, r, v1, v2, res))
		
	state.reg4[R_2c] |= state.reg4[R_39]
	state.reg4[R_39] &= (state.read4(4))
	
	t = U32(state.read2(0) - state.reg4[R_39] + 0xc7c6904c)
	state.next = t & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x417] = ASM_0x417

def ASM_0x491(state, log):
	uVar1 = U32(((state.read2(8)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += -0x57d4a6df
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += -0x3015e696
		
	uVar1 = U32(((state.read4(2)) + state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += 0x8756870
	state.reg4[R_8c] += uVar1
	
	v2 = U32(state.reg4[R_8c] + 0x746f498b)
	r = (state.reg2[R_9d] + 0xb03a) & 0xFFFF
	v1 = state.reg4[r]
	res = U32(v1 - v2)
	efl = (state.read2(6))
	log.append("VMR[{:02X}] = EFLAGS CMP TEST VMR[{:02X}]({:02X}), {:02X} ({:02X})".format(efl, r, v1, v2, res))
	
	
	t = U32((state.read2(10)) + 0x8da9d72)
	state.reg4[R_39] += t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x491] = ASM_0x491

def ASM_0x3F2(state, log):
	uVar5 = U32((state.read2(10) - state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] &= uVar5
	state.reg4[R_69] &= 0x3ab7344d
	state.reg2[R_9d] ^= uVar5 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] |= 0x11d53587
	
	r = (state.reg2[R_9d] ^ 0xe847)
	efl = (state.read2(8))
	state.VM_ADD_R_V(log, r, 1, efl)
	
	state.reg4[R_39] |= (state.read4(2))
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0xa2509f59)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3F2] = ASM_0x3F2

def ASM_0x4BA(state, log):
	r1 = (state.read2(2))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	state.reg4[R_39] |= 0x41d7a03b
	
	r1 = (state.read2(6))
	r2 = (state.read2(8))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = (state.read2(10)) ^ state.reg4[R_2c]
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] += 0x5ca32622
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x3020) & 0xFFFF
	state.VM_SUB_R_V(log, r, 1)
	
	t = state.read2(0) ^ 0x4fc741
	state.reg4[R_39] -= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4BA] = ASM_0x4BA

def ASM_0x19D(state, log):
	uVar4 = U32(((state.read2(8)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar4
	state.reg4[R_69] |= 0x1abb3ec4
	state.reg2[R_9d] -= uVar4 & 0xFFFF
	
	uVar4 = (state.read4(4)) ^ state.reg4[R_69]
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] |= 0x1c8da4a7
	state.reg4[R_8c] += uVar4
	state.reg4[R_a7] ^= uVar4
	
	r = (state.reg2[R_9d] + 0xd95b) & 0xFFFF
	val = state.reg4[R_8c] ^ 0x16b7e42c
	efl = state.read2(0)
	state.VM_OR_R_V(log, r, val, efl)
	
	state.reg4[R_39] |= 0x69449312
	
	t = U32((state.read2(2)) + state.reg4[R_39])
	state.reg4[R_39] &= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x19D] = ASM_0x19D

def ASM_0x49A(state, log):
	state.reg4[R_2c] |= 0x3446a30d
	state.reg4[R_2c] += 0x7ae519e0
	
	uVar1 = U32(((state.read2(4)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] ^= 0x305ad19a
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	r = state.reg2[R_9d]
	state.VM_NEG_R(log, r, state.read2(8))

	t = U32((state.read2(6)) + 0x57417c0d)
	state.reg4[R_39] &= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x49A] = ASM_0x49A


def ASM_0x08(state, log):
	state.reg4[R_39] &= 0x3f4f0bc9
	state.reg2[R_9d] += ((state.read2(2)) + state.reg2[R_39] + state.reg2[R_2c]) & 0xFFFF
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] += -0x17682592
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] |= 0x4deb56f9
	
	uVar1 = U32(((state.read4(8)) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] += -0x61ac4689
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] -= uVar1
	state.reg4[R_39] &= 0x4b6bafd8
	
	r = state.reg2[R_9d]
	v = U32(state.reg4[R_8c] + 0x10c355a2)
	state.VM_SUB_R_V(log, r, v)
	
	t = U32((state.read2(4)) + state.reg4[R_39] + 0x2abbe6de)
	state.reg4[R_39] &= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x08] = ASM_0x08


def ASM_0x17C(state, log):
	jmp = state.read4(4)
	state.next = state.read2(0)
	if (jmp & 0x80000000):
		jmp &= 0x7FFFFFFF
		log.append("JMP to -{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] - jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] - jmp)
	else:
		log.append("JMP to +{:02X}(EIP:{:02X})  with next {:02X}".format(jmp, state.reg4[R_EIP] + jmp, state.next))
		state.AddRoute(state.next, state.reg4[R_EIP] + jmp)
	log.append(";next = {:02X}".format(state.next))
	state.run = False
VMAsm[0x17C] = ASM_0x17C


def ASM_0x2C5(state, log):
	iVar2 = U32(state.read2(0) - state.reg4[R_39])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] &= 0x2efadc21
	state.reg2[R_9d] += iVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x7037) & 0xFFFF
	state.VM_POP_RM(log, r1)
	
	r2 = state.read2(6)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
		
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] += -0x5015458d
	t = U32((state.read2(2)) + state.reg4[R_39])
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C5] = ASM_0x2C5

def ASM_0x49E(state, log):
	r1 = state.read2(0)
	r2 = state.read2(8)
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(0xe))
	r2 = (state.read2(0x10))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar4 = U32(((state.read2(0xc)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar4
	state.reg4[R_69] ^= 0x586c8c6c
	state.reg2[R_9d] -= iVar4 & 0xFFFF
	
	uVar5 = (state.read4(4)) + state.reg4[R_69]
	state.reg4[R_69] += -0x2cec5ffc
	state.reg4[R_8c] -= uVar5
	state.reg4[R_a7] &= uVar5
	state.reg4[R_2c] ^= state.reg4[R_39]
	
	r = state.reg2[R_9d]
	v = U32(state.reg4[R_8c] + 0x97abbeee)
	efl = (state.read2(2))
	state.VM_AND_R_V(log, r, v, efl)
	
	t = U32((state.read2(10)) + state.reg4[R_39] + 0x6ac2ca12)
	state.reg4[R_39] += t
	state.chEIP(+0x12)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x49E] = ASM_0x49E

def ASM_0x1EB(state, log):
	r1 = (state.read2(2))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = U32(((state.read2(0x10)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] += 0x7ebab46
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	state.reg4[R_39] ^= (state.read4(6))
	
	r = (state.reg2[R_9d] + 0x7111) & 0xFFFF
	
	state.VM_NOT_RM(log, r)
	
	t = U32(state.read2(0xe) + 0xabcc3726)
	state.reg4[R_39] &= t
	state.chEIP(+0x12)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1EB] = ASM_0x1EB



def ASM_0x53(state, log):
	sVar1 = (state.read2(6))
	state.reg4[R_69] |= 0x33fe048b
	state.reg2[R_9d] += ((sVar1 + state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	uVar5 = U32((state.read2(2) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] ^= uVar5
	state.reg4[R_69] += 0x112708c5
	state.reg2[R_8a] += uVar5 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x4672) & 0xFFFF
	r2 = (state.reg2[R_8a] - 0xb2b) & 0xFFFF
	efl = (state.read2(4))
	state.VM_SUB_R_R(log, r1, r2, efl)
	
	t = U32(state.read2(0) + state.reg4[R_39] + 0xb929fda0)
	state.reg4[R_39] |= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x53] = ASM_0x53


def ASM_0xBB(state, log):
	state.reg4[R_39] |= 0x16653dd1
	state.reg4[R_69] &= 0x6a143cef
	
	iVar2 = U32((state.read2(6)) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] ^= 0x42fe4873
	state.reg2[R_9d] -= iVar2 & 0xFFFF
	state.reg4[R_69] |= 0x57cf8fa1
	state.reg4[R_39] |= (state.read4(8))
	
	iVar2 = U32(state.read4(0x10) - state.reg4[R_39])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] ^= 0x58e69295
	state.reg4[R_8c] -= iVar2
	state.reg4[R_a7] += iVar2
	state.reg4[R_39] += (state.read4(2))
	
	r = (state.reg2[R_9d] + 0xa7af) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0xfbf2b773)
	efl = (state.read2(0xc))
	state.VM_XOR_R_V(log, r, v, efl)
	
	t = U32((state.read2(0x14)) + state.reg4[R_39] + 0xc4ba56ff)
	state.reg4[R_39] |= t
	state.chEIP(+0x16)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xBB] = ASM_0xBB


def ASM_0x4F1(state, log):
	uVar1 = state.read2(0) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] ^= 0x2461c703
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	state.reg4[R_69] += -0x392069f4
	
	uVar1 = (state.read4(2)) ^ state.reg4[R_69]
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] &= 0x2e22c066
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] ^= uVar1
	state.reg4[R_2c] &= 0x4716a3d4
	
	r = (state.reg2[R_9d] + 0xa262) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0x851ecb39)
	
	state.VM_AND_R_V(log, r, v)
	
	t = U32((state.read2(6)) + state.reg4[R_39] + 0x5cc4b32e)
	state.reg4[R_39] += t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F1] = ASM_0x4F1


def ASM_0x31A(state, log):
	uVar5 = (state.read2(3)) ^ state.reg4[R_39]
	state.reg4[R_39] -= uVar5
	state.reg2[R_9d] ^= uVar5 & 0xFFFF
	uVar5 = U32((state.read(2) + state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_69] &= 0x6b5a5865
	state.reg4[R_8c] -= uVar5
	state.reg4[R_a7] |= uVar5
	state.reg4[R_39] &= 0x8dad25e
	
	v = U32(state.reg4[R_8c] + 0x99073db)
	r = (state.reg2[R_9d] + 0x6f0b) & 0xFFFF
	state.VM_LSH_R_V(log, r, v, (state.read2(5)))
	
	t = state.read2(0) ^ state.reg4[R_39] ^ 0x5e74104b
	state.reg4[R_39] -= t
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x31A] = ASM_0x31A

def ASM_0x414(state, log):
	uVar1 = U32(((state.read4(4)) - state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_69] ^= 0x1ccc11d7
	state.reg4[R_8c] += uVar1
	state.reg4[R_a7] ^= uVar1
	
	iVar2 = U32((state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] &= 0x5718d65e
	state.reg2[R_9d] += iVar2 & 0xFFFF
	state.reg4[R_39] += 0x5e112d0e
	
	r = (state.reg2[R_9d] + 0xade8) & 0xFFFF
	v = state.reg4[R_8c]
	efl = (state.read2(2))
	state.VM_XOR_R_V(log, r, v, efl)
	
	t = U32(state.read2(0xe) + 0x2f275549)
	state.reg4[R_39] += t
	state.chEIP(+0x12)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x414] = ASM_0x414


def ASM_0x454(state, log):
	state.reg4[R_2c] ^= state.reg4[R_39]
	r1 = (state.read2(2))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar4 = U32((state.read2(4) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] += -0x7fdc3ac1
	state.reg2[R_8a] ^= uVar4 & 0xFFFF
	
	iVar3 = U32((state.read2(6)) + state.reg4[R_2c])
	state.reg4[R_39] -= iVar3
	state.reg4[R_69] += 0x36e94d3d
	state.reg2[R_9d] += iVar3 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] - 0x90f) & 0xFFFF
	efl = state.read2(10)
	state.VM_XOR_R_R(log, r1, r2, efl)
	
	t = U32((state.read2(8) + state.reg4[R_39]) ^ 0x1c63a0df)
	state.reg4[R_39] ^= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x454] = ASM_0x454


def ASM_0x359(state, log):
	r1 = (state.read2(0xc))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(6))
	r2 = (state.read2(0xe))
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(8))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	sVar2 = (state.read2(2))
	state.reg4[R_69] |= 0x3d4e7295
	state.reg2[R_9d] += ((sVar2 - state.reg2[R_39]) ^ state.reg2[R_2c]) & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x5e9b) & 0xFFFF
	state.VM_NEG_R(log, r)
	
	t = U32(((state.read2(0x10)) ^ state.reg4[R_39]) + 0x33007497)
	state.chEIP(+0x14)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x359] = ASM_0x359


def ASM_0x420(state, log):
	state.reg4[R_2c] ^= 0x2c7d1f
	
	uVar3 = U32((state.read2(4)) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] |= 0x111c741e
	state.reg2[R_9d] += uVar3 & 0xFFFF
	
	uVar3 = U32((state.read4(6) - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_69] ^= 0x239f496f
	state.reg4[R_8c] ^= uVar3
	state.reg4[R_a7] ^= uVar3
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] |= 0x6eeba087
	
	r = (state.reg2[R_9d] + 0x18b4) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0xeb6bbf6f)
	efl = (state.read2(2))
	
	state.VM_OR_R_V(log, r, v, efl)
	
	state.reg4[R_39] += -0x7409a8c0
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0x9a3d2eae)
	state.reg4[R_39] += t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x420] = ASM_0x420


def ASM_0x12F(state, log):
	state.reg2[R_9d] ^= (state.read2(2)) ^ state.reg2[R_2c]
	state.reg4[R_2c] &= state.reg4[R_39]
	
	sVar1 = (state.read2(10))
	state.reg4[R_69] += 0x7dfc631
	state.reg2[R_8a] += ((sVar1 + state.reg2[R_39]) - state.reg2[R_a7]) & 0xFFFF
	state.reg4[R_39] &= 0x5f0b4eb3
	
	r1 = (state.reg2[R_9d] + 0x4e06) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x7518) & 0xFFFF
	v1 = state.reg4[r1]
	v2 = state.reg4[r2]
	efl = state.read2(8)
	res = U32(v1 - v2)
	log.append("VMR[{:02X}] = EFLAGS CMP TEST VMR[{:02X}]({:02X}), VMR[{:02X}]({:02X}) ({:02X})".format(efl, r1, v1, r2, v2, res))
	
	t = U32(state.read2(4) ^ state.reg4[R_39] ^ 0x33684616)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x12F] = ASM_0x12F


def ASM_0x88(state, log):
	state.reg4[R_69] |= 0x5b58caeb
	
	uVar1 = state.read2(0)
	state.reg4[R_69] |= 0x187d936d
	state.reg2[R_8a] ^= ((uVar1 ^ state.reg2[R_39]) - state.reg2[R_a7]) & 0xFFFF
	
	uVar2 = U32(((state.read2(2)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] |= 0x7bc7efc0
	state.reg2[R_9d] ^= uVar2 & 0xFFFF
	state.reg4[R_2c] &= state.reg4[R_39]
	
	r1 = (state.reg2[R_9d] + 0xb846) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x7692) & 0xFFFF
	state.VM_ASGN_BR_BRM(log, r1, r2)
	
	t = U32((state.read2(4)) ^ state.reg4[R_39] ^ 0x3e250091)
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x88] = ASM_0x88


def ASM_0x382(state, log):
	state.reg4[R_39] += 0x7d35866
	
	r1 = (state.read2(0xc))
	r2 = (state.read2(8))
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(10))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	state.reg4[R_39] |= (state.read4(0xe))
	uVar4 = U32((state.read2(6)) + state.reg4[R_39] ^ state.reg4[R_a7])
	state.reg4[R_39] &= uVar4
	state.reg4[R_69] ^= 0x6b295098
	state.reg2[R_8a] += uVar4 & 0xFFFF
	
	uVar4 = U32((state.read2(0) - state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] &= uVar4
	state.reg4[R_69] += 0x33e7e673
	state.reg2[R_9d] ^= uVar4 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x5919) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0xf5b2) & 0xFFFF
	v1 = state.reg1[r1]
	v2 = state.reg1[r2]
	efl = state.read2(0x12)
	res = U32(v1 & v2)
	log.append("VMR[{:02X}] = EFLAGS AND TEST b,VMR[{:02X}]({:02X}), b,VMR[{:02X}]({:02X}) ({:02X})".format(efl, r1, v1, r2, v2, res))
	
	t = U32((state.read2(2) + state.reg4[R_39]) ^ 0x1443e4)
	state.reg4[R_39] += t
	state.chEIP(+0x14)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x382] = ASM_0x382


def ASM_0x263(state, log):
	uVar2 = (state.read4(4))
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] += -0x3edf6c99
	state.reg4[R_8c] ^= uVar2
	state.reg4[R_a7] &= uVar2
	state.reg4[R_69] &= 0x762d4839
	
	uVar1 = (state.read2(10))
	state.reg4[R_69] &= 0x4f119fd5
	state.reg2[R_9d] += ((uVar1 ^ state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	state.reg4[R_2c] &= 0x4517fb34
	
	r = (state.reg2[R_9d] + 0xc491) & 0xFFFF
	v = U32(state.reg4[R_8c] + -0x2fa8007e) 
	state.VM_SUB_R_V(log, r, v)
	
	state.reg4[R_39] ^= state.read4(0)
	
	t = (state.read2(8)) ^ state.reg4[R_39]
	state.reg4[R_39] ^= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x263] = ASM_0x263


def ASM_0x65(state, log):
	of = state.read2(4)
	val = state.read4(6) + state.reg4[R_ImgBase] 
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x65] = ASM_0x65


def ASM_0x2E4(state, log):
	of = state.read2(4)
	val = state.read4(6) + state.reg4[R_ImgBase] 
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x2E4] = ASM_0x2E4


def ASM_0x4FA(state, log):
	uVar1 = state.read2(0) ^ state.reg4[R_39]
	state.reg4[R_39] -= uVar1
	state.reg4[R_69] |= 0x6665b6a3
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	uVar1 = (state.read2(2)) ^ state.reg4[R_a7]
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] += -0x33aeeb3e
	state.reg2[R_8a] += uVar1 & 0xFFFF
	state.reg4[R_2c] &= 0x18d26f86
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0x4bb1) & 0xFFFF
	state.VM_XOR_R_R(log, r1, r2)
	
	t = U32(((state.read2(4)) ^ state.reg4[R_39]) + 0x6962c6f3)
	state.reg4[R_39] += t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4FA] = ASM_0x4FA


def ASM_0x287(state, log):
	uVar2 = U32((state.read2(8)) + state.reg4[R_a7])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] += 0x6172d855
	state.reg2[R_8a] += uVar2 & 0xFFFF
	state.reg4[R_69] &= 0x5044ad68
	
	uVar1 = (state.read2(10))
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] |= 0x3bff38a3
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	state.reg4[R_39] += (state.read4(4))
	
	r1 = (state.reg2[R_9d] ^ 0x96b0) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x643) & 0xFFFF
	v1 = state.reg4[r1]
	v2 = state.reg4[r2]
	efl = state.read2(2)
	res = U32(v1 & v2)
	log.append("VMR[{:02X}] = EFLAGS AND TEST VMR[{:02X}]({:02X}), VMR[{:02X}]({:02X}) ({:02X})".format(efl, r1, v1, r2, v2, res))
	
	
	t = state.read2(0) ^ state.reg4[R_39] ^ 0x6d9665c3
	state.reg4[R_39] |= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x287] = ASM_0x287


def ASM_0x30(state, log):
	uVar1 = U32(((state.read2(4)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += 0x2dda05a1
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	uVar1 = state.read(6) ^ state.reg4[R_39]
	state.reg4[R_69] += 0x53edd7ab
	state.reg4[R_8c] += uVar1
	state.reg4[R_a7] |= uVar1
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] += -0x699aff11
	state.reg4[R_2c] ^= state.reg4[R_39]
	
	r = (state.reg2[R_9d] ^ 0xbcf6)
	b = (state.reg1[R_8c] + 0x1f) & 0xFF
	
	state.VM_ASGN_BRM_B(log, r, b)	
	
	t = U32((state.read2(2)) + state.reg4[R_39])
	state.reg4[R_39] += t
	state.chEIP(+0xd)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x30] = ASM_0x30


def ASM_0x2F(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(6) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(6), uvar1))
	log.append(eflags)
	tp = state.read(8)
	op = JCC(tp)
	
	of = state.read2(4)
	val = state.read4(0) + state.reg4[R_ImgBase] 
	
	log.append(op + " TO:")
	log.append("\t#STACK set [esp + {:02X}] = {:02X}".format(of, val))
	if (of < 0x24 and of >= 0):
		state.wMem4(state.esp + of, val)
	
	log.append("\t#pop EDI {:02X}".format(state.pop()))
	log.append("\t#pop ESI {:02X}".format(state.pop()))
	log.append("\t#pop EBP {:02X}".format(state.pop()))
	log.append("\t#pop EBX {:02X}".format(state.pop()))
	log.append("\t#pop EDX {:02X}".format(state.pop()))
	log.append("\t#pop ECX {:02X}".format(state.pop()))
	log.append("\t#pop EAX {:02X}".format(state.pop()))
	log.append("\t#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append("\t;RET!  to {:02X}".format(state.pop()))
	
	if state.OnEnd:
		state.OnEnd(state, log)
	
	log.append("On Not:")
	
	r = state.read2(9)
	state.VM_ADD_R_V(log, r, 0x24)

	t = U32(state.read2(11) - state.reg4[R_39] + 0x517fc623)
	state.reg4[R_39] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2F] = ASM_0x2F


def ASM_0x3BC(state, log):
	of = state.read2(4)
	
	r = state.read2(6)
	va = state.reg4[r]
	val = state.rMem4(va)
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = [VMR{:02X}] ([{:02X}]) ({:02X})".format(of, r, va, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x3BC] = ASM_0x3BC


def ASM_0x1C5(state, log):
	uVar1 = (state.read2(4)) ^ state.reg4[R_39]
	state.reg4[R_39] += uVar1
	state.reg4[R_69] &= 0x756acef6
	state.reg2[R_9d] += uVar1 & 0xFFFF
	state.reg4[R_2c] += -0x41256715
	
	uVar1 = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += -0x41256715
	state.reg2[R_8a] -= uVar1 & 0xFFFF
	state.reg4[R_2c] &= 0x5e2708a5
	state.reg4[R_39] &= 0x5e2708a5
	state.reg4[R_69] |= 0x305b1d4b
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] ^ 0x9b0f) & 0xFFFF
	state.VM_ASGN_BR_BR(log, r1, r2)
	
	t = U32((state.read2(2)) + state.reg4[R_39])
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1C5] = ASM_0x1C5


def ASM_0xB1(state, log):
	state.reg4[R_39] |= state.read4(0)
	state.reg4[R_39] &= (state.read4(10))
	
	uVar1 = U32(((state.read2(6)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] ^= 0x3333fe87
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	uVar1 = (state.read2(4)) ^ state.reg4[R_a7]
	state.reg4[R_39] -= uVar1
	state.reg4[R_69] &= 0xd90a2c2
	state.reg2[R_8a] ^= uVar1 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] ^ 0xecff) & 0xFFFF
	state.VM_ASGN_R_BRM(log, r1, r2)
		 
	t = U32(((state.read2(8)) - state.reg4[R_39]) + 0xe4d2698d)
	state.reg4[R_39] += t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xB1] = ASM_0xB1

def ASM_0x2FB(state, log):
	of = state.read2(4)
	val = state.read4(6) + state.reg4[R_ImgBase] 
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x2FB] = ASM_0x2FB


def ASM_0x1C4(state, log):
	of = state.read2(4)
	val = state.read4(0) + state.reg4[R_ImgBase] 
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, val))

	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x1C4] = ASM_0x1C4

def ASM_0x3FB(state, log):
	uVar1 = U32((state.read2(4)) + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] &= 0x5af225e8
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	state.reg4[R_2c] &= 0x4ec8fc61
	
	uVar1 = U32((state.read2(6)) ^ state.reg4[R_39])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] &= 0x4ec8fc61
	state.reg2[R_8a] ^= uVar1 & 0xFFFF
	state.reg4[R_2c] += state.reg4[R_39]
	
	r1 = (state.reg2[R_9d] ^ 0x24da)
	r2 = (state.reg2[R_8a] ^ 0x5d84)
	state.VM_OR_WR_WR(log, r1, r2)
		 
	t = (state.read2(2)) ^ state.reg4[R_39] ^ 0x354e3f96
	state.reg4[R_39] += t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3FB] = ASM_0x3FB

def ASM_0x11C(state, log):
	state.reg4[R_39] &= 0x6b6905c2
	
	r1 = (state.read2(6))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar6 = (state.read2(8)) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= uVar6
	state.reg4[R_69] += 0x494ffdb1
	state.reg2[R_9d] -= uVar6 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xc291) & 0xFFFF
	state.VM_POP_RM(log, r1)
	
	r2 = state.read2(4)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
		
	t = U32((state.read2(2)) + 0x69b75fd)
	state.reg4[R_39] ^= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x11C] = ASM_0x11C

def ASM_0x188(state, log):
	uVar3 = U32(((state.read2(2)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar3
	state.reg2[R_9d] ^= uVar3 & 0xFFFF
	
	uVar3 = U32(((state.read2(4)) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] += 0x4dccd708
	state.reg2[R_8a] += uVar3 & 0xFFFF
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x125a4b2b
	
	r1 = (state.reg2[R_9d] + 0x14dd) & 0xFFFF
	r2 = state.reg2[R_8a]
	efl = (state.read2(6))
	state.VM_SUB_R_R(log, r1, r2, efl)
	
	t = U32(state.read2(0) + state.reg4[R_39] + 0xb99b8b6c)
	state.reg4[R_39] -= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x188] = ASM_0x188

def ASM_0x292(state, log):
	iVar5 = U32(((state.read2(2)) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] += iVar5
	state.reg4[R_69] &= 0x3d4a1027
	state.reg2[R_8a] -= iVar5 & 0xFFFF
	
	uVar3 = U32(((state.read2(4)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] ^= 0x3f74121d
	state.reg2[R_9d] ^= uVar3 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0x9f71) & 0xFFFF
	efl = (state.read2(0xc))
	state.VM_SUB_R_RM(log, r1, r2, efl)
	
	state.reg4[R_2c] -= state.reg4[R_39]
	
	t = U32(state.read2(0) + 0xf97ea10c)
	state.reg4[R_39] += t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x292] = ASM_0x292

def ASM_0x1A4(state, log):
	state.reg4[R_69] &= 0x220f62b1
	
	r1 = (state.read2(6))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] |= 0x66ac893e

	uVar4 = U32((state.read4(0) - state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_39] -= uVar4
	state.reg4[R_69] += 0x3fa8ce78
	state.reg4[R_8c] -= uVar4
	state.reg4[R_a7] |= uVar4
	
	sVar2 = (state.read2(8))
	state.reg4[R_69] += 0x3529f156
	state.reg2[R_9d] += ((sVar2 - state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	
	r = state.reg2[R_9d]
	v = U32(state.reg4[R_8c] + 0x138cf40)
	state.VM_XOR_R_V(log, r, v)
	
	t = U32((state.read2(10)) + state.reg4[R_39] + 0xdc25ec80)
	state.reg4[R_39] |= t
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1A4] = ASM_0x1A4

def ASM_0x199(state, log):
	state.reg4[R_39] += 0x14c0304b
	state.reg4[R_69] |= 0x30b49045
	
	iVar1 = U32(state.read(0) + state.reg4[R_39])
	state.reg4[R_39] -= iVar1
	state.reg4[R_8c] += iVar1
	state.reg4[R_a7] -= iVar1
	state.reg2[R_9d] += ((state.read2(3)) ^ state.reg2[R_39]) & 0xFFFF
	
	v = U32(state.reg4[R_8c] + 0x2a580941)
	r = (state.reg2[R_9d] + 0xb1a7) & 0xFFFF
	
	state.VM_LSH_R_V(log, r, v)
	
	state.reg4[R_39] ^= (state.read4(7))
	
	t = U32((state.read2(1)) - state.reg4[R_39])
	state.reg4[R_39] -= t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x199] = ASM_0x199

def ASM_0x19(state, log):
	uVar9 = (state.read2(0xc)) ^ state.reg4[R_39] ^ state.reg4[R_a7]
	state.reg4[R_39] |= uVar9
	state.reg4[R_69] &= 0x7b2abb92
	state.reg2[R_8a] ^= uVar9 & 0xFFFF
	
	iVar7 = U32(((state.read2(6)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] += iVar7
	state.reg4[R_69] += 0x588c8915
	state.reg2[R_9d] ^= iVar7 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] ^ 0xba73) & 0xFFFF
	efl = (state.read2(2))
	state.VM_SUB_R_RM(log, r1, r2, efl)

	state.reg4[R_a7] += 0xa4cf210

	t = (state.read2(0) ^ 0x632e405a)
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x19] = ASM_0x19

def ASM_0x2D1(state, log):
	r1 = state.read2(0)
	r2 = state.read2(0x10)
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar5 = U32(((state.read2(0x14)) ^ state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] += iVar5
	state.reg4[R_69] += -0x6d7508c5
	state.reg2[R_8a] -= iVar5 & 0xFFFF
	state.reg4[R_39] -= (state.read4(8))
	state.reg4[R_69] += -0x24f1b137
	
	uVar3 = U32(((state.read2(0x12)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] ^= uVar3
	state.reg4[R_69] += -0x3b3d4f2
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	efl = state.read2(0xc)
	state.VM_XOR_R_RM(log, r1, r2, efl)
	
	t = U32((state.read2(0xe)) + 0x79e59b1a)
	state.chEIP(+0x16)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2D1] = ASM_0x2D1

def ASM_0x494(state, log):
	state.reg4[R_39] += -0x436ef438
	
	uVar5 = U32((state.read2(6)) + state.reg4[R_39] + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar5
	state.reg4[R_69] &= 0x1d80140c
	state.reg2[R_9d] ^= uVar5 & 0xFFFF
	
	uVar5 = U32((state.read2(0) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] &= uVar5
	state.reg4[R_69] += -0x510bc913
	state.reg2[R_8a] ^= uVar5 & 0xFFFF
	
	r1 = (state.reg2[R_9d] ^ 0xa06f)
	r2 = state.reg2[R_8a]
	efl = state.read2(4)
	state.VM_XOR_RM_R(log, r1, r2, efl)

	state.reg4[R_39] |= 0x72fd91d9
	
	t = U32((state.read2(2)) + state.reg4[R_39] + 0xed53c8e6)
	state.reg4[R_39] &= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x494] = ASM_0x494

def ASM_0x151(state, log):
	state.reg4[R_39] |= (state.read4(2))
	
	uVar1 = U32(((state.read4(6)) ^ state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += 0x77588948
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] ^= uVar1
	
	uVar1 = U32((state.read2(0) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] &= 0x5bf0f340
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	r = (state.reg2[R_9d] - 0xad0)
	v = U32(state.reg4[R_8c] + 0x68368c02)
	efl = state.read2(10)
	state.VM_AND_R_V(log, r, v, efl)
	
	t = U32(((state.read2(0xc)) - state.reg4[R_39]) + 0x6f07a994)
	state.reg4[R_39] -= t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x151] = ASM_0x151


def ASM_0x1F1(state, log):
	of = state.read2(4)
	r = state.read2(6)
	val = state.reg4[r]
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = VMR[{:02X}] ({:02X})".format(of, r, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))

	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x1F1] = ASM_0x1F1


def ASM_0x3E3(state, log):
	state.reg4[R_2c] &= 0x42e362b3
	
	r1 = (state.read2(0xb))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	sVar2 = (state.read2(2))
	state.reg4[R_69] ^= 0x3bce9267
	state.reg2[R_9d] += sVar2
	
	uVar4 = U32((state.read(10) ^ state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] += 0x153313bd
	state.reg4[R_8c] -= uVar4
	state.reg4[R_a7] &= uVar4
	
	r = (state.reg2[R_9d] + 0x920b) & 0xFFFF
	v = (state.reg4[R_8c] + 0x62) & 0xFF
	state.VM_ADD_BR_B(log, r, v)
	
	t = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] |= t
	state.chEIP(+0xd)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3E3] = ASM_0x3E3


def ASM_0x3B2(state, log):
	state.reg4[R_39] -= (state.read4(4))
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] += -0x2c284b
	
	iVar1 = U32((state.read2(0) + state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] += iVar1
	state.reg4[R_69] += -0x48650390
	state.reg2[R_8a] += iVar1 & 0xFFFF
	
	uVar2 = U32((state.read2(2) + state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] -= uVar2
	state.reg2[R_9d] -= uVar2 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	state.VM_OR_R_R(log, r1, r2)
	
	t = U32((state.read2(8) - state.reg4[R_39]) ^ 0x5b2969e8)
	state.reg4[R_39] ^= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3B2] = ASM_0x3B2

def ASM_0x2C0(state, log):
	bVar1 = state.read(8)
	iVar3 = state.reg4[R_69]
	state.reg4[R_69] |= 0x5c9a3e82
	state.reg4[R_8c] -= U32((bVar1 - state.reg4[R_39]) - iVar3)
	
	uVar4 = U32(((state.read2(6)) - state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] += uVar4
	state.reg4[R_69] |= 0x49c8c260
	state.reg2[R_9d] += uVar4 & 0xFFFF
	
	v = state.reg4[R_8c] ^ 0x5314e262
	r = (state.reg2[R_9d] + 0xefe4) & 0xFFFF
	state.VM_RSH_R_V(log, r, v)
	
	t = state.read2(0)
	state.reg4[R_39] |= t
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C0] = ASM_0x2C0

def ASM_0x40C(state, log):
	r1 = (state.read2(6))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar3 = U32((state.read2(8)) + state.reg4[R_39])
	state.reg4[R_39] -= iVar3
	state.reg4[R_69] ^= 0x4bb1c998
	state.reg2[R_9d] -= iVar3 & 0xFFFF
	
	uVar4 = U32(((state.read4(10)) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] += 0xd7ea254
	state.reg4[R_8c] -= uVar4
	state.reg4[R_39] ^= 0x2eefbc02
	
	r = (state.reg2[R_9d] ^ 0xfc3c) & 0xFFFF
	v = state.reg4[R_8c] ^ 0x264536d0
	state.VM_OR_R_V(log, r, v)
		 
	t = U32(state.read2(0) - state.reg4[R_39])
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x40C] = ASM_0x40C


def ASM_0xA3(state, log):
	iVar5 = U32(((state.read2(5)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar5
	state.reg4[R_69] &= 0x2b0aedbd
	state.reg2[R_9d] += iVar5 & 0xFFFF
	
	uVar7 = state.read(2) ^ state.reg4[R_69]
	state.reg4[R_69] += 0x2aa38f7b
	state.reg4[R_8c] -= uVar7
	state.reg4[R_a7] &= uVar7
	
	v = state.reg4[R_8c] + 0xcfebe5fc
	r = state.reg2[R_9d]
	efl = state.read2(3)
	state.VM_LSH_R_V(log, r, v, efl)
	
	state.reg4[R_2c] |= 0x61e91e5a
	state.reg4[R_39] |= 0x61e91e5a
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] ^= 0x4b1d93c5

	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0xeec76f4e)
	state.reg4[R_39] &= t
	state.chEIP(+7)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xA3] = ASM_0xA3

def ASM_0x266(state, log):
	r1 = (state.read2(2))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar1 = (state.read2(6))
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] |= 0x180c80a4
	state.reg2[R_9d] += uVar1
	state.reg4[R_2c] += -0x7a88f98d
	
	r = (state.reg2[R_9d] ^ 0xf1a)
	efl = (state.read2(8))
	state.VM_ADD_R_V(log, r, 1, efl)
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0x711f8fc5)
	state.reg4[R_39] -= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x266] = ASM_0x266


def ASM_0x41B(state, log):
	state.reg4[R_2c] ^= state.reg4[R_39]
	state.reg4[R_39] += (state.read4(4))
	
	uVar1 = state.read2(0)
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += -0x6eda3a6d
	state.reg2[R_8a] -= uVar1
	
	iVar3 = U32(((state.read2(2)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] += iVar3
	state.reg4[R_69] ^= 0x782ab3d2
	state.reg2[R_9d] -= iVar3 & 0xFFFF
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x362977b8
	
	r1 = (state.reg2[R_9d] + 0xd0db) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x50a3) & 0xFFFF
	efl = state.read2(10)
	v1 = state.reg4[r1]
	v2 = state.reg4[r2]
	res = U32(v1 - v2)
	log.append("VMR[{:02X}] = EFLAGS CMP TEST VMR[{:02X}]({:02X}), VMR[{:02X}]({:02X}) ({:02X})".format(efl, r1, v1, r2, v2, res))
	
	t = (state.read2(8)) + 0x2eb8bc1c
	state.reg4[R_39] ^= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x41B] = ASM_0x41B


def ASM_0x39E(state, log):
	uVar1 = (state.read2(4))
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += -0x25c59282
	state.reg2[R_9d] += uVar1
	
	iVar2 = U32(((state.read2(2)) - state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] += 0x5e5e6004
	state.reg2[R_8a] -= iVar2 & 0xFFFF
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_39] += -0x75aef20a
	state.reg4[R_a7] += -0x75aef20a
	state.reg4[R_2c] += -0x7cfc82ac
	
	r1 = (state.reg2[R_9d] + 0xaab2) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_ASGN_R_BRM(log, r1, r2)
	
	t = U32(state.read2(0) + state.reg4[R_39] + 0xa436a94d)
	state.reg4[R_39] += t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x39E] = ASM_0x39E

def ASM_0x1C0(state, log):
	state.reg4[R_39] += -0x69ca72eb
	state.reg4[R_69] += 0x742e1cc0
	
	uVar1 = (state.read2(4))
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += 0x34df9f79
	state.reg2[R_9d] += uVar1
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] &= 0x41b4ff0
	
	uVar2 = U32(((state.read2(6)) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] += uVar2
	state.reg4[R_69] += -0xaa4cfa
	state.reg2[R_8a] ^= uVar2 & 0xFFFF
	state.reg4[R_39] ^= (state.read4(8))
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	state.VM_ASGN_WR_WR(log, r1, r2)
		
	t = (state.read2(2)) ^ state.reg4[R_39]
	state.reg4[R_39] += t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1C0] = ASM_0x1C0


def ASM_0x10C(state, log):
	state.reg4[R_2c] |= state.reg4[R_39]
	
	uVar2 = U32(((state.read2(4)) + state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] |= 0x6bb6232a
	state.reg2[R_8a] += uVar2 & 0xFFFF
	
	uVar1 = (state.read2(2))
	state.reg4[R_39] -= uVar1
	state.reg4[R_69] |= 0x2172dcf3
	state.reg2[R_9d] += uVar1
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0xc19ff106)
	state.reg4[R_39] ^= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x10C] = ASM_0x10C


def ASM_0x1DC(state, log):
	state.reg4[R_69] ^= 0x4e7e70ed
	
	iVar2 = U32((state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg2[R_9d] ^= iVar2 & 0xFFFF
	
	iVar2 = U32(state.read(4) + state.reg4[R_69])
	state.reg4[R_69] |= 0x748747be
	state.reg4[R_8c] -= iVar2
	state.reg4[R_a7] -= iVar2
	state.reg4[R_69] &= 0x76f6dcf2
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x7af14388
	
	r = state.reg2[R_9d] ^ 0x571a
	v = state.reg1[R_8c]
	state.VM_ASGN_BR_B(log, r, v)
	
	t = U32(((state.read2(2)) - state.reg4[R_39]) + 0xf5f4ff64)
	state.reg4[R_39] ^= t
	state.chEIP(+5)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1DC] = ASM_0x1DC


def ASM_0x49B(state, log):
	uVar5 = U32((state.read2(4) + state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] &= uVar5
	state.reg4[R_69] ^= 0x633e69e7
	state.reg2[R_9d] -= uVar5 & 0xFFFF
	state.reg4[R_69] += 0x69885779
	
	r = (state.reg2[R_9d] ^ 0x5da6)
	efl = state.read2(0)
	state.VM_SUB_R_V(log, r, 1, efl)
	
	state.reg4[R_2c] &= 0x58070e92
	
	t = U32((state.read2(2) + state.reg4[R_39]) ^ 0x6f0a8979)
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x49B] = ASM_0x49B

def ASM_0x331(state, log):
	uVar1 = U32(((state.read4(2)) + state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_69] |= 0x24e79ff8
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] |= uVar1
	
	iVar2 = U32(state.read2(0) + state.reg4[R_39] + state.reg4[R_2c])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] |= 0x4a523af
	state.reg2[R_9d] += iVar2 & 0xFFFF
	state.reg4[R_39] &= 0x37f9e91
	state.reg4[R_69] += -0x22fa4f3b
	state.reg4[R_39] += 0x4683aac8
	
	r = (state.reg2[R_9d] ^ 0x3746)
	v = state.reg4[R_8c]
	efl = state.read2(8)
	state.VM_OR_R_V(log, r, v, efl)
	
	t = U32(((state.read2(6)) ^ state.reg4[R_39]) + 0x5b29d163)
	state.reg4[R_39] += t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x331] = ASM_0x331


def ASM_0x237(state, log):
	sVar1 = (state.read2(2))
	state.reg4[R_69] ^= 0x74e43a1
	state.reg2[R_8a] += sVar1
	state.reg4[R_69] |= 0x33bfbd65
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] += 0x788eaf5c
	state.reg4[R_69] += 0x19f41cda
	
	uVar2 = (state.read2(6))
	state.reg4[R_69] |= 0x7016946
	state.reg2[R_9d] -= U32((uVar2 ^ state.reg2[R_39]) + state.reg2[R_2c])
	state.reg4[R_39] += 0x7db83f38
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	efl = state.read2(4)
	state.VM_XOR_RM_R(log, r1, r2, efl)
	
	t = U32((state.read2(0) - state.reg4[R_39]) + 0x7c8e404e)
	state.reg4[R_39] -= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x237] = ASM_0x237


def ASM_0x3A8(state, log):
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] ^= 0x77650915

	r1 = (state.read2(8))
	r2 = (state.read2(0xc))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar6 = U32((state.read4(4) - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_39] |= uVar6
	state.reg4[R_69] += -0x6790a007
	state.reg4[R_8c] ^= uVar6
	state.reg4[R_a7] += uVar6
	
	iVar4 = U32(((state.read2(2)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar4
	state.reg4[R_69] += -0x671949df
	state.reg2[R_9d] ^= iVar4 & 0xFFFF
	state.reg4[R_39] |= 0x6eeb3d21
	
	r = (state.reg2[R_9d] + 0x22d5) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0xc773899a)
	efl = state.read2(10)
	state.VM_XOR_R_V(log, r, v, efl)
	
	state.reg4[R_39] += 0x4e4e4a68
	
	t = state.read2(0) ^ state.reg4[R_39]
	state.reg4[R_39] |= t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A8] = ASM_0x3A8


def ASM_0x48A(state, log):
	uVar5 = U32((state.read2(10) + state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] |= uVar5
	state.reg4[R_69] += 0x75c1b8d
	state.reg2[R_8a] += uVar5 & 0xFFFF
	
	iVar3 = U32(state.read2(4) + state.reg4[R_39])
	state.reg4[R_39] += iVar3
	state.reg2[R_9d] ^= iVar3 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] ^ 0x9a53)

	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] &= 0x2622a28a
	
	efl = state.read2(2)
	v1 = state.reg4[r1]
	adr = state.reg4[r2]
	v2 = state.rMem4(adr)
	res = U32(v1 - v2)
	log.append("VMR[{:02X}] = EFLAGS CMP TEST VMR[{:02X}]({:02X}), [VMR[{:02X}]]([{:02X}] {:02X}) ({:02X})".format(efl, r1, v1, r2, adr, v2, res))

	t = U32((state.read2(0) - state.reg4[R_39]) ^ 0x216139f2)
	state.reg4[R_39] ^= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x48A] = ASM_0x48A

def ASM_0xFF(state, log):
	of = state.read2(4)
	
	r = state.read2(6)
	va = state.reg4[r]
	val = state.rMem4(va)
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = [VMR[{:02X}]] ([{:02X}]) ({:02X})".format(of, r, va, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0xFF] = ASM_0xFF


def ASM_0x44B(state, log):
	r1 = (state.read2(0x10))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = U32((state.read2(0) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] ^= 0x4621ea78
	state.reg2[R_9d] += uVar3 & 0xFFFF

	r = (state.reg2[R_9d] + 0x3dc9) & 0xFFFF
	state.VM_SUB_R_V(log, r, 1)
		 
	state.reg4[R_2c] ^= state.reg4[R_39]
	state.reg4[R_39] |= (state.read4(8))
	
	t = U32((state.read2(0xe)) + state.reg4[R_39] + 0x6ccdb64)
	state.reg4[R_39] -= t
	state.chEIP(+0x12)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x44B] = ASM_0x44B

def ASM_0x13F(state, log):
	iVar3 = U32(((state.read2(2)) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] -= iVar3
	state.reg4[R_69] |= 0x4c0e503f
	state.reg2[R_8a] -= iVar3 & 0xFFFF
	state.reg4[R_39] ^= 0x64c062cb
	state.reg4[R_69] ^= 0x40a023e1
	state.reg4[R_2c] ^= 0x64c062cb
	
	uVar2 = U32(((state.read2(4)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] += 0x231d340d
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x178a) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_XOR_R_RM(log, r1 ,r2)
	
	t = state.read2(0)
	state.reg4[R_39] += t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x13F] = ASM_0x13F


def ASM_0x32B(state, log):
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_a7] &= 0x14a4e2f3
	
	r1 = (state.read2(0xe))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar4 = U32(((state.read2(6)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar4
	state.reg4[R_69] &= 0x7b60f8b7
	state.reg2[R_9d] -= uVar4 & 0xFFFF
	
	iVar5 = U32((state.read2(4)) + state.reg4[R_a7])
	state.reg4[R_39] += iVar5
	state.reg4[R_69] ^= 0x45f00cee
	state.reg2[R_8a] -= iVar5 & 0xFFFF
	state.reg4[R_2c] &= state.reg4[R_39]
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] + 0xb8a3) & 0xFFFF
	state.VM_XOR_RM_R(log, r1, r2)
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0x3cf9030b

	t = U32((state.read2(2)) + state.reg4[R_39] + 0x99cfea1)
	state.reg4[R_39] &= t
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x32B] = ASM_0x32B

def ASM_0x506(state, log):
	iVar2 = U32((state.read2(6)) + state.reg4[R_39] + state.reg4[R_a7])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] |= 0x62bab660
	state.reg2[R_8a] ^= iVar2 & 0xFFFF
	
	iVar2 = U32((state.read2(0) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] += -0x6d16a8c0
	state.reg2[R_9d] += iVar2 & 0xFFFF
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] |= 0x3fdb5b1b
	
	r1 = (state.reg2[R_9d] + 0xdd16) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x9d12) & 0xFFFF
	state.VM_XOR_R_R(log, r1, r2)
	
	t = (state.read2(4))
	state.reg4[R_39] += t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x506] = ASM_0x506

def ASM_0x25B(state, log):
	state.reg4[R_39] &= (state.read4(6))
	state.reg4[R_2c] &= 0x31dd0a5a
	
	r1 = (state.read2(0xc))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar3 = U32(((state.read4(0x10)) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] += iVar3
	state.reg4[R_69] |= 0x25342fdd
	state.reg4[R_8c] += iVar3
	
	uVar4 = U32(((state.read2(10)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar4
	state.reg2[R_9d] += uVar4 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x4024) & 0xFFFF
	v = state.reg4[R_8c]
	state.VM_AND_R_V(log, r, v)
	
	t = U32((state.read2(0) - state.reg4[R_39]) + 0xf63fd264)
	state.reg4[R_39] += t
	state.chEIP(+0x16)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x25B] = ASM_0x25B


def ASM_0x2B6(state, log):
	iVar2 = U32(state.read2(0) + state.reg4[R_39] + state.reg4[R_a7])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] &= 0x5c6ae636
	state.reg2[R_8a] ^= iVar2 & 0xFFFF
	state.reg4[R_69] &= 0x5c2249b7
	state.reg4[R_39] &= (state.read4(2))
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] += 0x4634b8e7
	
	uVar1 = U32(((state.read2(8)) - state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] |= 0x27db827b
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x817e) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x80f1)
	state.VM_SUB_R_RM(log, r1, r2)
		 
	t = state.read2(6)
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2B6] = ASM_0x2B6


def ASM_0xB9(state, log):
	uVar7 = U32(state.read2(0) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar7
	state.reg4[R_69] += -0x36bb0977
	state.reg2[R_9d] ^= uVar7 & 0xFFFF
	state.reg4[R_2c] ^= 0x751c4f48
	
	r = (state.reg2[R_9d] ^ 0x5e5f) & 0xFFFF
	efl = state.read2(4)
	state.VM_ADD_R_V(log, r, 1, efl)
		
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] |= 0x1754c946
	
	state.reg4[R_39] |= (state.read4(6))
	
	t = U32(((state.read2(2)) - state.reg4[R_39]) ^ 0x7e506686)
	state.reg4[R_39] ^= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xB9] = ASM_0xB9


def ASM_0x26C(state, log):
	uVar8 = U32((state.read2(2)) ^ state.reg4[R_39])
	state.reg4[R_39] |= uVar8
	state.reg4[R_69] += -0x71fa2720
	state.reg2[R_8a] += uVar8 & 0xFFFF
	
	uVar8 = (state.read2(0xc)) ^ state.reg4[R_2c]
	state.reg4[R_39] ^= uVar8
	state.reg4[R_69] |= 0x4de2ffe
	state.reg2[R_9d] += uVar8 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xaffe) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xe161) & 0xFFFF
	efl = state.read2(0)
	state.VM_SUB_RM_R(log, r1, r2, efl)
	
	state.reg4[R_39] |= (state.read4(6))
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += -0x17e22db1

	state.reg4[R_69] |= 0x632dba2f
	state.reg4[R_2c] |= 0x632dba2f
	
	t = U32(((state.read2(10)) ^ state.reg4[R_39]) + 0xbbf039e2)
	state.reg4[R_39] |= t
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x26C] = ASM_0x26C


def ASM_0x20E(state, log):
	uVar1 = (state.read2(5))
	state.reg4[R_69] += 0x9d6a34
	state.reg4[R_2c] |= 0x19559735
	state.reg2[R_9d] += (uVar1 ^ state.reg2[R_39]) & 0xFFFF
	
	iVar3 = U32(state.read(4) + state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_69] ^= 0x391ad995
	state.reg4[R_8c] -= iVar3
	state.reg4[R_a7] -= iVar3
	state.reg4[R_69] += 0x552970b1
	
	r = state.reg2[R_9d]
	b = (state.reg4[R_8c] - 2) & 0xFF
	efl = state.read2(7)
	
	v = state.reg1[r]
	res = U32(v & b)
	log.append("VMR[{:02X}] = EFLAGS AND TEST b,VMR[{:02X}]({:02X}), {:02X} ({:02X})".format(efl, r, v, b, res))

	t = U32((state.read2(0) ^ 0x310254d6))
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x20E] = ASM_0x20E

def ASM_0x172(state, log):
	sVar3 = (state.read2(2))
	state.reg4[R_69] |= 0x3a140de2
	state.reg2[R_9d] += (sVar3 + state.reg2[R_39] + state.reg2[R_2c]) & 0xFFFF
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x3451529
	
	uVar6 = U32((state.read(8) - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_39] += uVar6
	state.reg4[R_69] += 0x6e3b9cab
	state.reg4[R_8c] -= uVar6
	state.reg4[R_a7] -= uVar6
	
	r = state.reg2[R_9d]
	v = (state.reg4[R_8c] ^ 0xbb) & 0xFF
	efl = (state.read2(9))
	state.VM_SUB_BR_B(log, r, v, efl)
	
	state.reg4[R_39] -= (state.read4(4))
	
	t = state.read2(0) ^ state.reg4[R_39]
	state.reg4[R_39] ^= t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x172] = ASM_0x172

def ASM_0x326(state, log):
	uVar1 = U32(((state.read2(4)) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] ^= uVar1
	state.reg2[R_8a] ^= uVar1 & 0xFFFF
	state.reg4[R_69] += -0xc3dcae0
	state.reg4[R_2c] |= 0x35b6bf0
	
	uVar1 = U32((state.read2(2)) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += -0x625d5d07
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	r1 = state.reg2[R_9d] ^ 0x5243
	r2 = (state.reg2[R_8a] + 0x5177) & 0xFFFF
	state.VM_XOR_BR_BR(log, r1, r2)
		 
	t = state.read2(0) ^ state.reg4[R_39]
	state.reg4[R_39] ^= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x326] = ASM_0x326


def ASM_0x394(state, log):
	uVar7 = U32((state.read2(2)) - state.reg4[R_a7])
	state.reg4[R_39] &= uVar7
	state.reg4[R_69] &= 0x6d05a349
	state.reg2[R_8a] -= uVar7 & 0xFFFF
	
	uVar7 = U32((state.read2(8)) + state.reg4[R_39])
	state.reg4[R_39] &= uVar7
	state.reg4[R_69] += 0x279bc4ee
	state.reg2[R_9d] -= uVar7 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x70ee) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x3177) & 0xFFFF
	efl = (state.read2(10))
	state.VM_SUB_RM_R(log, r1, r2, efl)
	
	state.reg4[R_2c] -= state.reg4[R_39]
	state.reg4[R_2c] |= 0x3402b51
	 
	t = U32(((state.read2(4)) - state.reg4[R_39]) ^ 0x38244860)
	state.reg4[R_39] |= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x394] = ASM_0x394


def ASM_0x2C(state, log):
	state.reg4[R_39] -= (state.read4(6))
	
	r1 = (state.read2(10))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	sVar3 = (state.read2(0xe))
	state.reg4[R_69] ^= 0x40c8aac2
	state.reg2[R_9d] -= (sVar3 - state.reg2[R_2c]) & 0xFFFF
	
	uVar7 = (state.read2(4)) ^ state.reg4[R_a7]
	state.reg4[R_39] |= uVar7
	state.reg4[R_69] += -0x4f28820a
	state.reg2[R_8a] -= uVar7 & 0xFFFF
	
	r1 = (state.reg2[R_9d] - 0xa2c) & 0xFFFF
	v1 = state.reg4[r1]
	
	r2 = (state.reg2[R_8a] + 0x7d5) & 0xFFFF
	adr = state.reg4[r2]
	v2 = state.rMem4(adr)
	
	efl = state.read2(0)

	res = U32(v1 - v2)
	log.append("VMR[{:02X}] = EFLAGS CMP TEST VMR[{:02X}]({:02X}), [VMR[{:02X}]]([{:02X}] {:02X}) ({:02X})".format(efl, r1, v1, r2, adr, v2, res))
	
	t = (state.read2(0xc))
	state.reg4[R_39] ^= t
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C] = ASM_0x2C


def ASM_0x3F1(state, log):
	uVar2 = U32((state.read2(10)) + state.reg4[R_39])
	state.reg4[R_39] &= uVar2
	state.reg2[R_9d] ^= uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x1f4e) & 0xFFFF
	state.VM_POP_RM(log, r1)
	
	r2 = state.read2(6)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
	
	t = state.read2(0) ^ state.reg4[R_39] ^ 0x553a96bd
	state.reg4[R_39] |= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3F1] = ASM_0x3F1


def ASM_0x36D(state, log):
	uVar6 = U32((state.read2(0) - state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] &= uVar6
	state.reg4[R_69] += 0x49f8646c
	state.reg2[R_9d] ^= uVar6 & 0xFFFF
	
	r = (state.reg2[R_9d] ^ 0x7dd1) & 0xFFFF
	efl = state.read2(2)
	state.VM_SUB_R_V(log, r, 1, efl)
	
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] &= 0x6cc9e56c
	
	t = U32(((state.read2(4)) - state.reg4[R_39]) + 0xedfdd64e)
	state.reg4[R_39] -= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x36D] = ASM_0x36D


def ASM_0x3C7(state, log):
	of = state.read2(4)
	
	r = state.read2(6)
	val = state.reg4[r]
	
	adr = state.esp + of
	state.wMem4(adr, val)
	log.append("#[esp+{:02X}h] = VMR[{:02X}] ({:02X})".format(of, r, val))
	
	val = state.read4(0) + state.reg4[R_ImgBase] 
	state.wMem4(adr + 4, val)
	log.append("#[esp+{:02X}h] = {:02X}".format(of + 4, val))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0x3C7] = ASM_0x3C7


def ASM_0x45A(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(6) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(6), uvar1))
	log.append(eflags)
	tp = state.read(8)
	op = JCC(tp)
	
	of = state.read2(4)
	val = state.read4(0) + state.reg4[R_ImgBase] 
	
	log.append(op + " TO:")
	log.append("\t#STACK set [esp + {:02X}] = {:02X}".format(of, val))
	if (of < 0x24 and of >= 0):
		state.wMem4(state.esp + of, val)
	
	log.append("\t#pop EDI {:02X}".format(state.pop()))
	log.append("\t#pop ESI {:02X}".format(state.pop()))
	log.append("\t#pop EBP {:02X}".format(state.pop()))
	log.append("\t#pop EBX {:02X}".format(state.pop()))
	log.append("\t#pop EDX {:02X}".format(state.pop()))
	log.append("\t#pop ECX {:02X}".format(state.pop()))
	log.append("\t#pop EAX {:02X}".format(state.pop()))
	log.append("\t#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append("\t;RET!  to {:02X}".format(state.pop()))
	
	if state.OnEnd:
		state.OnEnd(state, log)
	
	log.append("On Not:")
	
	r = state.read2(9)
	state.VM_ADD_R_V(log, r, 0x24)

	t = U32(state.read2(11))
	state.reg4[R_39] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x45A] = ASM_0x45A

def ASM_0x302(state, log):
	state.reg1[0x30] = 0
	
	uvar1 = state.reg4[ state.read2(6) ]
	eflags = EFLAGS(uvar1)
	log.append("EFLAGS TEST VMR[{:02X}]   ({:02X})".format(state.read2(6), uvar1))
	log.append(eflags)
	tp = state.read(8)
	op = JCC(tp)
	
	of = state.read2(4)
	val = state.read4(0) + state.reg4[R_ImgBase] 
	
	log.append(op + " TO:")
	log.append("\t#STACK set [esp + {:02X}] = {:02X}".format(of, val))
	if (of < 0x24 and of >= 0):
		state.wMem4(state.esp + of, val)
	
	log.append("\t#pop EDI {:02X}".format(state.pop()))
	log.append("\t#pop ESI {:02X}".format(state.pop()))
	log.append("\t#pop EBP {:02X}".format(state.pop()))
	log.append("\t#pop EBX {:02X}".format(state.pop()))
	log.append("\t#pop EDX {:02X}".format(state.pop()))
	log.append("\t#pop ECX {:02X}".format(state.pop()))
	log.append("\t#pop EAX {:02X}".format(state.pop()))
	log.append("\t#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append("\t;RET!  to {:02X}".format(state.pop()))
	
	if state.OnEnd:
		state.OnEnd(state, log)
	
	log.append("On Not:")
	
	r = state.read2(9)
	state.VM_ADD_R_V(log, r, 0x24)

	t = U32(state.read2(11) + state.reg4[R_39] + 0x48ababf)
	
	state.next = t & 0xFFFF
	state.chEIP(+13)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x302] = ASM_0x302


def ASM_0xFB(state, log):
	ImgBase = state.reg4[R_ImgBase]
	
	of = state.read2(0)
	ad1 = state.read4(2) + ImgBase
	
	adr = state.esp + of
	state.wMem4(adr, ad1)
	log.append("#[esp+{:02X}h] = {:02X}".format(of, ad1))
	
	log.append("#pop EDI {:02X}".format(state.pop()))
	log.append("#pop ESI {:02X}".format(state.pop()))
	log.append("#pop EBP {:02X}".format(state.pop()))
	log.append("#pop EBX {:02X}".format(state.pop()))
	log.append("#pop EDX {:02X}".format(state.pop()))
	log.append("#pop ECX {:02X}".format(state.pop()))
	log.append("#pop EAX {:02X}".format(state.pop()))
	log.append("#pop EFLAGS {:02X}".format(state.pop()))
	
	log.append(";RET!  {:02X}".format(state.pop()))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)
VMAsm[0xFB] = ASM_0xFB

def ASM_0x31E(state, log):
	uVar1 = U32(((state.read4(8)) ^ state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += -0x7ebbeb05
	state.reg4[R_8c] += uVar1
	state.reg4[R_a7] |= uVar1
	
	uVar1 = U32((state.read2(6)) + state.reg4[R_39])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += -0x2ece1c96
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	state.reg4[R_2c] -= state.reg4[R_39]
	state.reg4[R_39] &= 0x64e5b111
	
	r = state.reg2[R_9d]
	v = U32(state.reg4[R_8c] + 0xdb7980a9)
	state.VM_AND_R_V(log, r, v)
		 
	t = (state.read2(2)) ^ 0x50f25275
	state.reg4[R_39] += t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x31E] = ASM_0x31E

def ASM_0x492(state, log):
	uVar1 = (state.read2(6))
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] &= 0x7fea2ae5
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	uVar2 = U32((state.read4(2)) - state.reg4[R_69])
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] += -0x7e6ae97a
	state.reg4[R_8c] ^= uVar2
	state.reg4[R_a7] += uVar2
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0x68ff79b2
	
	r = (state.reg2[R_9d] ^ 0x1093) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0x88b40b92)
	state.VM_OR_R_V(log, r, v)

	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] |= 0x224a5180
	
	state.reg4[R_2c] |= state.reg4[R_39]
	
	t = U32(state.read2(0) + state.reg4[R_39] + 0x6d56e7ef)
	state.reg4[R_39] ^= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x492] = ASM_0x492


def ASM_0x346(state, log):
	state.reg4[R_39] &= 0x7639bfba
	uVar2 = U32((state.read4(10)) - state.reg4[R_69])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] &= 0x1b8f0f76
	state.reg4[R_8c] ^= uVar2
	state.reg4[R_a7] ^= uVar2
	
	iVar1 = U32(((state.read2(8)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] -= iVar1
	state.reg4[R_69] += 0x6cdaeca2
	state.reg2[R_9d] -= iVar1 & 0xFFFF
	
	r = (state.reg2[R_9d] ^ 0x6fc3) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0xa1ce83b3)
	state.VM_AND_R_V(log, r, v)
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0x4874c0e8)
	state.reg4[R_39] -= t
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x346] = ASM_0x346

def ASM_0x4F6(state, log):
	uVar2 = U32(((state.read2(2)) - state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] += -0x2debeff5
	state.reg2[R_8a] += uVar2 & 0xFFFF
	
	sVar1 = (state.read2(4))
	state.reg4[R_69] &= 0x5afe174
	state.reg2[R_9d] -= (sVar1 - state.reg4[R_2c]) & 0xFFFF
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] |= 0x1ede54b6
	
	r1 = (state.reg2[R_9d] ^ 0x7986) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x29aa) & 0xFFFF
	state.VM_ASGN_WR_BR(log, r1, r2)
		 
	t = U32(state.read2(0) + state.reg4[R_39] + 0xeb2de053)
	state.reg4[R_39] |= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F6] = ASM_0x4F6


def ASM_0x14D(state, log):
	uVar1 = U32(((state.read2(2)) + state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] &= uVar1
	state.reg2[R_8a] -= uVar1 & 0xFFFF
	
	uVar1 = U32((state.read2(6)) ^ state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] |= 0x3a06d402
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = (state.reg2[R_8a] ^ 0xc920) & 0xFFFF
	state.VM_ASGN_R_WR(log, r1, r2)
		 
	t = state.read2(0) ^ 0x42e28149
	state.reg4[R_39] ^= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x14D] = ASM_0x14D

def ASM_0x483(state, log):
	r1 = (state.read2(0xc))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar10 = U32(((state.read2(10)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar10
	state.reg4[R_69] += -0x3e8fc77f
	state.reg2[R_9d] ^= uVar10 & 0xFFFF
	
	uVar10 = (state.read2(4)) ^ state.reg4[R_a7]
	state.reg4[R_39] += uVar10
	state.reg4[R_69] ^= 0x72bba967
	state.reg2[R_8a] -= uVar10 & 0xFFFF
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] &= 0x34d6e0a
	
	r1 = (state.reg2[R_9d] ^ 0xdb) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x9975) & 0xFFFF
	efl = (state.read2(8))
	state.VM_SUB_WR_WR(log, r1, r2, efl)

	state.reg4[R_2c] -= state.reg4[R_39]
	
	t = U32(((state.read2(6)) ^ state.reg4[R_39]) + 0x96b05346)
	state.reg4[R_39] ^= t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x483] = ASM_0x483


def ASM_0x38D(state, log):
	state.reg4[R_2c] |= 0x5c1a57e9
	
	r1 = (state.read2(6))
	r2 = (state.read2(8))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar4 = U32(state.read4(0) + state.reg4[R_69])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] ^= 0x7b5e25db
	state.reg4[R_8c] += uVar4
	state.reg4[R_a7] -= uVar4
	
	iVar3 = U32((state.read2(4)) + state.reg4[R_2c])
	state.reg4[R_39] += iVar3
	state.reg4[R_69] += 0x7882b7ab
	state.reg2[R_9d] ^= iVar3 & 0xFFFF
	
	t = U32(((state.read2(10)) + state.reg4[R_39]) ^ 0x4b5c6ad0)
	state.reg4[R_39] += t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x38D] = ASM_0x38D


def ASM_0x2E7(state, log):
	state.reg4[R_a7] += -0x1dfee3c
	
	r1 = (state.read2(2))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar9 = U32((state.read(8) + state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] += iVar9
	state.reg4[R_69] += -0x7e63b921
	state.reg4[R_8c] -= iVar9
	
	sVar4 = state.read2(0)
	state.reg4[R_69] += 0x59fecfa0
	state.reg2[R_9d] -= ((sVar4 + state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	
	v = state.reg4[R_8c] ^ 0xd1e80ea
	r = state.reg2[R_9d]
	efl = state.read2(6)
	state.VM_LSH_BR_V(log, r, v, efl)
	
	state.reg4[R_2c] ^= state.reg4[R_39]
	
	t = U32(((state.read2(9)) - state.reg4[R_39]) + 0x8474150)
	state.reg4[R_39] &= t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2E7] = ASM_0x2E7


def ASM_0xF7(state, log):
	r1 = (state.read2(6))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar4 = U32((state.read(10) ^ state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_39] |= uVar4
	state.reg4[R_8c] += uVar4
	state.reg4[R_a7] &= uVar4
	
	uVar4 = U32(((state.read2(8)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] |= 0x765f5361
	state.reg2[R_9d] += uVar4 & 0xFFFF
	state.reg4[R_69] += 0x3965e2ec
	
	b = (state.reg4[R_8c] ^ 0x41) & 0xFF
	r = (state.reg2[R_9d] + 0x30a5) & 0xFFFF
	
	efl = state.read2(0)
	
	v = state.reg1[r]
	res = U32(v & b)
	log.append("VMR[{:02X}] = EFLAGS AND TEST b,VMR[{:02X}]({:02X}), {:02X} ({:02X})".format(efl, r, v, b, res))
	
	state.reg4[R_39] &= 0x51d4dbfb
	
	t = U32((state.read2(2)) + state.reg4[R_39] + 0x5b6d8169)
	state.reg4[R_39] ^= t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xF7] = ASM_0xF7


def ASM_0x2EF(state, log):
	uVar1 = U32((state.read2(3)) + state.reg4[R_39] + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] |= 0x23c08321
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	uVar1 = U32((state.read(2) ^ state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_39] &= uVar1
	state.reg4[R_8c] -= uVar1
	state.reg4[R_a7] |= uVar1
	
	r = (state.reg2[R_9d] + 0xd49c) & 0xFFFF
	b = (state.reg4[R_8c] - 0x10) & 0xFF
	state.VM_XOR_BR_B(log, r, b)
	
	t = U32(state.read2(0) ^ state.reg4[R_39] ^ 0x2dbd3792)
	state.reg4[R_39] ^= t
	state.chEIP(+5)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2EF] = ASM_0x2EF


def ASM_0x222(state, log):
	state.reg4[R_69] &= 0x393fc3a
	
	uVar2 = U32((state.read2(0) + state.reg4[R_39]) ^ state.reg4[R_2c])
	state.reg4[R_39] -= uVar2
	state.reg4[R_69] |= 0xad4731b
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] ^ 0xc433) & 0xFFFF
	state.VM_POP_RM(log, r1)
	
	r2 = state.read2(4)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
	
	t = U32((state.read2(2) - state.reg4[R_39]) ^ 0x782409b4)
	state.reg4[R_39] += t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x222] = ASM_0x222


def ASM_0x22(state, log):
	r1 = (state.read2(2))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = U32((state.read2(0xc)) ^ state.reg4[R_39] ^ state.reg4[R_a7])
	state.reg4[R_39] += uVar3
	state.reg4[R_69] |= 0x9dce044
	state.reg2[R_8a] ^= uVar3 & 0xFFFF
	
	uVar3 = U32(((state.read2(4)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] &= 0x7da02430
	state.reg2[R_9d] += uVar3 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] ^= 0x2535872a
	
	t = U32((state.read2(8)) + 0xbfe23956)
	state.reg4[R_39] -= t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x22] = ASM_0x22


def ASM_0x140(state, log):
	iVar2 = U32((state.read2(6)) + state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] |= 0x673de787
	state.reg2[R_9d] += iVar2 & 0xFFFF
	
	uVar1 = U32(state.read4(0) ^ state.reg4[R_39] ^ state.reg4[R_69])
	state.reg4[R_39] += uVar1
	state.reg4[R_69] ^= 0x4ca9e2a6
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] |= uVar1
	
	v = state.reg4[R_8c] ^ 0x67e6e4c3
	r = (state.reg2[R_9d] ^ 0xbb21) & 0xFFFF
	state.VM_ASGN_RM_V(log, r, v)
	
	t = U32(((state.read2(4)) - state.reg4[R_39]) + 0xd077ce3a)
	state.reg4[R_39] |= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x140] = ASM_0x140

def ASM_0x3EB(state, log):
	r1 = (state.read2(0x12))
	r2 = (state.read2(8))
	state.VM_XCHG_R_R(log, r1, r2)

	uVar3 = U32((state.read4(2) + state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_39] -= uVar3
	state.reg4[R_69] += -0xf2298da
	state.reg4[R_8c] ^= uVar3
	state.reg4[R_a7] &= uVar3
	
	uVar3 = U32((state.read2(6)) ^ state.reg4[R_39])
	state.reg4[R_39] ^= uVar3
	state.reg4[R_69] &= 0x1ac8790f
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	state.reg4[R_39] |= 0x601d817f
	state.reg4[R_69] |= 0x583906c3
	state.reg4[R_39] += (state.read4(0xe))
	
	v = U32(state.reg4[R_8c] + -0x2284ce26)
	r = (state.reg2[R_9d] + 0x5d03) & 0xFFFF
	
	state.VM_ASGN_RM_V(log, r, v)	
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0x3ce40f92
	
	t = state.read2(0) ^ 0x2aeabcb8
	state.reg4[R_39] -= t
	state.chEIP(+0x14)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3EB] = ASM_0x3EB


def ASM_0x22B(state, log):
	sVar1 = (state.read2(2))
	state.reg4[R_69] += -0x268f4838
	state.reg2[R_9d] -= (sVar1 - state.reg4[R_39]) & 0xFFFF
	
	sVar1 = (state.read2(4))
	state.reg4[R_69] &= 0x713a1a6
	state.reg2[R_8a] -= ((sVar1 + state.reg2[R_39]) ^ state.reg2[R_a7]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xa35d) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xee53) & 0xFFFF
	state.VM_XCHG_R_R(log, r1, r2)
	
	t = state.read2(0)
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x22B] = ASM_0x22B


def ASM_0x4A(state, log):
	r1 = (state.read2(2))
	r2 = (state.read2(0xc))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar3 = U32((state.read2(0xe)) + state.reg4[R_39] + state.reg4[R_a7])
	state.reg4[R_39] -= iVar3
	state.reg4[R_69] &= 0x3019a83d
	state.reg2[R_8a] += iVar3 & 0xFFFF
	
	uVar4 = U32(((state.read2(8)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar4
	state.reg4[R_69] |= 0x135f135
	state.reg2[R_9d] -= uVar4 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] &= 0x1488b772
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += -0x7dd6274e
	
	r1 = (state.reg2[R_9d] + 0xc3cb) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x6199) & 0xFFFF
	state.VM_XOR_R_RM(log, r1, r2)
	
	t = U32((state.read2(6)) + 0x99ebb28e)
	state.chEIP(+0x10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4A] = ASM_0x4A


def ASM_0x301(state, log):
	sVar1 = (state.read2(10))
	state.reg4[R_69] ^= 0x1eec6abf
	state.reg2[R_8a] ^= ((sVar1 - state.reg2[R_39]) + state.reg2[R_a7]) & 0xFFFF
	
	uVar2 = U32(state.read2(0) - state.reg4[R_39])
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] += 0x2d27c0e2
	state.reg2[R_9d] ^= uVar2 & 0xFFFF
	state.reg4[R_39] += (state.read4(6))
	
	r1 = (state.reg2[R_9d] + 0x19c1) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_XOR_RM_R(log, r1, r2)
	
	t = U32(((state.read2(4)) ^ state.reg4[R_39]) + 0x296448c5)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x301] = ASM_0x301


def ASM_0x3A3(state, log):
	uVar1 = U32((state.read2(0) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] &= 0x2e5bac04
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	uVar1 = U32(((state.read4(6)) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += -0x6d100bb9
	state.reg4[R_8c] -= uVar1
	state.reg4[R_a7] &= uVar1
	state.reg4[R_39] |= 0x757d8dcd
	state.reg4[R_39] |= 0x4f3742da
	state.reg4[R_69] += -0x31f0fefe
	
	v = U32(state.reg4[R_8c] + 0x2a9c216c)
	r = (state.reg2[R_9d] ^ 0xeebe) & 0xFFFF
	state.VM_ASGN_RM_V(log, r, v)
	
	t = (state.read2(4)) ^ state.reg4[R_39]
	state.reg4[R_39] &= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A3] = ASM_0x3A3


def ASM_0x89(state, log):
	state.reg4[R_2c] += state.reg4[R_39]
	
	uVar2 = U32(state.read2(4) - state.reg4[R_39])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] |= 0x2185ae01
	state.reg2[R_8a] -= uVar2 & 0xFFFF
	
	sVar1 = (state.read2(2))
	state.reg4[R_69] += -0x3a79b75f
	state.reg2[R_9d] += (sVar1 - state.reg2[R_2c]) & 0xFFFF
	state.reg4[R_69] += -0x77bb25a9
	
	r1 = (state.reg2[R_9d] + 0xd8b) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x75e4) & 0xFFFF
	state.VM_SUB_R_RM(log, r1, r2)
		 
	state.reg4[R_39] += 0x5b36a4ec
	state.reg4[R_2c] += 0x5b36a4ec
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0xd65ab7e2)
	state.reg4[R_39] &= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x89] = ASM_0x89


def ASM_0x406(state, log):
	state.reg4[R_2c] &= 0x348dcd39
	
	uVar2 = U32(((state.read2(2)) ^ state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] &= 0x348dcd39
	state.reg2[R_8a] += uVar2 & 0xFFFF
	
	iVar1 = U32(((state.read2(8)) + state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar1
	state.reg2[R_9d] += iVar1 & 0xFFFF
	state.reg4[R_39] |= 0xd4b8b74
	state.reg4[R_69] += 0x4415d836
	
	r1 = (state.reg2[R_9d] + 0xaee8) & 0xFFFF
	r2 = state.reg2[R_8a]
	efl = state.read2(0)
	state.VM_AND_WR_WR(log, r1, r2, efl)
	
	t = U32((state.read2(10) + state.reg4[R_39]) ^ 0x3a9995c3)
	state.reg4[R_39] &= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x406] = ASM_0x406


def ASM_0x350(state, log):
	iVar2 = U32(state.read(0) - state.reg4[R_69])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] += 0x31f23b3a
	state.reg4[R_8c] -= iVar2
	state.reg4[R_a7] += iVar2
	
	uVar3 = U32(((state.read2(1)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar3
	state.reg4[R_69] ^= 0x370c1f6d
	state.reg2[R_9d] += uVar3 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] &= 0x15a03d26
	
	b = (state.reg4[R_8c] + 0x2e) & 0xFF
	r = (state.reg2[R_9d] ^ 0x8984) & 0xFFFF
	state.VM_XOR_BR_B(log, r, b)
	
	t = (state.read2(3))
	state.reg4[R_39] -= t
	state.chEIP(+5)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x350] = ASM_0x350

def ASM_0x4F(state, log):
	state.reg4[R_2c] ^= 0x7b076eb2
	
	iVar2 = U32(((state.read2(7)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] += 0x35ec50ca
	state.reg2[R_9d] += iVar2 & 0xFFFF
	state.reg4[R_2c] += 0x26db8a63
	
	uVar1 = U32(state.read(2) + state.reg4[R_39])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += 0x44bb1d6c
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] &= uVar1
	
	t = U32(state.read2(0) + 0xb8960797)
	state.reg4[R_39] ^= t
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F] = ASM_0x4F


def ASM_0x3F9(state, log):
	uVar2 = state.read2(0) ^ state.reg4[R_2c]
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] += -0x2b7c144f
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x69f6) & 0xFFFF
	efl = state.read2(4)
	state.VM_SUB_RM_V(log, r, 1, efl)
	
	t = U32((state.read2(2)) + 0xa8fd674d)
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3F9] = ASM_0x3F9


def ASM_0x42D(state, log):
	uVar2 = U32((state.read2(4)) + state.reg4[R_39])
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] += 0xaad6e82
	state.reg2[R_9d] -= uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] - 0x14c) & 0xFFFF
	state.VM_POP_RM(log, r1)
	
	r2 = state.read2(6)
	if (r1 != r2):
		state.VM_ADD_R_V(log, r2, 4)
				
	state.reg4[R_a7] |= state.reg4[R_69]
	
	t = U32((state.read2(2) - state.reg4[R_39]) ^ 0x68884a9b)
	state.reg4[R_39] ^= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x42D] = ASM_0x42D


def ASM_0x2E9(state, log):
	r1 = (state.read2(8))
	r2 = (state.read2(10))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar6 = U32((state.read2(2)) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar6
	state.reg4[R_69] |= 0x6bed534a
	state.reg2[R_9d] += uVar6 & 0xFFFF
	
	uVar6 = U32(((state.read2(4)) ^ state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] &= uVar6
	state.reg4[R_69] += 0x2fe964cf
	state.reg2[R_8a] -= uVar6 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	adr = state.reg4[r1]
	v1 = state.rMem4(adr)
	r2 = (state.reg2[R_8a] + 0x1db5) & 0xFFFF
	v2 = state.reg4[r2]
	efl = state.read2(0)
	log.append("VMR[{:02X}] = CMP [VMR[{:02X}]]([{:02X}] -> {:02X}), VMR[{:02X}]({:02X})".format(efl, r1, adr, v1, r2, v2))
		
	uVar4 = state.reg4[R_69]
	state.reg4[R_a7] &= uVar4
	state.reg4[R_a7] += 0x57531ad2
	state.reg4[R_2c] &= state.reg4[R_39]
	
	t = U32(((state.read2(6)) ^ state.reg4[R_39]) + 0xbafa58ea)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2E9] = ASM_0x2E9


def ASM_0x2CD(state, log):
	r1 = (state.read2(0x10))
	r2 = (state.read2(0x12))
	state.VM_XCHG_R_R(log, r1, r2)
	
	r1 = (state.read2(0xc))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar3 = (state.read4(4))
	iVar4 = state.reg4[R_69]
	state.reg4[R_69] &= 0x792362ca
	state.reg4[R_8c] += U32((iVar3 - state.reg4[R_39]) - iVar4)
	
	uVar6 = U32((state.read2(8)) ^ state.reg4[R_39] ^ state.reg4[R_2c])
	state.reg4[R_39] += uVar6
	state.reg4[R_69] ^= 0x3e2003f7
	state.reg2[R_9d] += uVar6 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x6df1) & 0xFFFF
	v = U32(state.reg4[R_8c] + 0x3db3268a)
	efl = state.read2(10)
	state.VM_XOR_RM_V(log, r, v, efl)
	
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] += 0x4962a352
	
	t = U32(state.read2(0) + state.reg4[R_39] + 0x53fd9985)
	state.reg4[R_39] += t
	state.chEIP(+0x16)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2CD] = ASM_0x2CD


def ASM_0x487(state, log):
	r1 = (state.read2(6))
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = state.read2(0) ^ state.reg4[R_2c]
	state.reg4[R_39] -= uVar3
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x5e0e) & 0xFFFF
	efl = state.read2(2)
	state.VM_NEG_R(log, r, efl)
	
	t = U32((state.read2(8)) + state.reg4[R_39] + 0x21fb9b1)
	state.reg4[R_39] -= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x487] = ASM_0x487


def ASM_0x31C(state, log):
	uVar1 = (state.read2(2)) ^ state.reg4[R_a7]
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] += 0x7a0629d1
	state.reg2[R_8a] -= uVar1 & 0xFFFF
	state.reg4[R_39] += -0xfac98a8
	state.reg4[R_69] ^= 0x29daed0
	state.reg4[R_69] += 0x126c0f84
	
	uVar1 = U32(((state.read2(4)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] += -0x564e3673
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	r2 = (state.reg2[R_8a] + 0x7799) & 0xFFFF
	r1 = state.reg2[R_9d]
	state.VM_SUB_R_RM(log, r1, r2)
	
	t = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] -= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x31C] = ASM_0x31C


def ASM_0x71(state, log):
	state.reg2[R_9d] += (((state.read2(4)) - state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
	
	sVar1 = (state.read2(2))
	state.reg4[R_69] &= 0x4e94ba8f
	state.reg2[R_8a] -= ((sVar1 - state.reg2[R_39]) + state.reg2[R_a7]) & 0xFFFF
	state.reg4[R_2c] += state.reg4[R_39]
	state.reg4[R_a7] += state.reg4[R_69]
	state.reg4[R_a7] |= 0x2f3db851
	state.reg4[R_39] ^= 0x1937aa3c
	
	r1 = (state.reg2[R_9d] ^ 0xb248) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_AND_WR_WR(log, r1, r2)
	
	t = U32(state.read2(0) + 0xaf55d3ba)
	state.reg4[R_39] ^= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x71] = ASM_0x71

def ASM_0x217(state, log):
	uVar2 = U32((state.read2(8) + state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] |= uVar2
	state.reg2[R_8a] ^= uVar2 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0x5128afea
	
	uVar2 = (state.read2(2)) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] |= uVar2
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x184) & 0xFFFF
	r2 = state.reg2[R_8a]
	efl = state.read2(4)
	state.VM_XOR_RM_R(log, r1, r2, efl)
	
	t = U32(state.read2(6) + 0xa737f5d8)
	state.reg4[R_39] ^= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x217] = ASM_0x217



def ASM_0x4BE(state, log):
	uVar2 = U32(((state.read2(8)) + state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] ^= uVar2
	state.reg4[R_69] |= 0x4bfa6a2c
	state.reg2[R_8a] += uVar2 & 0xFFFF
	
	uVar1 = (state.read2(2))
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] &= 0x3bd9dec0
	state.reg2[R_9d] += uVar1
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	state.VM_XOR_R_RM(log, r1, r2)
	
	t = U32((state.read2(0xc) - state.reg4[R_39]) ^ 0xc0f615f)
	state.reg4[R_39] += t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4BE] = ASM_0x4BE


def ASM_0x453(state, log):
	uVar3 = U32(((state.read2(2)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] += 0x319f00a0
	state.reg2[R_9d] -= uVar3 & 0xFFFF
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] += 0x50a326da
	
	iVar2 = U32((state.read2(4)) + state.reg4[R_39])
	state.reg4[R_39] -= iVar2
	state.reg2[R_8a] -= iVar2 & 0xFFFF
	state.reg4[R_69] ^= 0x79df6304
	
	r2 = (state.reg2[R_8a] + 0xa5f) & 0xFFFF
	r1 = state.reg2[R_9d]
	state.VM_XOR_R_RM(log, r1, r2)
	
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0x41152665)
	state.reg4[R_39] ^= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x453] = ASM_0x453


def ASM_0x2DD(state, log):
	uVar1 = U32(((state.read2(4)) + state.reg4[R_39]) - state.reg4[R_a7])
	state.reg4[R_39] |= uVar1
	state.reg2[R_8a] -= uVar1 & 0xFFFF
	state.reg4[R_69] += -0x1666b3a2
	
	uVar1 = (state.read2(2)) ^ state.reg4[R_2c]
	state.reg4[R_39] += uVar1
	state.reg4[R_69] += 0x90f1c85
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	state.reg4[R_39] += (state.read4(6))
	
	r1 = (state.reg2[R_9d] + 0x12cd) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0xb837) & 0xFFFF
	state.VM_XOR_R_R(log, r1, r2)
		 
	t = state.read2(0) ^ state.reg4[R_39] ^ 0x83dc614
	state.reg4[R_39] |= t
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2DD] = ASM_0x2DD


def ASM_0x3F(state, log):
	state.reg4[R_39] += 0xc244407
	state.reg4[R_69] |= 0x6802d770
	
	iVar2 = U32(((state.read2(4)) - state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] += -0x1b24708a
	state.reg2[R_9d] -= iVar2 & 0xFFFF
	
	uVar1 = (state.read2(2))
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] += -0x3bec4c06
	state.reg2[R_8a] += uVar1
	
	r1 = (state.reg2[R_9d] ^ 0x68e2) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x40c3) & 0xFFFF
	state.VM_ASGN_BR_BR(log, r1, r2)	
	
	t = U32(state.read2(0) - state.reg4[R_39])
	state.reg4[R_39] += t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3F] = ASM_0x3F


def ASM_0x20(state, log):
	iVar2 = U32((state.read2(3)) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar2
	state.reg4[R_69] += 0x478af7e
	state.reg2[R_9d] += iVar2 & 0xFFFF
	
	uVar1 = U32((state.read(2) - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_39] += uVar1
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] |= uVar1
	
	r = (state.reg2[R_9d] ^ 0x7001) & 0xFFFF
	b = (state.reg1[R_8c] + 0x69) & 0xFF
	state.VM_SUB_BR_B(log, r, b)
	
	t = U32(state.read2(0) + 0xa3821e2e)
	state.reg4[R_39] -= t
	state.chEIP(+5)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x20] = ASM_0x20


def ASM_0x2B7(state, log):
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] ^= 0xf85f664
	
	uVar1 = U32(state.read2(0) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	uVar1 = U32((state.read(6) - state.reg4[R_39]) - state.reg4[R_69])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] ^= 0x5d6597a
	state.reg4[R_8c] += uVar1
	state.reg4[R_a7] |= uVar1
	
	r = (state.reg2[R_9d] ^ 0xe793) & 0xFFFF
	b = (state.reg1[R_8c] ^ 0x8c)
	efl = (state.read2(4))
	state.VM_XOR_BR_B(log, r, b, efl)
	
	state.reg4[R_2c] += -0xa725eb2
	t = U32((state.read2(2)) + state.reg4[R_39] + 0x50f8a8c5)
	state.reg4[R_39] ^= t
	state.chEIP(+7)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2B7] = ASM_0x2B7


def ASM_0x479(state, log):
	r1 = (state.read2(7))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar4 = state.read(6) ^ state.reg4[R_69]
	state.reg4[R_39] -= uVar4
	state.reg4[R_69] ^= 0x41f3eeaa
	state.reg4[R_8c] += uVar4
	state.reg4[R_a7] &= uVar4
	
	uVar4 = U32(((state.read2(2)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar4
	state.reg4[R_69] |= 0x49351c45
	state.reg2[R_9d] += uVar4 & 0xFFFF
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_2c] += -0x14aae144
	state.reg4[R_a7] += -0x14aae144
	
	efl = state.read2(4)
	r = (state.reg2[R_9d] + 0x4a55) & 0xFFFF
	v = (state.reg1[R_8c] ^ 0x29)
	state.VM_AND_BR_B(log, r, v, efl)
	
	t = U32((state.read2(9)) + state.reg4[R_39] + 0xee17d532)
	state.reg4[R_39] &= t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x479] = ASM_0x479


def ASM_0x464(state, log):
	uVar2 = U32((state.read2(7)) - state.reg4[R_2c])
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] &= 0x66ea283a
	state.reg2[R_9d] += uVar2 & 0xFFFF
	
	uVar2 = U32(state.read(6) + state.reg4[R_39] + state.reg4[R_69])
	state.reg4[R_39] -= uVar2
	state.reg4[R_69] &= 0x5780d8ad
	state.reg4[R_8c] ^= uVar2
	
	r = (state.reg2[R_9d] + 0x156f) & 0xFFFF
	b = state.reg1[R_8c] ^ 0xe1
	efl = state.read2(2)
	state.VM_XOR_BR_B(log, r, b, efl)
	
	t = (state.read2(4))
	state.reg4[R_39] -= t
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x464] = ASM_0x464

def ASM_0xCE(state, log):
	uVar1 = U32(((state.read2(2)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] |= 0x4e6d86c0
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += -0x3739ab02
	
	r = (state.reg2[R_9d] + 0xedd6) & 0xFFFF
	state.VM_NEG_R(log, r)
	
	state.reg4[R_2c] += 0x3c9d0f5a
	
	t = U32((state.read2(0) + state.reg4[R_39]) ^ 0x1264da90)
	state.reg4[R_39] &= t
	state.chEIP(+4)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xCE] = ASM_0xCE


def ASM_0x2C2(state, log):
	state.reg4[R_39] += 0x5d86e222
	
	uVar1 = U32((state.read2(4)) + state.reg4[R_39] + state.reg4[R_2c])
	state.reg4[R_39] ^= uVar1
	state.reg4[R_69] |= 0x70b2f708
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	state.reg4[R_a7] |= state.reg4[R_69]
	
	r = (state.reg2[R_9d] + 0x7a5f) & 0xFFFF
	state.VM_NOT_RM(log, r)
		 
	state.reg4[R_a7] |= 0x6f23a521
	
	t = U32(((state.read2(2)) - state.reg4[R_39]) ^ 0x3f6992ba)
	state.reg4[R_39] -= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C2] = ASM_0x2C2


def ASM_0x13A(state, log):
	uVar1 = U32(((state.read2(8)) ^ state.reg4[R_39]) + state.reg4[R_a7])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] &= 0x78ce9df
	state.reg2[R_8a] ^= uVar1 & 0xFFFF
	
	iVar2 = U32(state.read2(0) + state.reg4[R_39])
	state.reg4[R_39] += iVar2
	state.reg4[R_69] &= 0x3dc56b1a
	state.reg2[R_9d] += iVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] ^ 0xb013) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0xe83) & 0xFFFF
	state.VM_ASGN_WRM_WR(log, r1, r2)
	
	t = U32(((state.read2(2)) ^ state.reg4[R_39]) + 0xd7c6a2e4)
	state.chEIP(+10)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x13A] = ASM_0x13A


def ASM_0x126(state, log):
	uVar1 = (state.read2(2)) ^ state.reg4[R_69]
	state.reg4[R_39] += uVar1
	state.reg4[R_69] |= 0x369c3c1f
	state.reg4[R_8c] += uVar1
	
	uVar1 = U32((state.read2(4)) + state.reg4[R_39])
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] &= 0x2cfd858d
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	state.reg4[R_2c] += state.reg4[R_39]
	
	r = state.reg2[R_9d]
	w = state.reg2[R_8c]
	state.VM_ASGN_WRM_W(log, r, w)
	
	t = U32((state.read2(0) + state.reg4[R_39]) ^ 0x3e479cb8)
	state.reg4[R_39] -= t
	state.chEIP(+8)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x126] = ASM_0x126

def ASM_0x2AE(state, log):
	r1 = (state.read2(10))
	r2 = (state.read2(2))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = (state.read2(8)) ^ state.reg4[R_39] ^ state.reg4[R_a7]
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] |= 0x4035ada5
	state.reg2[R_8a] += uVar3 & 0xFFFF
	
	uVar1 = state.read2(0)
	state.reg4[R_69] += -0x335889aa
	state.reg2[R_9d] ^= ((uVar1 ^ state.reg2[R_39]) + state.reg2[R_2c]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x95ef) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xe87d) & 0xFFFF
	state.VM_AND_R_R(log, r1, r2)
	
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] |= 0x54898150
	t = U32(((state.read2(4)) - state.reg4[R_39]) + 0xce02f855)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2AE] = ASM_0x2AE


def ASM_0x432(state, log):
	uVar1 = (state.read2(4))
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] ^= 0x1b896c5b
	state.reg2[R_8a] -= uVar1
	
	uVar3 = U32(((state.read2(10)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar3
	state.reg4[R_69] ^= 0x74d1498d
	state.reg2[R_9d] ^= uVar3 & 0xFFFF
	
	r1 = state.reg2[R_9d]
	r2 = state.reg2[R_8a]
	efl = state.read2(2)
	state.VM_AND_WR_WR(log, r1, r2, efl)
	
	t = (state.read2(8)) ^ 0x337233ae
	state.reg4[R_39] += t
	state.chEIP(+0xe)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x432] = ASM_0x432


def ASM_0x3C9(state, log):
	uVar1 = (state.read2(2)) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] -= uVar1
	state.reg4[R_69] += 0x3ac1d997
	state.reg2[R_9d] += uVar1 & 0xFFFF
	
	r = state.reg2[R_9d]
	state.VM_NOT_RM(log, r)
	
	state.reg4[R_39] |= 0x4f0fbf3f
	
	t = U32((state.read2(0) - state.reg4[R_39]) ^ 0x284cb7fe)
	state.reg4[R_39] &= t
	state.chEIP(+4)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3C9] = ASM_0x3C9


def ASM_0x375(state, log):
	r1 = state.read2(0)
	r2 = (state.read2(4))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar3 = state.read(6) ^ state.reg4[R_39]
	state.reg4[R_39] += uVar3
	state.reg4[R_69] &= 0x7e012785
	state.reg4[R_8c] ^= uVar3
	state.reg4[R_a7] -= uVar3
	state.reg4[R_39] += 0x45893de7
	
	uVar1 = (state.read2(7))
	state.reg4[R_39] |= uVar1
	state.reg4[R_69] |= 0x3fb2bc67
	state.reg2[R_9d] ^= uVar1
	
	r = (state.reg2[R_9d] + 0xb60e) & 0xFFFF
	b = state.reg1[R_8c]
	state.VM_ASGN_BR_B(log, r, b)
	
	t = U32((state.read2(2)) - state.reg4[R_39])
	state.chEIP(+9)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x375] = ASM_0x375


def ASM_0x2CC(state, log):
	r1 = (state.read2(9))
	r2 = (state.read2(0xb))
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar11 = state.read(2) + state.reg4[R_69]
	state.reg4[R_39] += uVar11
	state.reg4[R_69] &= 0x20c90201
	state.reg4[R_8c] += uVar11
	state.reg4[R_a7] &= uVar11
	state.reg4[R_69] |= 0x3b77d6c7
	
	sVar7 = state.read2(0)
	state.reg4[R_69] ^= 0x4a059ea1
	state.reg2[R_9d] ^= ((sVar7 + state.reg2[R_39]) - state.reg2[R_2c]) & 0xFFFF
		
	b = (state.reg4[R_8c] + 3) & 0xFF
	r = (state.reg2[R_9d] + 0x6bde) & 0xFFFF
	efl = (state.read2(0xd))
	state.VM_ADD_BR_B(log, r, b, efl)
	
	state.reg4[R_a7] &= state.reg4[R_69]
	
	t = (state.read2(7)) ^ 0x7402b2b
	state.reg4[R_39] += t
	state.chEIP(+0xf)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2CC] = ASM_0x2CC


def ASM_0xBF(state, log):
	uVar1 = U32((state.read(4) - state.reg4[R_39]) + state.reg4[R_69])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] ^= 0x235d93df
	state.reg4[R_8c] ^= uVar1
	state.reg4[R_a7] += uVar1
	state.reg4[R_39] += -0x30482c64
	state.reg4[R_69] |= 0x5c1a8f53
	state.reg4[R_69] += -0x1d638654
	state.reg4[R_39] += -0x37732ed9
	state.reg4[R_69] ^= 0x1546bf5d
	
	uVar1 = U32(((state.read2(2)) - state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] |= 0x736c010d
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	r = (state.reg2[R_9d] + 0x2770) & 0xFFFF
	v = state.reg4[R_8c]
	state.VM_LSH_BR_V(log, r, v)
	
	t = U32((state.read2(5)) + 0x13e7d442)
	state.reg4[R_39] += t
	state.chEIP(+0xb)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xBF] = ASM_0xBF


def ASM_0x109(state, log):
	uVar1 = U32((state.read2(4)) + state.reg4[R_2c])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += -0x52369a04
	state.reg2[R_9d] ^= uVar1 & 0xFFFF
	
	uVar1 = U32((state.read2(2)) - state.reg4[R_a7])
	state.reg4[R_39] &= uVar1
	state.reg4[R_69] += 0xcffe6c
	state.reg2[R_8a] += uVar1 & 0xFFFF
	state.reg4[R_a7] |= state.reg4[R_69]
	state.reg4[R_a7] += 0x44312c96
	
	r1 = (state.reg2[R_9d] + 0xd890) & 0xFFFF
	r2 = state.reg2[R_8a]
	state.VM_ASGN_R_WR(log, r1, r2)
		 
	t = U32((state.read2(0) ^ state.reg4[R_39]) + 0xb9ee8deb)
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x109] = ASM_0x109


def ASM_0x23B(state, log):
	state.reg4[R_a7] += state.reg4[R_69]
	
	r1 = (state.read2(2))
	r2 = state.read2(0)
	state.VM_XCHG_R_R(log, r1, r2)
	
	uVar5 = U32((state.read2(8)) + state.reg4[R_39] + state.reg4[R_a7])
	state.reg4[R_39] |= uVar5
	state.reg4[R_69] &= 0x20d757
	state.reg2[R_8a] += uVar5 & 0xFFFF
	
	uVar5 = U32(((state.read2(6)) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] |= uVar5
	state.reg4[R_69] += -0x1724c233
	state.reg2[R_9d] -= uVar5 & 0xFFFF
	state.reg4[R_a7] -= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x7cb0ff1f
	
	r1 = (state.reg2[R_9d] + 0x62ed) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x8a88) & 0xFFFF
	efl = (state.read2(4))
	state.VM_OR_R_R(log, r1, r2, efl)
	
	state.reg4[R_a7] &= state.reg4[R_69]
	state.reg4[R_a7] &= 0x3f06c4cc	
	state.reg4[R_39] |= 0x63db6e92
	
	t = U32(((state.read2(10)) - state.reg4[R_39]) ^ 0x228e8824)
	state.reg4[R_39] -= t
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x23B] = ASM_0x23B


def ASM_0x2E(state, log):
	uVar2 = (state.read2(0x10)) ^ state.reg4[R_39]
	state.reg4[R_39] &= uVar2
	state.reg4[R_69] &= 0x70525119
	state.reg2[R_8a] -= uVar2 & 0xFFFF
	
	iVar1 = U32(((state.read2(0xe)) ^ state.reg4[R_39]) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar1
	state.reg2[R_9d] += iVar1 & 0xFFFF
	
	
	r1 = (state.reg2[R_9d] + 0xd2f3) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xcbcb) & 0xFFFF
	state.VM_ASGN_WRM_WR(log, r1, r2)
		 
	iVar1 = (state.read4(2))
	state.reg4[R_39] += iVar1
	state.reg4[R_a7] ^= state.reg4[R_69]
	state.reg4[R_a7] ^= 0x1bc4a05c
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0x200c5b12
	
	t = U32(((state.read2(6)) ^ state.reg4[R_39]) + 0x38ea7329)
	state.reg4[R_39] &= t
	state.chEIP(+0x12)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2E] = ASM_0x2E


def ASM_0xA6(state, log):
	state.reg4[R_2c] &= state.reg4[R_39]
	state.reg4[R_a7] &= 0x5b4f84da
	
	if ((state.reg4[R_69] & 1)):
		state.reg4[R_69] += 0xdc23066
	
	uVar1 = (state.read2(2)) ^ state.reg4[R_a7]
	state.reg4[R_39] += uVar1
	state.reg4[R_69] |= 0x405bb22d
	state.reg2[R_8a] -= uVar1 & 0xFFFF
	
	uVar1 = (state.read2(4)) ^ state.reg4[R_39] ^ state.reg4[R_2c]
	state.reg4[R_39] -= uVar1
	state.reg4[R_69] |= 0x6ac15440
	state.reg2[R_9d] -= uVar1 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xa1a) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0x3e9a) & 0xFFFF
	state.VM_ASGN_WRM_WR(log, r1, r2)
	
	t = U32(state.read2(0) - 0xadd114)
	state.reg4[R_39] |= t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0xA6] = ASM_0xA6


def ASM_0x11F(state, log):
	state.reg4[R_39] += 0x1a4896cf
	r1 = (state.read2(8))
	r2 = (state.read2(6))
	state.VM_XCHG_R_R(log, r1, r2)
	
	iVar3 = U32((state.read2(0) ^ state.reg4[R_39]) + state.reg4[R_2c])
	state.reg4[R_39] += iVar3
	state.reg2[R_9d] -= iVar3 & 0xFFFF
	
	uVar4 = (state.read4(2)) ^ state.reg4[R_39]
	state.reg4[R_69] &= 0x3158859f
	state.reg4[R_8c] += uVar4
	state.reg4[R_a7] ^= uVar4
	
	r = (state.reg2[R_9d] ^ 0xb8d8) & 0xFFFF
	v = state.reg4[R_8c]
	state.VM_OR_R_V(log, r, v)
	
	t = U32(((state.read2(10)) ^ state.reg4[R_39]) + 0x29586f92)
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x11F] = ASM_0x11F


def ASM_0x1F7(state, log):
	uVar5 = U32(((state.read2(8)) - state.reg4[R_39]) ^ state.reg4[R_a7])
	state.reg4[R_39] += uVar5
	state.reg4[R_69] += -0x15e601ef
	state.reg2[R_8a] ^= uVar5 & 0xFFFF
	
	uVar5 = U32((state.read2(4)) - state.reg4[R_2c])
	state.reg4[R_39] |= uVar5
	state.reg4[R_69] += -0x6c5a3db
	state.reg2[R_9d] += uVar5 & 0xFFFF
	state.reg4[R_2c] += -0x176da51
	
	r1 = (state.reg2[R_9d] + 0x8f35) & 0xFFFF
	r2 = (state.reg2[R_8a] + 0xdb89) & 0xFFFF
	efl = state.read2(6)
	state.VM_XOR_RM_R(log, r1, r2, efl)
	
	state.reg4[R_2c] -= state.reg4[R_39]
	state.reg4[R_39] &= state.read4(0)
	
	t = U32(((state.read2(10)) ^ state.reg4[R_39]))
	state.chEIP(+0xc)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1F7] = ASM_0x1F7

def ASM_0x143(state, log):
	iVar1 = U32(state.read2(4) - state.reg4[R_2c])
	state.reg4[R_39] -= iVar1
	state.reg2[R_9d] += iVar1 & 0xFFFF
	state.reg4[R_69] &= 0x5ad2d0c2
	state.reg4[R_2c] |= 0x16770c95
	
	uVar2 = U32(state.read2(0) - state.reg4[R_39])
	state.reg4[R_39] |= uVar2
	state.reg4[R_69] |= 0x16770c95
	state.reg2[R_8a] ^= uVar2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xab) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x8faa) & 0xFFFF
	state.VM_ASGN_WRM_WR(log, r1, r2)
	
	t = U32((state.read2(2) ^ state.reg4[R_39]) + 0xde7b4a11)
	state.reg4[R_39] += t
	state.chEIP(+6)
	state.next = t & 0xFFFF
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x143] = ASM_0x143


def Parse(state):
	ERR = list()
	PARSED = dict()

	for rt in state.Routes:
		state.mem = rt.mem
		state.next = rt.next
		state.reg4[R_EIP] = rt.eip
		state.esp = rt.esp
		state.run = True
		print("Route {:02X}".format(rt.eip))
		while(state.run):
			eip = state.reg4[R_EIP]
			if eip in PARSED:
				print("Already parsed, BREAK!")
				break
		
			log = list()
			PARSED[eip] = log
	
			log.append("--OP 0x{:02X}  Addr: 0x{:08x}   \t| 0x{:02X}/0x{:02X}".format(state.next, 0x1103d3fc + state.next * 4, state.reg4[R_EIP], len(state.data)) + "    " + state.data[state.reg4[R_EIP]: state.reg4[R_EIP] + 4].hex())
			#log.append(hex(state.reg2[R_8a]))
			print("--OP 0x{:02X}  Addr: 0x{:08x}   \t| 0x{:02X}/0x{:02X}".format(state.next, 0x1103d3fc + state.next * 4, state.reg4[R_EIP], len(state.data)))
			if state.next not in VMAsm:
				log.append("\nNot implemented 0x{:02X}".format(state.next) + " \tAddr: "+ hex(0x1103d3fc + state.next * 4))
				ERR.append("\nNot implemented 0x{:02X}".format(state.next) + " \tAddr: "+ hex(0x1103d3fc + state.next * 4))
				break
	
			#state.reg4[ R_8c ] &= 0xFFFFFFFF
			#state.reg4[ R_39 ] &= 0xFFFFFFFF
			#state.reg4[ R_69 ] &= 0xFFFFFFFF
	
	
	
			func = VMAsm[state.next]
			func(state, log)
	
	
			log.append("stack (esp -0x10):")
			i = state.esp - 0x10
			while i < state.esp:
				log.append(hex(state.rMem4(i) ))
				i += 4
			
			log.append("stack: ({:X} VMESP {:X})".format(state.esp, state.reg4[0x3D]))
			i = state.esp
			while i < state.esp + 0x10:
				log.append(hex(state.rMem4(i) ))
				i += 4
	
			#print()

	print("\n\n#################################################\n\n")
	return PARSED, ERR
	
if __name__ == "__main__":
	print(len(VMAsm))