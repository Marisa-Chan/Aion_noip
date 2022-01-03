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
		v2 = self.reg4[r1]
		res = U32(v1 + v2)
		log.append("[VMR[{0:02X}]] += VMR[{1:02X}] ([{2:02X}] += {3:02X}) ({4:02X} += {3:02X}) ({5:02X})".format(r1, r2, adr, v2, v1, res))
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
	
	def VM_ADD_R_V(self, log, r, val, efl = -1):
		v1 = self.reg4[r]
		res = U32(v1 + val)
		log.append("VMR[{0:02X}] += {1:02X} ({2:02X} += {1:02X}) ({3:02X})".format(r, val, v1, res))
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
	
	def VM_SUB_BR_BR(self, log, r1, r2, efl = -1):
		v1 = self.reg1[r1]
		v2 = self.reg1[r2]
		res = (v1 - v2) & 0xFF
		log.append("b, VMR[{0:02X}] -= b, VMR[{1:02X}] ({2:02X} -= {3:02X}) ({4:02X})".format(r1, r2, v1, v2, res))
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
	
	def VM_ASGN_WR_V(self, log, r, v):
		log.append("w, VMR[{0:02X}] = {1:02X}".format(r, v & 0xFFFF))
		self.reg2[r] = v
	
	def VM_ASGN_R_R(self, log, r1, r2):
		v = self.reg4[r2]
		log.append("VMR[{0:02X}] = VMR[{1:02X}] ({2:02X})".format(r1, r2, v))
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
	log.append("#pop") #real pop
	state.reg4[ r ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r, state.reg4[ r ]))

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
	log.append("#pop")
	state.reg4[ r3 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r3, state.reg4[ r3 ]))
	
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
	log.append("#pop")
	state.reg4[ r1 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r1, state.reg4[ r1 ]))
	
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
	log.append("#pop")
	state.reg4[ r1 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r1, state.reg4[ r1 ]))

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
	log.append("#pop")
	state.reg4[ r1 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r1, state.reg4[ r1 ]))

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
	
	uvar1 = (state.read2(0) ^ state.reg4[ R_39 ]) + 0x446890a5
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
	
	log.append("#pop")
	state.reg4[ r3 ] = state.pop()
	log.append("VMR[{:02X}] = pop({:02X})".format(r3, state.reg4[ r3 ]))
	
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

	log.append("VMR[{:02X}] -= {:02X}   ({:02X} -= {:02X})".format(r, val, state.reg4[r], val))
	state.reg4[r] -= val
	
	r = state.read2(10)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	log.append("VMR[{:02X}] = {:02X}   ({:02X} = {:02X})".format(r1, val, state.reg4[r1], val))
	state.reg4[r1] = val
	
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
	log.append("VMR[{:02X}] ^= {:02X} ({:02X} ^= {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], state.reg4[r1] ^ state.reg4[r2]))
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
	#log.append(hex(state.reg4[R_8c]))
	#log.append(hex(state.reg4[R_8c] + 0x91a23270))
	if ( t & 0x1F ):
		res = U32(state.reg4[r] << (t & 0x1F))
		log.append("VMR[{0:02X}] <<= {1:02X} ({2:02X} <<= {1:02X}) ({3:02X})".format(r, (t & 0x1F), state.reg4[r], res))
		state.reg4[r] = res
	
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
	res = U32(-state.reg4[r])
	log.append("VMR[{0:02X}] = -VMR[{0:02X}]   ({1:02X})  ({2:02X})".format(r, state.reg4[r], res))
	state.reg4[r] = res	
	
	state.reg4[R_69] -= 0x23d69759
	state.reg4[R_a7] &= state.reg4[R_69]
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))

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
	if v:
		res = U32(t << v)
		log.append("VMR[{0:02X}] <<= {1:02X} ({2:02X} <<= {1:02X}) ({3:02X})".format(r, v, t, res))
		state.reg4[r] = res
		
		r = state.read2(0)
		log.append("VMR[{:02X}] = eflags".format(r))
	
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
	
	t = U32(state.read2(4) - state.reg4[R_69]) ^ state.reg4[R_2c]
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
	log.append("b, [VMR[{0:02X}]] = VMR[{1:02X}]  ([{2:02X}] = {3:02X})".format(r1, r2, adr, b))
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
	v = state.reg4[r]
	res = v & val
	log.append("VMR[{0:02X}] &= {1:02X}  ({2:02X} &= {1:02X}) ({3:02X})".format(r, val, v, res))
	state.reg4[r] = res
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	if v:
		r = (state.reg2[R_9d] + 0xba3d) & 0xFFFF
		res = U32(state.reg4[r] << v)
		log.append("VMR[{0:02X}] <<= {1:02X} ({2:02X} <<= {1:02X}) ({3:02X})".format(r, v, state.reg4[r], res))
		state.reg4[r] = res
	
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
	
	log.append(";cmp {} ({:02X}[{:02X}]){:02X} {:02X}".format(t, v1, of, rm1, rm2))
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

	log.append("#pop")
	state.reg4[ r1 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r1, state.reg4[ r1 ]))

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
