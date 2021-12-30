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

PARSED = dict()	

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
		state.reg4[r2] += 4
		log.append("VM_ESP[0x{:02X}] += 4 \t".format(r2))
	
	uvar3 = state.read2(2) + state.reg4[ R_39 ]
	state.reg4[ R_39 ] ^= uvar3

	state.next = uvar3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x4F5] = ASM_0x4F5


def ASM_0x2AC(state, log):
	r1 = state.read2(0)
	r2 = state.read2(2)
	tmp = state.reg4[ r1 ]
	state.reg4[ r1 ] = state.reg4[ r2 ]
	state.reg4[ r2 ] = tmp
	log.append("VMR[0x{:02X}] <=> VMR[0x{:02X}]".format(r1, r2))
	uvar3 = state.read2(8) + state.reg4[ R_39 ] + state.reg4[ R_2c ]
	state.reg4[ R_39 ] &= uvar3
	state.reg4[ R_69 ] ^= 0x604cadfc
	state.reg2[ R_9d ] ^= (uvar3 & 0xFFFF)
	
	r3 = (state.reg2[ R_9d ] & 0xFFFF) ^ 0xfba4
	log.append("#pop")
	state.reg4[ r3 ] = state.pop()
	log.append("VMR[0x{:02X}] = {:02X}".format(r3, state.reg4[ r3 ]))
	
	r4 = state.read2(6)
	if (r4 != r3):
		state.reg4[r4] += 4
		log.append("VM_ESP[0x{:02X}] += 4 \t".format(r4))
	
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] |= 0x4774ac77
	
	tmp = state.read2(4) + 0xaa6ba9d7
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
		state.reg4[r2] += 4
		log.append("VM_ESP[0x{:02X}] += 4 \t".format(r2))
	
	if ( state.reg4[ R_69 ] & 1 ):
		state.reg4[ R_69 ] -= 0xf7b3c5b
	
	uVar2 = state.read2(4) + state.reg4[ R_39 ] + 0xfc3344ba
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
		state.reg4[r2] += 4
		log.append("VM_ESP[0x{:02X}] += 4 \t".format(r2))
		
	state.reg4[ R_39 ] -= state.read4(14)
	state.reg4[ R_39 ] -= state.read4(10)
	state.reg4[ R_39 ] -= state.read4(6)
	
	uvar3 = (state.read2(2) ^ state.reg4[ R_39 ]) + 0x87a69b9f
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
	state.reg4[r2] += 4
	log.append("VM_ESP[0x{:02X}] += 4 \t".format(r2))
	
	uvar3 = state.read2(0) ^ state.reg4[ R_39 ] ^ 0x4b76c880
	state.next = uvar3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x446] = ASM_0x446

def ASM_0x46A(state, log):
	r = state.read2(3)
	val = state.read(2)
	log.append("VMR[{:02X}] += 0x{:02X}".format(r, val))
	log.append("#esp += 0x{:02X}".format(val))
	
	state.reg4[r] += val
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
	t1 = (state.read(0) - state.reg4[ R_39 ]) + state.reg4[ R_69 ]
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
	state.reg4[ r1 ] = val
	log.append("VMR[{:02X}] = {:02X}".format(r1, val))
	
	t3 = (state.read2(1) + state.reg4[ R_39 ]) ^ 0x41a790e7
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
	
	r1 = state.reg2[ R_8a ] & 0xFFFF
	r2 = (state.reg2[ R_9d ] + 0x722f) & 0xFFFF
	
	t3 = state.reg4[ r1 ]
	
	state.reg4[ R_a7 ] -= state.reg4[ R_69 ]
	state.reg4[ R_a7 ] ^= 0x33fa2277
	
	log.append("VMR[{:02X}] = VMR[{:02X}]  ({:02X})".format(r2, r1, t3))
	
	state.reg4[ r2 ] = t3
	
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
	
	state.reg4[ r1 ] += val	
	log.append("VMR[{:02X}] += {:02X}   ({:02X})".format(r1, val, state.reg4[ r1 ]))
	
	r2 = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r2))
	
	t4 = state.read2(12)
	state.reg4[ R_39 ] += t4
	
	state.next = t4 & 0xFFFF
	state.chEIP(+14)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1E6] = ASM_0x1E6


def ASM_0x3F8(state, log):
	r1 = state.read2(4)
	r2 = state.read2(16)
	t1 = state.reg4[ r2 ] 
	state.reg4[ r2 ] = state.reg4[ r1 ]
	state.reg4[ r1 ] = t1
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]".format(r2, r1))

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
	
	log.append("dw, [ VMR[{:02X}] ] <=> dw, VMR[{:02X}]".format(r1, r2))
	log.append("[ {:02X} ] ({:02X}) <=> {:02X}".format(state.reg4[ r1 ], state.rMem4( state.reg4[r1] ), state.reg4[ r2 ]))
	
	v1 = state.reg4[ r2 ]
	v2 = state.rMem4( state.reg4[r1] )
	state.wMem4( state.reg4[r1], v1 )
	state.reg4[ r2 ] = v2

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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	
	t = state.reg4[ r2 ]
	state.reg4[ r2 ] = state.reg4[ r1 ]
	state.reg4[ r1 ] = t
	
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
		state.reg4[r4] += 4
		log.append("VMR[{:02X}] += 4".format(r4))
	
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
	
	log.append("VMR[{:02X}] = VMR[{:02X}]".format(r1, r2))
	state.reg4[r1] = state.reg4[r2]
	
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

	log.append("VMR[{:02X}] <=> VMR[{:02X}] ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	res = U32(state.reg4[r3] + val)
	log.append("VMR[{0:02X}] += {1:02X}  ({2:02X} += {1:02X}) ({3:02X})".format(r3, val, state.reg4[r3], res))
	state.reg4[r3] = res
	
	r4 = state.read2(14)
	log.append("VMR[{:02X}] = eflags".format(r4))
	
	t3 = state.read2(8) - state.reg4[R_39] + 0xeb332817
	state.reg4[R_39] += t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+18)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x2C1] = ASM_0x2C1


def ASM_0x0E(state, log):
	r1 = state.read2(0)
	r2 = state.read2(4)
	
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]".format(r1, r2))
	
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
	log.append("VMR[{:02X}] = VMR[{:02X}]".format(r1, r2))
	state.reg4[r1] = state.reg4[r2]
	
	t3 = (state.read2(2) ^ state.reg4[R_39]) + 0xf406838c
	state.reg4[R_39] ^= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+6)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x3A6] = ASM_0x3A6

def ASM_0x376(state, log):
	t1 = state.read2(0)
	state.reg4[R_69] &= 0x6e5b0dbc
	state.reg2[R_9d] ^= (t1 + state.reg2[R_39]) - state.reg2[R_2c]
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
	log.append("VMR[{:02X}] += {:02X} (={:02X})".format(r1, val, (state.reg4[r1] + val)&0xFFFFFFFF ))
	state.reg4[r1] += val
	
	t3 = state.read2(10) + 0x18541491
	state.reg4[R_39] ^= t3

	state.next = t3 & 0xFFFF
	state.chEIP(+16)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x376] = ASM_0x376

def ASM_0x4C8(state, log):
	r1 = state.read2(4)
	r2 = state.read2(0)
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}] ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]  ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
	t1 = state.read2(12) + state.reg4[R_39]
	state.reg4[R_39] &= t1
	state.reg4[R_69] -= 0x6c605a16
	state.reg2[R_8a] += t1 & 0xFFFF
	
	t2 = (state.read2(2) - state.reg4[R_39]) - state.reg4[R_2c]
	state.reg4[R_39] ^= t2
	state.reg2[R_9d] ^= t2 & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0xc720) & 0xFFFF
	r2 = (state.reg2[R_8a] ^ 0x3771) & 0xFFFF
	log.append("VMR[{:02X}] = VMR[{:02X}]  ({:02X})".format(r1, r2, state.reg4[r2]))
	state.reg4[r1] = state.reg4[r2]
	
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
	log.append("VMR[{:02X}] &= VMR[{:02X}]".format(r1, r2))
	log.append("//{:02X} &= {:02X}".format(state.reg4[r1], state.reg4[r2]))
	state.reg4[r1] &= state.reg4[r2]

	state.reg4[R_39] ^= 0x4941fe11
	
	r3 = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r3))
	
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
	
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	log.append("VMR[{:02X}] <=> VMR[{:02X}]".format(r1, r2))
	
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
	log.append("VMR[{:02X}] += VMR[{:02X}]   ({:02X} += {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	state.reg4[r1] += state.reg4[r2]
	
	r = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	
	log.append("VMR[{:02X}] += {:02X}   ({:02X} += {:02X}) ({:02X})".format(r1, val, state.reg4[r1], val, U32(state.reg4[r1]+val)))
	state.reg4[r1] += val
	
	if (state.reg4[R_69] & 1):
		state.reg4[R_69] &= 0x2a035df2
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	t3 = (state.read2(0) + state.reg4[R_39]) + 0x4e06cc94

	state.next = t3 & 0xFFFF
	state.chEIP(+10)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x1AC] = ASM_0x1AC

def ASM_0x450(state, log):
	r1 = state.read2(6)
	r2 = state.read2(8)
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	
	log.append("VMR[{:02X}] += VMR[{:02X}]   ({:02X} += {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1]+state.reg4[r2])))
	state.reg4[r1] += state.reg4[r2]
	
	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
	state.reg4[R_39] -= state.read4(2)
	
	t3 = state.read2(0) + state.reg4[R_39]
	state.reg4[R_39] &= t3
	
	state.next = t3 & 0xFFFF
	state.chEIP(+12)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x29B] = ASM_0x29B

def ASM_0xAF(state, log):
	state.reg4[R_2c] |= state.reg4[R_39]
	
	t1 = state.read4(4) + state.reg4[R_39] - state.reg4[R_69]
	state.reg4[R_39] |= t1
	state.reg4[R_69] ^= 0x5b9388e8
	state.reg4[R_8c] += t1
	
	t2 = state.read2(0) - state.reg4[R_39] + state.reg4[R_2c]
	state.reg4[R_39] |= t2
	state.reg4[R_69] -= 0x6a2b1fd1
	state.reg2[R_9d] += t2 & 0xFFFF
	
	r1 = state.reg2[ R_9d ]
	val = U32(state.reg4[ R_8c ] + 0x574c2cc1)
	log.append("VMR[{:02X}] = {:02X}   ({:02X} = {:02X})".format(r1, val, state.reg4[r1], val))
	state.reg4[r1] = val
	
	t3 = (state.read2(8) - state.reg4[R_39]) ^ 0x2cd21358
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
	
	log.append("VMR[{:02X}] += {:02X}   ({:02X} += {:02X}) ({:02X})".format(r1, val, state.reg4[r1], val, U32(state.reg4[r1]+val)))
	state.reg4[r1] += val
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
	t1 = state.read2(0)
	state.reg4[ R_39 ] ^= t1
	state.reg4[ R_69 ] &= 0x3a302081
	state.reg2[ R_9d ] += t1
	
	t2 = state.read4(4)
	state.reg4[R_8c] -= ((t2 - state.reg4[R_39]) ^ state.reg4[R_69])
	state.reg4[R_69] ^= 0xdd40461
	
	val = U32(state.reg4[R_8c] + 0x1d0bc1b3)
	r1 = (state.reg2[R_9d] + 0xeab) & 0xFFFF
	
	log.append("VMR[{:02X}] += {:02X}   ({:02X} += {:02X}) ({:02X})".format(r1, val, state.reg4[r1], val, U32(state.reg4[r1]+val)))
	state.reg4[r1] += val
	
	r2 = state.read2(12)
	log.append("VMR[{:02X}] = eflags".format(r2))
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
	t1 = state.read2(0) - state.reg4[R_2c]
	state.reg4[R_39] ^= t1
	state.reg2[R_9d] -= t1 & 0xFFFFF
	state.reg2[R_8a] -= (state.read2(8) - state.reg2[R_a7]) & 0xFFFF
	
	r1 = (state.reg2[R_9d] + 0x15cf) & 0xFFFF
	r2 = state.reg2[R_8a]

	log.append("VMR[{:02X}] += VMR[{:02X}]   ({:02X} += {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1]+state.reg4[r2])))
	state.reg4[r1] += state.reg4[r2]
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
	
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
	log.append("VMR[{:02X}] = VMR[{:02X}]   ({:02X})".format(r1, r2, state.reg4[r2]))
	state.reg4[r1] = state.reg4[r2]
	
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
	addr = state.reg4[r1]
	val = state.rMem4(addr)
	sm = U32(state.reg4[r2] + val)
	log.append("[VMR[{:02X}]] += VMR[{:02X}]   ([{:02X}] += {:02X}) ({:02X} += {:02X}) ({:02X})".format(r1, r2, addr, state.reg4[r2], val, state.reg4[r2], sm))
	state.wMem4(addr, sm)
	
	r = state.read2(6)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	
	v2 = state.reg4[R_8c]
	
	r1 = state.reg2[R_9d]
	addr = state.reg4[r1]
	v1 = state.rMem4(addr)
	res = U32(v1 + v2)
	log.append("[VMR[{0:02X}]] += {1:02X} ([{2:02X}] += {1:02X}) ({3:02X} += {1:02X}) ({4:02X})".format(r1, v2, addr, v1, res))
	state.wMem4(addr, res)
	
	r = state.read2(10)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	log.append("VMR[{:02X}] += VMR[{:02X}] ({:02X} += {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], U32(state.reg4[r1] + state.reg4[r2])))
	state.reg4[r1] += state.reg4[r2]
	
	state.reg4[R_39] += 0x5dd482ea

	r = state.read2(8)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	
	v2 = state.reg4[R_8c]
	r = (state.reg2[R_9d] + 0xe589) & 0xFFFF
	addr = state.reg4[r]
	v1 = state.rMem4(addr)
	res = U32(v1 + v2)
	log.append("[VMR[{0:02X}]] += {1:02X} ([{2:02X}] += {1:02X}) ({3:02X} += {1:02X}) ({4:02X})".format(r, v2, addr, v1, res))
	state.wMem4(addr, res)
	
	r = state.read2(12)
	log.append("VMR[{:02X}] = eflags".format(r))
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	res = U32(state.reg4[r1] + state.reg4[r2])
	log.append("VMR[{:02X}] += VMR[{:02X}] ({:02X} += {:02X}) ({:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res))
	state.reg4[r1] = res
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	res = U32(state.reg4[r1] + state.reg4[r2])
	log.append("VMR[{0:02X}] += VMR[{1:02X}]   ({2:02X} += {3:02X})  ({4:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2], res))
	state.reg4[r1] = res	

	r = state.read2(2)
	log.append("VMR[{:02X}] = eflags".format(r))

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
	log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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
	
	log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t

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
	
	log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t

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
	
	log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t

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
	
	log.append("VMR[{0:02X}] <=> VMR[{1:02X}] ({2:02X} <=> {3:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t

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
	val = state.reg4[r2]
	adr = state.reg4[r1]
	v = state.rMem4(adr)
	res = U32(v + val)
	log.append("[VMR[{0:02X}]] += VMR[{1:02X}] ([{2:02X}] += {3:02X}) ({4:02X} += {3:02X}) ({5:02X})".format(r1, r2, adr, val, v, res))
	state.wMem4(adr, res)
	
	r3 = state.read2(0)
	log.append("VMR[{:02X}] = eflags".format(r3))
	
	t = U32((state.read2(4) ^ state.reg4[R_39]) + 0xbd7fe496)
	state.reg4[R_39] &= t
	state.next = t & 0xFFFF
	state.chEIP(+8)
	log.append(";next = {:02X}".format(state.next))
VMAsm[0x235] = ASM_0x235


def ASM_0x282(state, log):
	r1 = state.read2(3)
	r2 = state.read2(7)
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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

	state.reg4[r2] += 4
	log.append("VM_ESP[0x{:02X}] += 4 \t".format(r2))
	
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
	
	log.append("VMR[{:02X}] <=> VMR[{:02X}]   ({:02X} <=> {:02X})".format(r1, r2, state.reg4[r1], state.reg4[r2]))
	t = state.reg4[r2]
	state.reg4[r2] = state.reg4[r1]
	state.reg4[r1] = t
	
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


def FNC1(state, log):
	eip = state.reg4[R_EIP]
	if (eip == 0x12F5):
		state.pop()
		log.append("\n#InterlockedIncrement({:02X})\n".format(state.pop()))

		tmp = state.esp
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x14121d3 - 0x1410ed6)
	elif (eip == 0x1457):
		log.append("\n#CDQ\n")
		
		tmp = state.esp
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x141233a - 0x1410ed6)	
	elif (eip == 0x152B):
		log.append("\n#IDIV ECX\n")
		
		tmp = state.esp
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x141240e - 0x1410ed6)	
	elif (eip == 0x16B4):
		log.append("\n#memset\n")
		
		tmp = state.esp
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x1412594 - 0x1410ed6)
	elif (eip == 0x1809):
		log.append("\n#FUN_100b06c0\n")
		
		tmp = state.esp
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x14126e9 - 0x1410ed6)
	else:
		log.append("\n\n#OnEnd {:02X}\n\n".format(eip))


state = VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\xf5\x04\x6f\x6d\xfd\x23\x3d\x00\x11\x00\x41\x00\x65\x59\x3d\x00\xe0\xd7\x50\xb6\x28\x00\xfc\xb8\x3d\x00\x06\x8a\x98\x6a\x3d\x00\x3d\x00\x04\x6e\x20\xd7\x1b\xc6\x19\x60\x6a\xa1\xfb\x5a\xea\x22\x17\x61\x52\x00\x35\x4d\x90\x00\x7e\xb4\x3d\x00\x82\x2d\x49\x6f\x3d\x00\x6e\x93\x90\x00\xbd\x2e\x3d\x00\xac\xcc\x75\x00\x3d\x00\xb1\x70\x08\x3d\x00\xe7\x17\xae\x21\x3d\x00\xb3\x3b\x3c\xb8\xc9\xeb\x0c\xca\xa0\x75\x00\xf1\xef\x52\x00\xf6\x27\x0b\xc3\x75\x00\x39\x26\x66\x0f\x74\xeb\x11\x00\x11\x00\x75\x00\x19\x40\xfd\x4b\x41\x00\xd3\x5e\x75\x00\xab\x1f\x11\x00\x7e\x76\x75\x00\x3d\x00\x70\x71\xfa\xa1\x39\xbd\xd1\x58\x66\xe0\xb4\x50\x5d\x4b\x8e\x25\x11\x00\x62\x0e\xfa\xd8\xba\x1f\x3d\x00\xb8\xb3\x21\x65\xbf\xc2\x75\x00\x6d\x36\x2e\x37\x41\x00\x43\x8a\x55\xa4\x61\xc0\x75\x00\x02\x6c\x4b\x01\x52\x00\xa7\xa6\x42\x41\x3d\x00\x3b\x21\x96\xe5\x45\x33\x75\x00\xed\xe5\x98\x13\x1b\xd1\x47\xc6\x93\x7a\xf8\x03\x6e\xb4\x58\x5e\x90\x00\x75\x00\x31\xec\x75\x00\x09\xaa\x52\x00\x90\x00\x33\x3f\xc7\x7e\x5d\x1e\x3d\x00\x9c\x02\x11\x00\xd8\xea\x28\x00\x3d\x00\xf9\x7d\x1b\x05\x19\x47\xbf\xc2\x75\x00\xcf\x0d\x4a\x1c\x11\x00\x61\xb1\x46\x1f\x61\xc0\x75\x00\x9f\x87\x34\x4b\x7a\x00\xcb\xd1\x6b\x43\x3d\x00\x34\x4e\x42\xf5\x3c\xd1\x85\xb3\x8d\x54\x52\x00\x82\xf6\x8c\x6f\x11\x00\x9f\xc4\x75\x00\x52\x00\x75\x00\x35\xb4\x11\x00\x5c\xd9\x11\x00\x84\xc3\x0c\xd3\x75\x00\x35\x7a\xa0\x3d\xa2\xb2\xba\x01\x8f\x7a\x88\xdc\x3d\x00\x3d\x00\xa8\x78\x80\x42\xda\x8c\x1c\xc0\x75\x00\x9e\xac\x1f\x67\x28\x00\xa9\x09\x5a\xee\x42\x17\x82\x00\xe1\x33\x14\x05\xc4\xe2\x5c\x2c\x51\xb1\x25\xa2\x27\x78\x0d\x7a\xa2\x69\x37\xf0\xbc\x2b\x3e\x4f\x41\x00\x2d\xec\x52\x00\x90\x00\xf4\xc1\x90\x00\xad\x2c\x28\x00\x51\x87\x75\x00\x41\x00\x39\xb8\x3d\x00\xda\x00\x75\x00\x41\x00\xf3\xb8\x3d\x00\xc2\x97\x83\x39\x6e\xb6\xac\x32\x10\x12\xa1\xbc\x7a\x00\x6c\x4e\x41\x00\x90\x00\x03\xa2\x52\x00\x1e\x95\x75\x00\x75\x00\xda\xb0\x04\x1c\xc6\x1f\x7a\x00\x7e\xbe\xfb\x50\x28\x00\x25\x82\x75\x00\x7a\x00\x75\x00\x0a\x74\x3d\x00\xe1\xfb\xea\xa6\x38\x6f\x8f\x24\xd2\x5d\x75\x00\xe3\x16\x3d\x00\xed\x02\x41\x00\xc5\xad\x41\x00\x90\x00\x28\x00\xfa\xa7\x7e\x9f\x2d\xed\x75\x00\x50\xde\x7a\x00\x52\x00\x41\x00\x7a\x00\xa0\x90\x90\x00\x41\x00\x52\x00\x28\x00\x11\x00\x11\x00\x28\x00\x90\x00\x51\x00\x00\x00\x93\x00\x00\x00\x75\x00\xa2\x60\x9f\xf2\x6e\x4e\x43\x3d\x00\xac\xf6\x90\x00\x3d\x00\xc0\x41\x40\x6a\x18\x05\xc9\x68\x5e\x4d\x52\x00\x80\xaf\x3d\x00\x75\x00\x28\x00\x36\xbe\xbc\x9b\xe9\x37\x75\x00\x11\x00\x7f\x74\x28\x00\x28\x00\x28\x6a\x41\x00\x66\x5d\x52\x00\x75\x00\x86\xb3\x41\x5e\x64\x6b\x85\x42\xd8\xae\x9c\x02\x3d\x00\x28\x5b\x7a\x00\x52\x00\x41\x00\x41\x00\x1e\x17\x90\x00\x11\x00\x28\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x3b\x02\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x3d\x10\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x6f\x03\x3b\xd3\xaa\x57\xc7\x5a\x8c\x32\x28\x00\x75\x00\x52\x00\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x7e\x1b\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x05\x01\x00\x00\x75\x00\xa2\x88\x7d\x64\x14\x83\xe8\x3d\x00\xb3\x30\x93\xba\x75\x00\x9c\x55\xfe\x26\x11\x00\x7e\xec\x11\x44\x3d\x00\xd9\x95\xc9\x25\xb1\x6e\xb8\x00\x58\x15\xf2\xe8\xba\x17\x6d\xcf\xc9\xb2\x52\x51\x75\x00\x38\x95\xb3\x43\xbc\x78\x28\x00\x11\x00\xa1\xdd\x18\xcf\x28\x00\x75\x00\x84\xd5\x75\x00\xd0\xaa\x90\x00\x41\x00\x6a\x67\x5f\xdb\x3d\x00\x29\x4b\xdb\x03\xc6\x34\x68\xd6\x75\x00\xcc\x0d\x48\x94\x78\x65\x3d\x00\x7a\x00\x16\x1b\x11\x00\x81\xbe\x10\x3a\x75\x00\x4c\x15\x3d\x00\x0e\xd6\x2f\x12\xf1\xb4\x6e\xc1\x75\x00\xb3\x75\x9d\x4e\x11\x00\x9e\xc6\x7a\x00\x3a\x45\xa8\xd6\xc3\x0e\x75\x00\x48\x6f\xc5\x33\xa6\x2a\xaf\x19\x75\x00\x75\x00\x7a\x00\x16\xbd\x75\x5d\x11\x00\xd0\xd0\x1e\x00\xb8\xb3\x28\x00\x75\x00\x3a\x08\x75\x00\xd0\xaa\x11\x00\x52\x00\xa7\x20\xd3\xa4\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\x4f\x45\x90\x00\x7a\x00\x41\x00\x11\x00\x11\x00\x28\x00\x28\x00\x90\x00\x51\x00\x00\x00\x0a\x01\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xb6\x45\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x90\x01\x9e\x18\x45\x1d\x90\x00\xff\xda\x52\x00\x3d\x00\x76\x37\xf3\xee\xd4\x0b\xe5\xf0\x75\x00\x7a\x00\x84\xbb\x3d\x00\x9b\x22\x98\x2d\xcf\xe6\x75\x00\x01\xcf\x10\x6b\x96\x13\x14\x77\xd3\x79\x0e\x00\x41\x00\x5a\x2f\x7a\x00\x59\xd8\xee\x7c\x75\x00\x99\x0d\xb1\x7c\x7a\x7f\x87\x5b\x3d\x00\x9c\x02\x11\x00\xbb\x21\x90\x00\x3d\x00\x6e\x3f\xa4\xb5\x3d\xef\x18\xf0\xe1\x35\x83\x19\x69\x86\x24\x62\x78\x78\xa2\x85\x75\x00\xf2\xc2\x52\x00\x08\x67\xfd\xaa\xa8\x70\x66\x93\x52\x1e\x0d\x09\xc3\x1e\xaf\xeb\x3e\xef\xc6\x1b\x6f\x2f\x23\xa8\x7e\x74\x75\x00\x7a\x00\x3d\x00\x4b\x00\x52\x00\x41\x95\x28\x00\x3d\x00\x22\xf4\x82\xce\xb4\x44\x41\x00\x75\x00\xf4\xf1\x4d\x77\xc8\x36\x24\xaa\x05\xde\xf2\x45\xb5\x9a\x2d\x75\x70\x8b\xee\x37\x21\xce\x8b\x6a\x3d\x00\xda\x27\xcc\x96\x5b\xdf\xf4\x6e\x90\x3c\x7a\x00\x90\x00\x75\x00\x3d\x00\xd1\x31\x7a\x00\x52\x00\x41\x00\x90\x00\x94\xc6\x90\x00\x52\x00\x7a\x00\x41\x00\x11\x00\x11\x00\x28\x00\x28\x00\x98\x01\x52\x00\xe0\x38\x11\x00\x52\x00\xc9\x0a\x7a\x00\xf3\x37\x75\x00\x75\x00\x32\x63\x9b\x2c\x11\xc7\x60\x2e\x2e\x3d\x3f\x29\x2b\x1c\x52\xb3\xbc\x18\xcb\xed\x3c\x30\xb8\xf9\x3d\x00\x17\x8d\x0f\x28\xdc\x88\x59\x05\xa2\x2a\xe9\x4d\x88\xc2\x75\x00\x41\x8f\xca\x55\x90\x00\x6d\x89\x86\x1b\x40\xaf\x0b\x26\x4d\x0e\x09\x76\xb2\xbf\x11\x00\x75\x00\x71\x0e\x75\x00\x77\xa8\x41\x00\x41\x00\x3d\x00\xf1\x34\xb5\x6a\xce\x82\x67\xc2\x75\x00\x77\xe3\x31\x5d\x41\x00\x77\x4c\x67\xea\xc5\x48\xcf\xb4\xb2\x5f\xdf\x42\xb9\xfd\x75\x00\x9a\x37\x49\x80\x38\x11\x82\x2d\x75\x00\xa5\x34\x38\x34\xef\xe7\x3d\x00\x9c\x02\x11\x00\xeb\xac\x28\x00\x3d\x00\xee\xcf\x90\x82\xf6\x74\xea\xe8\xb5\x33\xce\x11\x01\x50\x26\x2d\x5d\xc5\x06\xbe\x22\xe1\x8d\x38\xc0\x0b\x86\x47\x09\x8b\x45\xca\x8a\xb3\x04\x77\xdf\x29\x64\x14\xb0\x22\x3d\x00\x8b\x32\x2d\x6a\x75\x00\x25\x97\xfe\x29\x7a\x00\x3b\xfc\x41\x00\x13\xcb\x15\xb6\x55\xff\x75\x00\x11\x00\x8a\xaf\x41\x00\xdd\xd6\x8a\x6e\x75\x00\x5b\x6a\xfc\x79\x56\x40\x2c\xa5\x11\x00\x28\x00\x52\xa9\x36\x5b\x49\xa0\xee\x9f\x52\x00\x90\x00\x75\x00\x41\x00\x8e\xdc\x7a\x00\x28\x00\x25\xd3\x52\x00\x27\x3c\x7a\x00\xe8\x2d\x8d\x23\x0c\xb1\xb0\x81\x75\x00\x3d\x00\x2e\x59\x7c\x60\xa5\x84\x75\x00\x72\xcf\x52\x00\x7a\x00\x52\x00\x41\x00\x11\x00\xe9\x1a\x90\x00\x7a\x00\x28\x00\x41\x00\x11\x00\x90\x00\x28\x00\x52\x00\x51\x00\x00\x00\x5b\x02\x00\x00\x75\x00\x80\xb0\x9c\x7a\x00\x52\x00\x41\x00\x41\x00\x6b\x1a\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x39\x02\xec\xf1\x3d\x00\x12\xda\xaf\x47\xc7\x7b\x05\x32\x2f\xcd\x56\xb5\xbf\xc2\x75\x00\xb3\xa1\x76\x0b\x28\x00\x6e\x93\x92\xe5\xd5\xc1\x75\x00\x35\x39\xb0\x7f\x28\x00\xa8\x5c\x3d\x00\xf1\x75\xc7\x5c\x8c\x1f\x03\xb2\x7a\x00\xe7\x44\x3d\x00\x9c\x4e\x0c\x44\x3d\x00\xaf\x06\xc9\x32\xdd\x77\x28\x00\x31\xd4\xb0\xd8\x28\x00\x81\x17\x75\x00\x11\x00\x75\x00\x93\x8f\x28\x00\x83\xa5\xcd\x0f\x52\x00\x86\x13\x75\x00\x11\x00\x75\x00\xdd\x77\xcf\x32\xc9\xcb\xb2\xe7\x5e\x4d\x90\x00\xc5\x8c\x3d\x00\x3d\x00\x7f\x53\x41\x00\x5e\x52\x8b\x7c\x28\x00\x09\x41\x75\x00\x11\x00\x75\x00\x95\x1d\xdc\x9c\x41\x00\xa5\x45\xcb\x88\x75\x00\x04\x6e\x7f\x9c\x52\x08\x79\x65\x4c\x79\x28\x00\x28\x00\xf2\xd5\xc5\xdd\xe4\xa6\xd0\xc5\xad\xa4\x75\x00\x6e\xf2\x75\x00\x90\x00\xf3\xb8\x3d\x00\xd2\x3f\x85\x6c\xae\x71\x81\x86\xd1\xdd\x7b\x0c\xba\x8b\x51\xc7\x70\xe2\x75\x00\x73\xd2\x90\x00\x4d\xc0\x3d\x00\x70\x25\x6e\x63\x75\x00\x3c\xc0\x90\x00\x6e\xd7\xe4\x43\x3d\x00\x5f\x29\x0f\xc9\xbf\xc0\x75\x00\x60\xa4\xb2\x49\x7a\x00\x72\xa4\x92\x18\x75\x00\x9b\x3e\x3c\x05\x28\x00\x52\x00\x0f\x26\x41\x00\x52\x00\x02\xeb\x28\x00\xe6\xeb\x75\x00\x75\x00\xc0\xa3\xcc\x1c\xd6\xc7\x16\xb4\x50\x0f\xaa\x35\x06\x5d\xec\x76\xcb\x4a\x77\xfc\xab\x36\x2a\xaf\x75\x00\x7a\x00\xba\x3f\x11\x00\x7a\x00\x8b\x0a\x28\x00\x17\xb6\x75\x00\x75\x00\xb1\xd9\xbf\x14\x6e\x42\xa1\x95\x54\x6e\xaf\xeb\xea\x2d\x8d\xe6\x7f\x76\x5a\xf7\x8d\xab\x75\x00\x11\x00\xd7\xc6\xe5\x65\xa8\x6b\x66\x39\x0e\x1e\xe8\xd4\xf6\xe5\x6c\x82\x30\x0a\xbb\x19\x44\x9e\x28\x00\x29\x6e\xc4\x64\xfb\x5a\x57\xdf\x75\x00\x3d\x00\x6e\x41\xae\x87\x54\xb1\x36\x59\x99\xcc\xc9\x7d\xa8\xcb\x5c\x6c\x52\x00\x1f\x16\x6d\xcf\x3d\x00\x15\x7a\xe1\x0d\x3f\x85\x31\xb8\x7b\x38\x80\xcd\x11\x44\x3d\x00\xd8\xf8\x53\x42\x07\x01\xd5\xf5\xb7\xb8\x8f\x07\x75\x00\x11\xd3\x28\x00\xc5\xba\x75\x00\x11\x0f\xfa\x77\x98\x4e\x32\x09\x75\x00\x09\x44\x1c\x51\xc7\xec\x5a\xcf\x4e\x78\x9c\x02\x3d\x00\x19\x37\x9c\xdd\xfe\xd8\x0d\xfa\x6a\x07\x28\x00\x11\x00\x75\x00\x6b\x74\xb5\xce\x1e\xf4\x5e\x4d\x7a\x00\x59\x80\x3d\x00\x3d\x00\x9a\x53\x7a\x00\x52\x00\x41\x00\x11\x00\x5a\x18\x90\x00\x52\x00\x28\x00\x7a\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\xc1\x05\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xa3\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa6\x03\x0a\x6a\x28\x80\x00\x00\xd4\xc0\xbb\x08\x2d\x06\x33\xe4\xc1\x7e\x1a\x72\xe5\xda\xd0\x24\x90\x89\x91\xf2\xf3\xae\x40\xcd\x5f\x73\x7b\xc0\xf5\xa4\xdf\x07\x81\x83\x80\x70\xc4\xd2\x48\x5c\x76\x54\x75\x1c\xaf\x61\x5a\x6f\x0e\xd4\xb9\x3f\x16\x09\x28\x00\x75\x00\x75\x00\x64\xaf\x81\x89\xb2\x3e\x06\xfe\xae\x79\x37\xde\x4c\xb2\x1b\x21\x00\x20\x23\x33\x0c\xee\xe8\xb4\x73\x1e\x7d\x93\x75\x00\x34\x8f\x3e\x3d\x75\x00\x11\x00\x90\x00\x1a\xdd\x52\x00\x9b\xbb\x61\x11\x75\x00\xcb\xa6\x3d\x00\x69\x9a\x35\xcb\x2e\xed\x47\x35\x26\x16\xb0\x3f\x3d\x00\x30\x29\x41\x00\x81\x5a\x3d\x00\x57\x84\xad\x3d\x11\x91\x3d\x00\x05\x03\x90\x00\x2f\x97\x52\x00\x79\xaa\x93\x5b\xc0\x6e\x8b\x66\xd3\x25\x03\xb7\x42\xcd\xe3\x63\x60\x2d\xd1\x1c\xba\xeb\x4c\x1a\x07\xce\x3d\x00\xe7\x88\x99\x96\xa5\x19\x90\x00\x75\x00\x77\xe2\x6f\xfa\x75\x00\xe1\x43\x7e\xee\x4c\x4f\x7a\x00\x75\x00\x09\x8b\xce\xf1\xe6\x2b\x31\x7c\x43\x59\x1f\x16\xa0\x09\x3d\x00\x7b\xdf\xee\x97\xbc\xfb\x08\x7c\x50\x35\xd7\xb9\xb9\x5b\xb0\x73\x98\x88\xf2\x12\xb1\x2a\x8a\x17\x66\x94\xfe\x96\x88\xc7\x0f\x36\xbc\xea\x11\x00\x11\x00\x75\x00\x64\x42\xeb\xe5\x35\x04\x90\x00\x41\x00\xc5\x58\x3d\x00\xbb\xbc\x3d\x00\x3a\x99\x08\x73\x28\x00\x86\x14\x42\xbe\x75\x00\xd4\x79\xe0\xaf\x4c\x03\xb5\x15\x21\x7b\x3d\x00\x7e\x22\x52\x00\x1a\xed\x22\x90\x2d\x10\x75\x00\x0b\xe1\x95\x59\x6b\x3e\x41\xb2\x63\x4d\x92\xed\x7b\x1f\x86\x15\x90\x00\x7a\x00\xc7\xc9\xf5\x4f\xdf\x75\x00\x34\xac\xb9\x69\x55\x85\x24\x6c\x3a\x46\x9e\xc6\x6f\x47\x55\x03\x75\x00\x41\x00\xbe\xb2\x47\x2c\x7e\x34\x75\x00\x39\x3d\x35\x10\x3d\x00\x60\x54\xa3\x1c\xa6\x7b\x1a\xf7\x75\x00\x53\x41\x09\x2a\x90\x00\xc9\xfe\x8a\x84\x75\x44\xf7\x10\x75\x00\x84\xca\x5b\xf9\x34\x99\xa3\x10\x72\x1f\x46\x47\x75\x00\x55\x5d\xff\x64\x51\xba\xe5\xa8\x75\x00\x11\x00\x26\xba\x3d\x00\xad\xa1\xc3\xc6\x75\x00\xf7\x2b\xd7\x7f\x52\x00\xfb\x90\x00\x75\x00\x2d\xec\xf0\xce\x52\x00\x07\x42\x75\x00\x7a\x00\xf7\xbb\x3d\x00\x03\xce\x90\x00\x2e\xeb\xeb\x89\x57\x13\x75\x00\x72\x9b\x7a\x00\x75\x00\x16\xa9\xde\x43\x2d\x2b\x75\x00\x6a\x4f\x3d\x00\x36\xa5\x69\x4f\x42\x26\x34\x6d\x29\x50\xee\x40\x4a\xc7\x20\x47\x41\x00\x17\x1f\x40\x6d\x56\x71\x4a\x60\x4e\x34\x0a\xec\xbd\x6e\xf7\xdf\x82\x06\xe7\xa5\xa5\xb1\x31\xd6\x90\x00\x52\x00\x75\x00\x6e\xde\x00\x21\x21\x2d\x90\x00\x75\x00\x44\x6f\x92\x07\xb7\x62\x8f\xa1\x6b\xb9\x73\x47\xac\x94\x28\xb5\x16\x22\xae\x1c\x75\x00\x53\x18\x2e\x81\x3d\x00\x0b\x64\x69\xb2\x4e\x1b\x83\x51\xa3\xd5\x98\x7e\x34\x51\xa8\x48\x11\x00\xcf\xc7\x4a\xa4\x0c\xaf\x6c\xcb\x92\x63\xfc\xd8\x22\x51\x2c\x82\xb9\xda\x8e\x2f\xb4\x72\xb9\xc8\xe0\x81\x2e\xf7\x3d\x00\x7a\x6e\xfa\x61\xe5\x4d\x75\x00\x75\xd2\x79\xc5\x2c\x15\x94\x0c\x63\x7d\x11\x00\x8b\xbe\x3d\x00\x8b\x75\x75\x00\x28\x00\xf7\xbb\x3d\x00\xd2\x6f\x90\x00\xe5\x19\x9a\xe0\xdf\xfa\x75\x00\xfb\x73\x16\x2c\xd6\xa4\xe7\xf9\x75\x00\xc4\x46\x19\x75\x00\xea\x59\x05\xdc\x0d\x75\x00\xe4\x42\x75\x00\x9a\xd8\x7a\x00\x5d\x61\xb1\x16\x81\x86\x3d\x00\x8c\x98\x34\x02\xfc\xe5\xd6\x4f\xde\xb2\xf2\x02\x94\x74\x98\x31\x70\xe8\xb3\x6c\xa5\x28\x00\x75\x00\x87\x87\x86\x55\x11\x00\x4a\xfc\xc9\x75\x11\x03\xca\x1a\xe2\x11\x00\x75\x00\x5f\x87\x7a\x55\x11\x00\x4a\x5a\x90\x00\xbb\xf3\x89\x20\x27\x9a\x90\x00\x75\x00\x84\x6d\x38\x36\x1a\x73\x7d\xe4\x75\x00\xa7\x18\xc1\xe7\x75\x00\x9f\x38\x75\x00\x90\x00\x5e\xd9\x7a\x00\xcc\xd2\x3d\x00\x75\x00\x35\x61\x52\x00\x70\xfe\x75\x00\x00\xb4\x3d\x00\xdc\x00\x90\x00\x56\x0b\x11\x00\x0e\xfe\xca\x3e\xbd\x71\x1b\xde\xca\x65\x9a\x6d\xb9\x50\xdb\x5f\xb8\xee\x85\x94\xc3\xdb\x90\x89\x02\x8e\x83\x3c\x7c\x97\x72\x19\x5f\xcc\xf6\x96\xe0\xf9\xea\xd1\x82\x17\x9f\x83\xed\x20\x49\xc5\xfd\xaf\x2d\x03\x08\x1f\x00\x50\xa3\x78\x13\x4e\x75\x00\xc2\x96\xcc\xc0\x75\x00\x11\x00\xe5\xc0\xe7\x05\xb2\xa5\x7b\x40\xf0\x6a\x9c\xc2\x85\xad\x80\x52\x76\x37\x2a\xa3\x81\xf5\x68\x08\x75\x00\x03\xb2\xea\x0a\x75\x00\x75\x00\x5e\x98\x61\xf4\xc2\x2b\x28\x00\x52\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\xf3\xe9\x90\x00\x28\x00\x90\x00\x11\x00\x11\x00\x52\x00\x28\x00\x41\x00\x51\x00\x00\x00\xcf\x00\x00\x00\x75\x00\x04\x2f\xf5\xba\x14\xcc\x24\x3d\x00\xa9\x70\x15\x41\x3d\x00\xea\x0f\x52\x00\x7f\x33\x9d\x57\x8f\x11\x75\x00\x98\x35\xc2\x0d\x75\x00\x1e\xc1\x8c\x8c\x28\x00\x19\x8d\x24\xc1\x75\x00\xa5\x85\x75\x00\x28\x00\x11\x00\xac\xfc\x11\x00\x7a\x00\xe4\xc7\x7a\x00\x20\x2f\x7a\x00\x75\x00\x31\x6e\x82\x59\x57\xfa\x7a\x36\xf3\xd1\x9c\x02\x3d\x00\xf6\x5d\x1c\x5a\x5b\x99\x8d\x6b\x65\x22\x11\x00\x75\x00\x49\x50\x75\x00\x5b\xaa\x11\x00\x52\x00\x5c\x51\x91\x02\x1a\x86\x96\x9c\xe0\x8c\x40\x4a\x7a\x00\x28\x00\x75\x00\x2c\xb3\x87\xf8\xbe\xb3\x7b\xb2\xe5\xac\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x61\x4b\x90\x00\x7a\x00\x52\x00\x28\x00\x11\x00\x11\x00\x28\x00\x90\x00\x51\x00\x00\x00\xad\x00\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xa0\x4d\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x03\x45\x38\x75\x00\x90\x00\x26\xba\x3d\x00\x4f\x27\xec\xd7\x75\x00\x4b\xaa\xf5\x8d\x52\x00\x75\x00\xb8\xe6\xa8\x14\xf5\x8a\xb6\x41\x00\x5c\x07\x72\x4d\x53\xce\x2d\xaa\xc9\x16\x41\x00\x11\x00\xbb\xd5\x20\x05\xf9\x14\x75\x00\x8e\x16\x3f\x2c\x8a\xc7\x11\x00\x7c\xab\xcf\x30\x28\x00\x33\x97\x75\x00\x90\x00\x75\x00\xe8\x73\x3d\x00\x87\x12\x81\xe1\xe0\x9b\x99\x6a\x16\x2c\x75\x00\xeb\xbc\x58\xb7\x17\xd7\x5c\x1d\x3e\x43\xcb\x2f\xdf\xed\xf9\xf6\xcf\x9e\x7a\x00\x52\x00\x41\x00\x28\x00\x85\x7d\x90\x00\x11\x00\x41\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x69\x01\x11\x00\x75\x00\x84\x46\x90\x00\xec\xbb\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xa5\xa1\x90\x00\x28\x00\x90\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x11\x00\x51\x00\x00\x00\x49\x00\x00\x00\x75\x00\x80\xb0\x9c\x7a\x00\x52\x00\x41\x00\x41\x00\xea\x1e\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xb1\x07\x00\x80\x7a\x00\x52\x00\x41\x00\x41\x00\x2b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x4b\x00\x3d\x00\xc3\xff\xd5\xf5\x0e\x10\x41\x00\x75\x00\xf2\xc3\x3d\x00\x27\xdb\xbb\xff\xd5\xbd\xc5\x55\xfe\x31\x6c\x63\x9a\x52\x60\x04\x41\x00\xae\xbd\xfe\x41\x3d\x00\x52\x00\x2c\x6e\x7a\x00\x90\x00\x3f\x37\x52\x00\x9e\x79\x75\x00\x75\x00\xd3\xd2\xe7\x8e\x3e\x2b\x61\xe4\xaf\x0e\x30\xee\x0f\x95\xdb\xc2\x11\x00\x35\xc9\xd9\x17\x52\x00\xe8\x3b\x75\x00\x52\x00\x75\x00\x99\x13\x9a\x9e\x08\x6c\x1b\xec\x52\x00\x52\x00\xc5\x58\x3d\x00\xfe\xc4\x3d\x00\x25\x81\x3d\x00\x2f\xcb\x70\xf5\x88\x69\x90\x00\x75\x00\x1d\xc4\x3d\x00\xa0\x01\x11\x00\x74\xb2\x90\x00\xb7\x66\x42\x41\x3d\x00\x77\xba\x84\xe7\x35\x35\xb4\xa9\x0f\x3b\xc3\xeb\xc2\xf8\xbd\xb0\xc3\x21\xaa\xaf\xd4\x38\x7c\x96\x06\x60\x0e\xce\xbe\x17\x7a\x00\x90\x00\x75\x00\x73\xba\xe4\xf4\xcb\x99\x3d\x00\x9c\x02\x52\x00\x8e\xb8\x90\x00\x3d\x00\xe1\xfe\x50\x15\x3d\x00\x89\x7e\xf8\xa8\x5e\x38\x7a\x00\xe7\xd3\x90\x00\x28\x00\xbd\xab\x52\x00\xf9\x12\x52\x00\x75\x00\x50\x9d\x87\x2e\x64\x27\xab\xf9\xe3\xbb\x9c\x02\x3d\x00\xad\x16\x07\xb2\xfa\x73\x49\xbc\x52\x9b\x75\x00\x3d\x00\x52\xd5\xf7\x07\x52\x00\xab\xdf\xb2\x6a\xe7\xd0\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x14\xa7\x90\x00\x28\x00\x7a\x00\x52\x00\x11\x00\x11\x00\x28\x00\x90\x00\xdc\x00\xfe\xea\xc6\xe6\xf6\x73\xf6\x65\x15\x01\xd5\x1e\xd1\x9e\x2b\x6a\x4b\xec\xd3\x19\xa4\x2d\xb9\xcd\xd2\x1f\x54\x10\x5e\x3c\x28\x00\x51\x8d\x78\x9d\x85\xef\x28\x00\x75\x00\x78\x49\x03\xa3\xd8\x8f\x08\x0c\x8f\x2f\x52\x00\x32\x6a\x3d\xe5\x86\x1d\xe3\xea\x0d\x31\xdb\x60\x2f\x64\x8d\x47\x9f\x46\xcf\xa9\x82\xd4\x52\x00\x47\x3b\x54\x60\x4a\x5e\x79\xd0\xed\xe3\x30\xc1\x3b\x5b\x8f\x4c\x63\x6d\x71\xf0\x02\x4e\x58\xdb\x52\x00\x28\x00\x8c\xe3\x75\x00\x69\xc8\xc4\x24\x28\x00\x1a\x31\x44\xe7\xd9\x67\x65\x92\xb4\x24\x51\x57\x23\x52\x40\x31\x4a\x3f\x00\x1c\x8e\x9d\x75\x00\x7d\x80\x52\x00\x67\x07\xfd\xc9\xa3\x7b\x14\x0d\x37\x88\x65\x55\x75\x00\xd4\xa1\x06\x7d\x43\x8a\x68\xad\xf3\x37\x12\x95\x8a\x50\x52\x00\x82\xc1\x39\xc6\x88\x59\xd3\xc7\xbd\x1b\x5c\xd0\xb8\x30\x01\xde\xf0\x89\xb2\x9b\x6e\x0f\x52\x00\x57\x5f\x48\x40\x4a\x3e\x6a\xee\xe1\xe3\x15\x32\xb4\x77\xcf\x94\x02\x0a\xb0\xec\x0d\xd6\xe1\xbe\xb9\x1a\xcd\xcc\x90\x00\x41\x00\xd6\xf5\x52\x00\x50\xd4\xb0\xf8\x19\x0e\xf5\x0b\x14\x0d\xa6\xd7\x21\x9c\x75\x00\xe6\x1e\x9d\x25\xdb\x31\xc5\xb4\xd5\x46\x00\x14\xcc\x64\x90\x00\x82\xc1\xe7\x4e\xf4\x24\xdd\x0d\x67\x3e\xb2\x2d\xb1\x16\xfb\xbd\xaa\x89\x02\x50\x41\xc7\x28\x00\x52\x97\x90\x00\xf9\x57\x90\x00\x41\x00\xa1\x2d\x41\x00\x07\x33\x75\x00\x75\x00\xe4\xcf\x61\x10\xc8\x35\x07\xff\x17\x0c\x15\xef\xd8\xe3\x0e\x53\xab\xf8\x84\xe4\x74\xe9\x11\x02\x34\x09\xfe\x86\x96\x97\x75\x00\x7d\x7c\x68\xfc\x41\xfe\xe8\x78\x55\x23\xfe\x0f\x17\xef\x08\xc1\x98\x19\x68\x76\x0c\x54\x90\x00\x28\x00\x8e\x7d\x75\x00\x31\x31\x36\x9f\x90\x00\xfe\xc4\xe0\x7c\x12\xa9\x32\xa8\xbf\xd7\x41\x00\x36\xf4\x14\x95\x61\xe9\x06\x52\x0f\x42\x5c\x3d\x16\xef\x43\x2e\x4d\x78\xcf\xb7\x31\xea\x28\x00\x0f\xcf\x2f\xbe\x13\xa7\x9b\xbe\xdd\xd5\x6f\x64\x23\x27\x26\xf0\x0e\x46\x5f\xec\x9a\x41\x4b\xec\x0c\x34\x84\xc5\x81\x8e\xad\x1d\x70\x73\xab\x71\x15\x94\xbb\x34\x3e\x0b\x75\x00\x06\x7b\xc4\xe7\x5e\x79\xcc\x35\x44\x69\x19\xd9\xe8\x1d\x35\x8b\xc5\x65\x33\x96\x62\x6d\x0c\xac\xe7\xd5\x11\x00\x11\x00\x3f\x47\x7a\x00\x81\xed\x19\x7c\xee\x73\xa6\x3e\xc2\x6d\xd1\x87\xea\xe3\x90\x00\x7a\x00\x21\xa4\x53\xcf\xd6\x42\xfd\x91\xe0\x75\x52\x38\x98\x76\x83\xc3\x26\x99\x9f\xa3\xf0\x0a\x7a\x00\x5c\x0c\x75\x00\x5f\x21\x11\x00\xea\x30\xa7\x59\x6c\xc2\x11\x39\x69\x0d\xef\x60\x88\x3f\x74\xee\x39\x09\xe5\x3f\x4f\x3a\x77\x75\x17\x82\x7f\xb0\x42\x21\x2c\xda\xde\x91\x3e\x00\x3b\xf3\x75\x00\x86\x06\xf2\xc6\xf8\xc2\x04\xed\xd9\x1a\xd2\x8a\x56\x37\x27\xc4\x43\x26\xcb\x09\xc0\x55\x89\x93\x26\xeb\xbe\x65\xca\xf8\x90\x00\x7a\x00\x0d\x43\x90\x00\xce\xfe\x18\xa4\xef\x9b\xc7\x02\x20\x48\x1e\x99\x29\xe3\x7a\x00\x7a\x00\x41\xa4\x06\xd5\x00\x65\x38\x40\xa1\x51\x30\x2f\x16\xef\xa7\x82\x14\xef\x30\xb2\xaa\x55\x28\x00\x8f\x40\x68\x9c\xc4\x25\xd1\xa3\x01\x07\x75\x00\x73\x22\x93\x95\x1b\xad\x1f\x32\x81\x2b\x74\x44\xcb\x03\x97\x16\xc3\xfa\x25\x72\x4b\xec\xdd\x69\xfe\x62\x16\xd6\xa0\xfc\x50\xdc\x75\x99\x28\x00\x65\x9a\x82\x06\x99\x0b\x75\x00\x5f\x8a\x8f\xec\x8a\xda\x08\xfe\x10\x2f\x87\xa5\xeb\x2b\xa3\x31\x0d\xf4\x7c\x40\x71\xf0\xad\xb5\x46\x43\x41\x00\x52\x00\xc3\xe7\x75\x00\xc6\xc5\xc9\x73\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x3e\x1b\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x12\x03\x00\x80\x75\x00\x94\xbf\x7f\xbd\xe9\x65\x36\xa3\x8a\x7a\x44\xbe\xfa\xfd\x08\x89\xa8\x57\xcd\xab\xdb\xc7\x43\x3d\x00\x2a\x38\x75\x00\x90\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x11\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\xc3\x7d\xc7\x43\x3d\x00\x7e\x38\x75\x00\x7a\x00\x39\xb8\x3d\x00\x31\x00\x75\x00\x41\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\xba\x14\x90\x9a\x3d\x00\xc5\x75\xc7\x43\x3d\x00\x85\x38\x75\x00\x28\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x70\x40\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x1f\x5a\xd5\x27\x41\x01\x20\x00\x90\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\xfd\x23\x3d\x00\x7a\x00\x7a\x00\xd5\x58\x3d\x00\xe0\xd7\x11\x00\x90\x00\xf8\x57\x3d\x00\xbb\x88\x3d\x00\xac\x02\x52\x00\xd3\x39\x41\x00\x28\x00\x11\x00\xd5\x58\x3d\x00\x06\x8d\x28\x00\x28\x00\x1e\x5b\x3d\x00\x57\x44\x31\x24\x5c\xd7\x3d\x00\x3d\x00\x46\x04\x52\x00\x72\x2d\x28\x00\xf3\xc9\x75\x00\x3d\x00\xea\x75\x08\x3d\x00\x41\x00\x8c\xc2\x11\x00\x41\x00\x5e\xb5\x11\x00\x30\x31\x75\x00\x75\x00\x7a\x00\x7a\xe7\xcc\xd1\x90\x00\x9f\xd3\x75\x00\x41\x00\x75\x00\xce\xee\xfc\x99\x28\x00\x48\xdc\xd5\x15\xa4\xdf\x41\x00\x75\x00\x9c\x72\x3d\xfd\x4c\x7b\xb2\xc9\xbc\x75\x00\x07\xf9\x2f\x02\xa4\x7e\x60\xc6\xd3\x1f\x90\xba\x2f\x23\x35\x48\xb2\xd4\x4e\x90\xbe\x4b\x05\xca\x11\xde\x29\x39\x07\x96\xeb\x0a\xfb\x03\x16\xa6\x75\x00\xe6\x38\xf5\xfd\xa8\x6b\xf5\x13\xb2\x75\x00\x67\xe8\x1c\x1c\xe4\x3c\x55\xce\x6f\xa5\x58\x98\xf1\x40\xdd\x3f\xba\xee\xd8\x66\xd7\x42\xa0\x88\xc2\xa5\x0a\xe5\x62\x8f\x96\x60\x75\x00\x4e\xf5\x76\x5a\x67\xf5\x67\x77\x76\xb9\xa6\x29\x75\x00\x95\x52\x00\x98\x7f\x7a\x00\x11\x6d\x08\x1a\x75\x00\x41\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x86\x14\x5c\xb9\x3d\x00\x86\x14\x64\x18\x3d\x00\xba\x14\x3e\x1c\x3d\x00\x13\x65\x06\x42\x3d\x00\x09\x64\x02\x42\x3d\x00\xba\x14\xfe\xe2\x3d\x00\x02\x01\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x05\xe1\x90\x00\x11\x00\x52\x00\x90\x00\x11\x00\x41\x00\x28\x00\x7a\x00\xc3\xfb\xd6\xcc\x42\x61\x53\xe4\x25\xb4\x27\x41\x01\x20\x00\x3d\x00\x51\x00\xac\x02\x90\x00\x52\x00\xd5\x58\x3d\x00\xf6\xfb\x52\x00\x28\x00\x1e\x5b\x3d\x00\x54\xfd\x17\xb4\x60\xd8\x3d\x00\x41\x00\x90\x00\xf8\x57\x3d\x00\x5f\x8b\x3d\x00\xcf\x01\x28\x00\x9b\x3b\x28\x00\x3d\x00\x3c\x03\x28\x00\xf9\x2f\x41\x00\x87\xff\x41\x00\xb5\x25\x3d\x00\x39\x00\x7a\x00\x80\xbf\x3d\x00\xee\xcc\x75\x00\x3d\x00\xdd\x70\x08\x3d\x00\xba\x33\x5b\xe9\x75\x00\xe1\x7e\xac\x12\x52\x00\xbe\xeb\xdc\x42\x3d\x00\xd7\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x7b\x16\x9e\x4c\x3d\x00\x96\x5b\x75\x00\x7a\x00\xf8\xba\x3d\x00\xfe\x41\x06\x42\x3d\x00\x13\x40\xc7\x43\x3d\x00\xe5\x38\x75\x00\x28\x00\x39\xb8\x3d\x00\xf0\x00\x75\x00\x90\x00\xc4\xba\x3d\x00\x6a\x17\x16\x8d\x3d\x00\x7a\x00\x52\x00\x41\x00\x90\x00\x1f\x1f\x90\x00\x52\x00\x11\x00\x7a\x00\x11\x00\x28\x00\x28\x00\x41\x00\xd9\x05\x0c\x30\xd8\x00\x95\x6d\x4c\xc4\x27\x41\x01\x20\x00\x3d\x00\x51\x00\xac\x02\x52\x00\x11\x00\x65\x59\x3d\x00\x34\xfb\x42\xb6\x52\x00\xff\xbc\x3d\x00\x5b\x21\x31\x6f\x3d\x00\x85\x93\x7a\x00\xde\x25\x3d\x00\x3d\x00\xcf\x01\x41\x00\x04\x94\x11\x00\x3d\x00\xcf\x01\x28\x00\xdd\x32\x28\x00\x3d\x00\xac\x02\x90\x00\x7d\x94\x90\x00\x11\x00\x41\x00\x00\x59\x3d\x00\x2b\xdb\x70\x36\x75\x00\x90\x00\x3d\x00\x1e\x47\x08\x3d\x00\x94\x41\x30\xe0\x9f\x41\x3d\x00\x52\x00\x88\x4b\x87\xb5\x7a\x00\x5c\x37\x75\x00\x28\x00\x75\x00\xef\x03\x22\xd9\x3d\x00\x6b\x91\xf7\x01\xdc\x34\xef\x2d\x5e\x00\x98\x41\x3d\x00\x8a\xfe\xad\x46\xd1\x75\x00\x20\xb2\x01\x45\x05\x03\x07\x99\xf6\xa6\x5b\x9c\x00\x13\x0c\x0d\xb1\x17\xd3\x16\x96\xce\xaf\x3e\xaa\xc7\xc2\x08\xc4\x61\xf9\x88\x52\x00\x11\x00\x11\xb8\x75\x00\xa0\xf4\xfc\x03\x11\x00\x7a\x00\x83\xd7\x7a\x00\x90\x00\x0b\x0b\x7a\x00\x61\x8d\x75\x00\x75\x00\xfa\x70\x31\x7a\x86\x11\x06\x80\xab\x3b\x5c\xed\xb6\x79\x4a\xd2\x7a\x00\x28\x00\xc2\x00\x26\xc1\xb6\x8f\x5d\x6a\x29\xa2\x75\x00\x30\xa4\x28\x00\xbf\x74\xf0\xfc\xd7\xfe\x0a\x06\x22\x46\x10\x6b\x21\x68\x71\xf0\xda\x12\xfa\xbc\x41\x00\x41\x00\x57\x42\x75\x00\x62\x6a\xf2\x5c\x11\x00\x90\xff\x02\x42\x3d\x00\x6c\x17\x4e\x0e\x3d\x00\x9c\xde\x75\x00\x7a\x00\x3d\x00\x75\x00\xff\x5c\x75\x00\x28\x00\xf8\xba\x3d\x00\xd1\x7b\xc7\x43\x3d\x00\x4f\x38\x75\x00\x7a\x00\x39\xb8\x3d\x00\x31\x00\x75\x00\x90\x00\xf8\xba\x3d\x00\x1f\x49\x06\x42\x3d\x00\x07\x38\x02\x42\x3d\x00\x6a\x17\x13\xc7\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x55\x97\x90\x00\x7a\x00\x90\x00\x52\x00\x11\x00\x11\x00\x28\x00\x28\x00\xdb\x8a\xe4\x27\x41\x01\x20\x00\x80\xce\x68\x00\x3d\x00\x51\x00\xac\x02\x11\x00\x52\x00\x65\x59\x3d\x00\x34\xfb\x42\xb6\x28\x00\x46\xbb\x3d\x00\xaa\x00\x52\x00\x1c\xba\x3d\x00\x3d\x00\xa2\xa7\x1a\x4b\x17\x50\x35\x48\xf0\xb3\xf3\x5d\x4a\x3b\x45\x7d\x90\x00\x41\x00\x7a\x00\xd5\x58\x3d\x00\x78\x32\x41\x00\x90\x00\x3b\x58\x3d\x00\xa0\x39\x3d\x00\x7e\x7f\xb5\xfd\x57\xe7\x57\x3c\x52\x04\x9d\x17\x0a\xfd\x48\x5e\x11\x00\x3d\x00\xd7\x02\x11\x00\xf7\x6b\x52\x00\x94\x22\x75\x00\x90\x00\x3d\x00\xd5\x53\x08\x3d\x00\x75\x00\xd5\x17\x4b\x75\xf3\xdc\x77\xa7\x87\xa2\x9c\x02\x3d\x00\xea\x58\x1d\xf1\x4c\x76\x28\x00\x62\xe3\x7a\x00\x3d\x00\x1f\x22\x62\x43\x3d\x00\x75\x00\x50\x92\x11\x00\xa7\xc0\x72\x27\xf8\x8c\x93\x76\x48\xc9\xa3\x1c\x00\xdd\xf2\x16\x8c\x68\x8f\x9e\x75\x00\x1b\x38\x52\x00\x13\xd2\x2e\x64\x3f\x38\x75\x00\x52\x00\xf3\xb8\x3d\x00\x31\x59\xf6\x59\xa7\xbf\xa7\xb3\x9d\xf3\xbd\x00\x62\xab\x13\xc5\x7b\x16\xc6\x7f\x3d\x00\xe8\x5b\x75\x00\x52\x00\xf8\xba\x3d\x00\xa8\x61\xdc\x42\x3d\x00\x9c\xde\x75\x00\x52\x00\x3d\x00\x75\x00\x3f\x38\x75\x00\x52\x00\xc4\xba\x3d\x00\x7b\x16\x41\x90\x3d\x00\x51\x5c\x75\x00\x11\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x28\x00\xc4\xba\x3d\x00\xba\x14\x06\xdd\x3d\x00\x73\xa5\xc7\x43\x3d\x00\x24\x38\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x45\x56\x90\x00\x7a\x00\x11\x00\x90\x00\x11\x00\x52\x00\x28\x00\x41\x00\x60\x4b\xf3\x27\x41\x01\x20\x00\xc0\x06\x0b\x00\x3d\x00\x51\x00\xac\x02\x7a\x00\x41\x00\x65\x59\x3d\x00\x34\xfb\x42\xb6\x52\x00\x46\xbb\x3d\x00\xaa\x00\x90\x00\x46\xbb\x3d\x00\xc3\x00\x52\x00\xb6\xba\x3d\x00\x52\x00\x11\x00\xf8\x57\x3d\x00\x1a\xab\x3d\x00\xac\x02\x7a\x00\x07\x47\x11\x00\x7a\x00\x7a\x00\xf8\x57\x3d\x00\x19\xf2\x3d\x00\xd7\x02\x28\x00\x86\x54\x7a\x00\x08\x71\x75\x00\x7a\x00\x3d\x00\x0f\x00\x08\x3d\x00\x78\x23\x25\x65\xf5\x29\xb9\x75\x75\x00\x3d\x00\xd2\x64\x22\xdd\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x11\x00\x3d\x00\x75\x00\x8a\xec\x02\x42\x3d\x00\x7b\x16\x94\x8e\x3d\x00\xc4\x5b\x75\x00\x28\x00\xf8\xba\x3d\x00\xd7\x55\x02\x42\x3d\x00\x86\x14\x66\x5d\x3d\x00\xba\x14\xc7\x7f\x3d\x00\x5b\x65\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x53\x7d\x90\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x28\x00\x28\x00\x90\x00\x21\x60\x6c\x47\x59\x00\x20\x00\x99\x68\x3a\x23\x41\x01\x68\x44\x04\x00\x00\xe9\x6c\xc0\xc2\xff\xf7\xf9\x68\x0e\x24\x41\x01\x68\x44\x04\x00\x00\xe9\x5b\xc0\xc2\xff\x68\xd3\x21\x41\x01\x68\x44\x04\x00\x00\xe9\x4c\xc0\xc2\xff\x68\x94\x25\x41\x01\x68\x44\x04\x00\x00\xe9\x3d\xc0\xc2\xff\x68\xe9\x26\x41\x01\x68\x44\x04\x00\x00\xe9\x2e\xc0\xc2\xff\x68\xd6\x0e\x41\x01'
#114127B4
#state.data = b''

state.esp = 0x6F8A8
state.VMA = 0x10f0429c ##Where VM registers in mem
VMA = 0x10f0429c

state.push(0x12345678)
state.push(0x257)

tmp = state.esp

state.push(0xFF0F0000) #eflags
state.push(0xFF1F0000) #eax
state.push(0xFF2F0000) #ecx
state.push(0xFF3F0000) #edx
state.push(0xFF4F0000) #ebx
state.push(tmp) #esp
state.push(0xFF6F0000) #ebp
state.push(0xFF7F0000) #esi
state.push(0xFF8F0000) #edi

state.reg4[R_EIP] = 0
state.reg4[R_31] = 0xFCB2A014
state.reg4[R_ImgBase] = 0x10000000 #imgBase
#state.reg4[0x11] = 0x6F8C4

state.wMem(0x000A2EC0, b'\x0A\xB2\xAC\x0A')


#state.wMem(0x10EFD721, b'\x46\x67\x38\xb8')
#state.wMem(0x10EFD721, b'\xbe\x69\xd9\xb9')
state.wMem(0x10EFD721, b'\x4e\x67\x9b\xb8')
state.wMem(0x1103f789, b'\x08\x10\x43\x11') #0x11431008
state.wMem(0x11431008, b'\x0A\xB2\xAC\x0A')

#state.wMem(0x1103f789, b'\xC0\x2E\x0A\x00\xDF\x90\x00\x28')
#state.wMem(0x11062511, b'\x0C\xFD\x6D\x1F')
state.wMem(0x11062511, b'\x0C\xFD\x6D\x1F')
state.wMem(0x110B727D, b'\x69\x7A\xB8\xED')
state.wMem(0x1105915F, b'\x59\x89\xC1\x58')
state.wMem(0x1109D8BB, b'\x7F\xA5\xEC\x70')
state.wMem(0x110AA61B, b'\x10\xBF\xEE\x94')
state.wMem(0x110BCE23, b'\x73\x58\x01\xF3')



state.wMem(0x7D0B736F, b'\xFF\xFF\xF7\xFF')
state.wMem(0x7C80003C, b'\x0F\x00\x00\x00')
state.wMem(0x7C800117, b'\x00\x3E\xB6\x00')

##7C800000 - kernel32

state.AddRoute(0x257, 0)

state.OnEnd = FNC1
#state.AddRoute(0x444, 0, False)

ERR = list()

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
			
		log.append("stack: ({:X})".format(state.esp))
		i = state.esp
		while i < state.esp + 0x10:
			log.append(hex(state.rMem4(i) ))
			i += 4
	
		#print()

print("\n\n#################################################\n\n")
for k,v in sorted(PARSED.items()):
	for l in v:
		print(l)
		pass
	print()


for l in ERR:
	print(l)
	pass
