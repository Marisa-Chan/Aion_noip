#!/usr/bin/python3

import sys
VMA = 0
R_EIP = 0x59
R_FIRSTFUNCPTR = 0x56

#4bt
r118 = 0x118
r125 = 0x125
r102 = 0x102
r114 = 0x114
r8 = 0x8

rc9 = 0xc9
r106 = 0x106

#2bt
ref = 0xef
r2f = 0x2f

r112 = 0x112

R_ImgBase = 0x99 
R_OldBase = 0x45

def U32(numb):
	return numb & ((1 << 32) - 1)

def JCC(tp):
	if (tp == 0x72):
		return "JNB/JNC [CF == 0]"
	elif (tp == 0x2e or tp == 0x59):
		return "JE/JZ [ZF == 1]"
	elif (tp == 0x99):
		return "JNE/JNZ [ZF == 0]"
	elif (tp == 0x3c):
		return "JA/JNBE [CF == 0 & ZF == 0]"
	elif (tp == 0xff):
		return "JB/JC/JNAE [CF == 1]"
	elif (tp == 0x9a):
		return "JBE/JNA [CF == 1 | ZF == 1]"
	elif (tp == 0x58):
		return "JG/JNLE [ZF == 0 & SF == OF]"
	elif (tp == 0x11):
		return "JGE/JNL [SF == OF]"
	elif (tp == 0x63):
		return "JL/JNGE [SF != OF]"
	elif (tp == 0x59):
		return "JLE/JNG [ZF == 1 | SF != OF]"
	elif (tp == 0x60):
		return "JNO [OF == 0]"
	elif (tp == 0xe9):
		return "JNP/JPO [PF == 0]"
	elif (tp == 0xb4):
		return "JNS [SF == 0]"
	elif (tp == 0x3):
		return "JO [OF == 1]"
	elif (tp == 0x71):
		return "JP/JPE [PF == 1]"
	elif (tp == 0x95):
		return "JS [SF == 1]"
	else:
		sys.exit("UNKNOWN JCC TP: {:02X}".format(tp))

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
	pops = None
	regnms = None
	
	
	def __init__(self, vm, n, i, OnCopy = True):
		if OnCopy:
			self.mem = vm.mem.copy()
			self.pops = vm.popping[:]
			self.regnms = vm.regnames.copy()
		else:
			self.mem = vm.mem
			self.pops = vm.popping
			self.regnms = vm.regnames
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
	
	regnames = None
	
	popping = None
	
	dataaddr = 0
	imgbase = 0
	
	printpos = True
	
	def __init__(self):
		self.mem = VMem()
		self.Routes = list()
		self.regnames = dict()
		self.popping = list()
		
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
		elif name == "reg8":
			return VMReg(self.VMA, 8, self.mem)
		
		raise AttributeError
		
	def read2(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos + 2 >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.reg2[R_EIP], dx, len(self.data)))
		
		return int.from_bytes(self.data[pos:pos+2], byteorder="little")
	
	def read4(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos + 4 >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.reg2[R_EIP], dx, len(self.data)))
		
		return int.from_bytes(self.data[pos:pos+4], byteorder="little")
	
	def read(self, dx = 0):
		pos = self.reg4[R_EIP] + dx
		if pos < 0 or pos >= len(self.data):
			sys.exit("Erro in Read2: EIP = {:02X} dx = {:02X} len = {:02X}".format(self.reg2[R_EIP], dx, len(self.data)))
		
		return int(self.data[pos])
	
	def chEIP(self, step):
		self.reg4[R_EIP] += step
	
	def GetPos(self):
		if not self.printpos:
			return ""
		return "{:08x}:  ".format(self.reg4[R_EIP] + self.dataaddr)
	
	def AddRoute(self, next, eip, _OnCopy = True):
		rt = VMRoute(self, next, eip, _OnCopy)
		self.Routes.append(rt)
	
	def RegName(self, r):
		if r in self.regnames:
			return self.regnames[r]
		else:
			return "R_{:02X}".format(r)
	
	
	def VM_ADD_R8_V(self, log, r1, v):
		log.append("{}ADD {}, {:02x}".format(self.GetPos(), self.RegName(r1), v))
	
	def VM_SUB_R8_V(self, log, r1, v):
		log.append("{}SUB {}, {:02x}".format(self.GetPos(), self.RegName(r1), v))
	
	def VM_ADD_R8_R8(self, log, r1, r2):
		log.append("{}ADD {}, {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
		
	def VM_MOV_R8_R8(self, log, r1, r2):
		log.append("{}MOV {}, {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_R8_MR2(self, log, r1, r2):
		log.append("{}MOV {}, word [{}]".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_R8_MR(self, log, r1, r2):
		log.append("{}MOV {}, [{}]".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_R8_MR4(self, log, r1, r2):
		log.append("{}MOV {}, dword [{}]".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_MR_R8(self, log, r1, r2):
		log.append("{}MOV [{}], {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_MR4_R4(self, log, r1, r2):
		log.append("{}MOV dword [{}], {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_MOV_MR4_V(self, log, r, v):
		log.append("{}MOV dword [{}], {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_MOV_MR_V1(self, log, r, v):
		log.append("{}MOV byte ptr [{}], {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_MOV_R8_V(self, log, r, v):
		log.append("{}MOV {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_MOV_R4_V(self, log, r, v):
		log.append("{}MOV dword {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_INC_R8(self, log, r):
		log.append("{}INC {}".format(self.GetPos(), self.RegName(r)))
	
	def VM_DEC_R8(self, log, r):
		log.append("{}DEC {}".format(self.GetPos(), self.RegName(r)))
	
	def VM_PUSH_R8(self, log, r):
		log.append("{}PUSH {}".format(self.GetPos(), self.RegName(r)))
		
		vl = None
		if r in self.regnames:
			vl = self.regnames[r]
		
		self.popping = [vl,] + self.popping
	
	def VM_PUSH_MR(self, log, r):
		log.append("{}PUSH [{}]".format(self.GetPos(), self.RegName(r)))
		self.popping = [None,] + self.popping
	
	def VM_UNSHUFFLE(self, log, s, d):
		log.append("{}UNSHFL".format(self.GetPos()))
		tmp = [None] * len(s)
		
		for i in range(len(s)):
			tmp[i] = self.RegName(s[i])
			
		for i in range(len(d)):
			self.regnames[ d[i] ] = tmp[i]
			#log.append("\tVM[{:02x}] <-- VM[{:02x}]".format(d[i], s[i]))
	
	def VM_CMP_R4_V4(self, log, r, v):
		log.append("{}CMP {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_CMP_MR4_V4(self, log, r, v):
		log.append("{}CMP dword [{}], {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_CMP_R8_V(self, log, r, v):
		log.append("{}CMP {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_POP_R(self, log, r):
		if len(self.popping):
			reg = self.popping[0]
			self.popping = self.popping[1:]
			
			if reg != None:
				self.regnames[r] = reg
			
			log.append("{}POP VM[{:02x}] = {}".format(self.GetPos(), r, reg))
		else:
			#self.regnames[r] = "R_{:02X}".format(r)
			if r in self.regnames:
				log.append("{}POP {}? ({:02x})".format(self.GetPos(), self.regnames[r], r))
			else:
				log.append("{}POP VM[{:02x}]".format(self.GetPos(), r))
	
	
	def VM_XCHG_R_R(self, log, r1, r2):
		#log.append("VM[{0:02X}] <=> VM[{1:02X}]".format(r1, r2))
		
		if r1 not in self.regnames or r2 not in self.regnames:
			#log.append("Can't exchange regnames")
			pass
		else:
			t = self.regnames[r1]
			self.regnames[r1] = self.regnames[r2]
			self.regnames[r2] = t
	
	
	def VM_JCC(self, log, t, jmp, ins):
		if jmp & 0x80000000:
			jmp = -(jmp & 0x7FFFFFFF)
		
		log.append("{}{} {:02x}".format(self.GetPos(), JCC(t), self.dataaddr + self.reg4[R_EIP] + jmp))
		
		self.AddRoute(ins, self.reg4[R_EIP] + jmp)
	
	
	def VM_IMUL_R_V(self, log, r, v):
		log.append("{}IMUL {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_IMUL_R4_V(self, log, r, v):
		log.append("{}IMUL dword {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	
	def VM_REP_MOV(self, log, r1, r2, t):
		s = "+"
		if t & 0x400:
			s = "-"
		log.append("{}{}REP MOV byte [{}], [{}]".format(self.GetPos(), s, self.RegName(r1), self.RegName(r2)))
		
		
	def VM_ROL_R1(self, log, r, v):
		log.append("{}ROL byte {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	
	def VM_JMP(self, log, jmp, ins):
		if jmp & 0x80000000:
			jmp = -(jmp & 0x7FFFFFFF)
		
		log.append("{}JMP {:02x}".format(self.GetPos(), self.dataaddr + self.reg4[R_EIP] + jmp))
		
		self.AddRoute(ins, self.reg4[R_EIP] + jmp)
		self.run = False
		
	def VM_RCL_R8_V(self, log, r, v):
		log.append("{}RCL {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
		
	
	def VM_ADD_MR1_V(self, log, r, v):
		log.append("{}ADD byte [{}], {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_AND_R1_V(self, log, r, v):
		log.append("{}AND byte {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_TEST_R_R(self, log, r1, r2):
		log.append("{}TEST {}, {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_TEST_R4_R4(self, log, r1, r2):
		log.append("{}TEST dword {}, dword {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2)))
	
	def VM_TEST_R2_V(self, log, r, v):
		log.append("{}TEST {}, {:02x}".format(self.GetPos(), self.RegName(r), v))
	
	def VM_SHL_R8_R4_V(self, log, r1, r2, v):
		log.append("{}SHL {}, dword {}, {:02x}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), v))
		
		
	def VM_OR_R8_R4_R4(self, log, r1, r2, r3):
		log.append("{}OR {}, dword {}, dword {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), self.RegName(r3)))
	
	def VM_XOR_R8_R4_R4(self, log, r1, r2, r3):
		log.append("{}XOR {}, dword {}, dword {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), self.RegName(r3)))
	
	def VM_XOR_R8_R4_V(self, log, r1, r2, v):
		log.append("{}XOR {}, dword {}, {:02x}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), v))
		
	def VM_ADD_R8_R4_R4(self, log, r1, r2, r3):
		log.append("{}ADD {}, dword {}, dword {}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), self.RegName(r3)))
	
	def VM_ADD_R8_R4_V(self, log, r1, r2, v):
		log.append("{}ADD {}, dword {}, {:02x}".format(self.GetPos(), self.RegName(r1), self.RegName(r2), v))
		


def UDW(v):
	return v & 0xFFFFFFFF

def UW(v):
	return v & 0xFFFF

def UB(v):
	return v & 0xFF


def OP_68(state, log):
	state.next = state.read2(0)
	state.chEIP(+4)

def OP_4bc(state, log):
	log.append("{}INIT \n".format(state.GetPos(), state.next))
	
	state.reg4[r118] = 0
	state.reg4[r102] = 0
	state.reg4[rc9] = 0
	state.reg4[r114] = 0
	state.reg4[r106] = 0
	state.reg2[ref] = 0
	state.reg2[r2f] = 0
	state.reg2[r112] = 0
	state.reg4[r125] = 0
	state.reg4[r8] = 0
	state.next = state.read2(0)
	state.chEIP(+2)

def OP_270(state, log):
	state.next = state.read2(2)
	log.append("{}STORE STACK {:02x}".format(state.GetPos(), state.read2(0)))
	state.regnames[state.read2(0)] = "RSP"
	state.chEIP(+4)
	
def OP_20c(state, log):
	state.reg4[r118] += 0xe5fc0f5f
	state.reg4[r118] |= 0x319108d4
	state.reg4[r102] += 0x414bfb8
	
	state.VM_XCHG_R_R(log, state.read2(8), state.read2(12))
	
	state.reg4[r118] &= state.read4(4)
	state.reg4[r118] &= state.read2(0)
	
	state.reg4[r102] |= 0x7efce956
	
	state.reg2[ref] ^= state.read2(0)
	
	addr = state.reg2[ref] ^ 0x1f4
	
	state.VM_POP_R(log, addr)
	#log.append("VMESP[{:02x}] += 8".format(state.read2(2)))
	
	t = state.read2(14) + state.reg4[r118] + 0x8607ba31
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)

def OP_592(state, log):
	t = UDW(state.read2(8) - state.reg4[r125])
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x55fa25ad
	state.reg2[ref] += t
	state.reg4[r102] &= 0x509bd621
	state.reg4[r118] += 0xad583b4d
	
	addr = UW(state.reg2[ref] + 0x5044)
	
	state.VM_POP_R(log, addr)
	#log.append("VMESP[{:02x}] += 8".format(state.read2(0)))
	
	t = UDW(state.read2(6) - state.reg4[r118] ^ 0xe0c3511)
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)

def OP_98(state, log):
	state.reg4[r118] += 0xdab75c3
	state.reg4[r102] += 0xe3430125
	state.reg2[ref] -= state.reg2[r118] + state.reg2[r125] + state.read2(2)
	
	state.reg4[r118] |= state.read4(6)
	
	addr = UW(state.reg2[ref] + 0xbf7c)
	
	state.VM_POP_R(log, addr)
	#log.append("VMESP[{:02x}] += 8".format(state.read2(0)))
	
	state.reg4[r118] |= 0xb9a82b4
	state.reg4[r102] &= 0x34734c79
	state.reg4[r102] += 0x8c02be50
	state.reg4[r118] += 0x8c02be50
	
	t = state.read2(4)
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_363(state, log):
	addr = state.read2(10)
	
	state.VM_POP_R(log, addr)
	#log.append("VMESP[{:02x}] += 8".format(state.read2(6)))
	
	state.reg4[r118] += 0x178c69b7
	
	t = state.reg4[r118] + state.read2(8)
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_4f0(state, log):
	addr = state.read2(10)
	
	state.VM_POP_R(log, addr)
	#log.append("VMESP[{:02x}] += 8".format(state.read2(2)))
	
	
	t = state.read2(8) + state.reg4[r118]
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+16)


def OP_549(state, log):
	r = state.read2(3)
	v = state.read(0)
	
	state.VM_ADD_R8_V(log, r, v)
	#state.reg8[r] += v
	
	t = state.read2(1) + state.reg4[r118] ^ 0x24ba9c5f
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+5)


def OP_85(state, log):
	t = state.read4(4) + state.reg4[r118] + state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0x4dd0d2aa
	state.reg4[r114] -= t
	state.reg4[r8] &= t
	
	t = state.read2(0x10) + state.reg4[r125]
	state.reg4[r118] += t
	state.reg2[ref] ^= t
	state.reg4[r118] &= state.read4(8)
	state.reg4[r102] &= 0x548e413a
	
	v = state.reg4[r114] ^ 0x1246a27b
	r = UW(state.reg2[ref] + 0xa341)
	
	state.VM_ADD_R8_V(log, r, v)
	
	t = state.read2(14) - state.reg4[r118] + 0x889b7740
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x12)


def OP_17e(state, log):
	log.append("{}VMESP LOAD VM[{:02x}]".format(state.GetPos(), state.read2(0)))
	t = state.read2(2) + state.reg4[r118] ^ 0x7f6a3338
	state.next = t & 0xFFFF
	state.chEIP(+4)


def OP_354(state, log):
	t = state.read2(6) - state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg2[ref] ^= t
	state.reg4[r102] += 0x26abd918
	
	t = state.read2(0)
	state.reg4[r118] += t
	state.reg4[r102] |= 0x5f291eda
	state.reg2[r2f] += t
	state.reg4[r118] += state.read4(2)
	
	r1 = UW(state.reg2[ref] + 0xecff)
	r2 = UW(state.reg2[r2f] + 0x1f06)
	
	state.VM_MOV_R8_R8(log, r1, r2)
	
	t = (state.read2(8) ^ state.reg4[r118]) + 0x5c64e2ca
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_1b1(state, log):
	t = state.read2(6)
	state.reg4[r102] |= 0x52e694ba
	state.reg2[ref] += (t - state.reg4[r118]) + state.reg4[r125]
	
	t = (state.read4(0) ^ state.reg4[r118]) - state.reg4[r102]
	state.reg4[r118] -= t
	state.reg4[r102] += 0x99c93bc5
	state.reg4[r114] -= t
	state.reg4[r8] += t
	
	r = UW(state.reg2[ref] + 0x1d53)
	v = state.reg4[r114]
	
	state.VM_ADD_R8_V(log, r, v)
	
	state.reg4[r102] ^= 0x1569bd5f
	
	t = state.read2(4) + 0xac4d98d1
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_23d(state, log):
	state.reg4[r102] += 0xba8c59f6
	
	t = state.read2(4) + state.reg4[r118]
	state.reg4[r118] -= t
	state.reg4[r102] ^= 0x3a859d01
	state.reg2[ref] += t
	state.reg4[r118] += 0x4420a45b
	
	t = (state.read2(2) + state.reg4[r118]) + state.reg4[r8]
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x45068d1
	state.reg2[r2f] -= t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] |= 0x3f0b036b
	
	state.reg4[r118] ^= state.read4(6)
	
	if state.reg4[r102] & 1:
		state.reg4[r102] &= 0x4d06d17f
	
	r1 = UW(state.reg2[ref] + 0xa581)
	r2 = UW(state.reg2[r2f] ^ 0x19ed)
	
	state.VM_MOV_R8_R8(log, r1, r2)
	
	t = state.read2(0) + state.reg4[r118] ^ 0x7929f493
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_40d(state, log):
	state.reg4[r118] |= 0xbad5188
	
	t = state.read2(10) ^ state.reg4[r118] ^ state.reg4[r8]
	state.reg4[r118] &= t
	state.reg4[r102] ^= 0x73e9e422
	state.reg2[r2f] += t
	
	t = (state.read2(2) + state.reg4[r125])
	state.reg4[r118] &= t
	state.reg4[r102] += 0xa1383fad
	state.reg2[ref] -= t
	
	r1 = state.reg2[ref]
	r2 = UW(state.reg2[r2f] + 0xa480)
	
	state.VM_ADD_R8_R8(log, r1, r2)
	
	t = state.read2(0) + state.reg4[r118] + 0x826289eb
	state.reg4[r118] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)

def OP_444(state, log):
	t = state.read2(6) ^ state.reg4[r118]
	state.reg4[r118] |= t
	state.reg4[r102] &= 0x783b6c5a
	state.reg2[ref] += t
	
	t = (state.read(8) ^ state.reg4[r118] ^ state.reg4[r102])
	state.reg4[r118] += t
	state.reg4[r102] += 0x5d8588c5
	state.reg4[r114] += t
	
	r = state.reg2[ref]
	v = UB(state.reg4[r114] + 0x5b)
	
	state.VM_MOV_MR_V1(log, r, v)
	
	state.reg4[r118] &= state.read4(0)
	
	t = state.read2(9) + 0xe789a18b
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+11)


def OP_4d1(state, log):	
	t = state.read2(6) + state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x2d7ccc0
	state.reg2[ref] ^= t

	r = UW(state.reg2[ref] + 0x70e2)
	
	state.VM_INC_R8(log, r)
	
	state.reg4[r118] &= 0x6f6b7752
	
	t = (state.read2(4) ^ state.reg4[r118]) + 0x41ecb799
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_2aa(state, log):	
	state.VM_XCHG_R_R(log, state.read2(8), state.read2(10))
	
	t = state.read2(12) + state.reg4[r118]
	state.reg4[r118] &= t
	state.reg2[ref] -= t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x1a027f88
	
	state.reg4[r118] ^= state.read4(0)
	
	r = UW(state.reg2[ref] ^ 0xc8e)
	
	state.VM_PUSH_R8(log, r)
	
	#state.VM_ADD_R8_V(log, state.read2(6), -8)
		
	t = (state.read2(16) ^ state.reg4[r118]) + 0xb8fb46f8
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+18)

def OP_43b(state, log):	
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(14))
	
	state.reg4[r118] += state.read4(4)
	
	t = state.read2(12) - state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg2[ref] -= t
	
	t = state.read4(8) ^ state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] ^= 0x291c2190
	state.reg4[r114] ^= t
	state.reg4[r8] |= t
	
	
	r = UW(state.reg2[ref] ^ 0x124d)
	v = state.reg4[r114]
	state.VM_MOV_R8_V(log, r, v)
		
	t = (state.read2(0) - state.reg4[r118]) + 0xd9b66af3
	
	state.reg4[r118] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+16)


def OP_208(state, log):
	state.reg4[r118] &= 0x238aa89d
	state.reg4[r118] |= 0x58ba4367
	state.reg4[r102] += 0x50e383c0
	
	t = state.read2(6) + state.reg4[r8]
	state.reg4[r118] += t
	state.reg4[r102] += 0xdb057945
	state.reg2[r2f] ^= t
	
	t = state.read2(0) - state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] &= t
	state.reg4[r102] ^= 0x1e7f15e9
	state.reg2[ref] -= t
	
	r1 = UW(state.reg2[ref] ^ 0x4a39)
	r2 = UW(state.reg2[r2f] + 0xe3a2)
	
	state.VM_MOV_R8_R8(log, r1, r2)
			
	t = (state.read2(4) + state.reg4[r118])
	
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)

def OP_418(state, log):
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x9e966b9d
	
	state.reg4[r102] ^= 0x4f3dbbdc	
	
	t = state.read2(4) ^ state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg2[ref] ^= t
	state.reg2[r2f] -= (state.read2(2) ^ state.reg4[r118]) - state.reg4[r8]
	state.reg4[r118] += 0x34e1a82f
		
	r1 = UW(state.reg2[ref] + 0x87e5)
	r2 = UW(state.reg2[r2f] + 0x6004)
	
	state.VM_MOV_R8_R8(log, r1, r2)
			
	t = (state.read2(6) + state.reg4[r118]) + 0x35b9379c
	
	state.reg4[r118] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_3bd(state, log):
	s = [0, ] * 8
	d = [0, ] * 8
	s[0] = state.read2(0x1e)
	s[1] = state.read2(0x1a)
	s[2] = state.read2(0xc)
	s[3] = state.read2(0xa)
	s[4] = state.read2(0x1c)
	s[5] = state.read2(0x20)
	s[6] = state.read2(0x18)
	s[7] = state.read2(0x10)
	
	d[0] = state.read2(0xe)
	d[1] = state.read2(2)
	d[2] = state.read2(4)
	d[3] = state.read2(8)
	d[4] = state.read2(0x16)
	d[5] = state.read2(0x14)
	d[6] = state.read2(0)
	d[7] = state.read2(0x12)
	
	state.VM_UNSHUFFLE(log, s, d)
	
	t = (state.read2(6) ^ state.reg4[r118]) + 0xc08b805c
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x22)


def OP_1ba(state, log):
	t = state.read2(0)
	state.reg4[r102] ^= 0x78164ca7
	state.reg2[r2f] += t + state.reg4[r118] ^ state.reg4[r8]
	
	t = state.read2(2) ^ state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] |= t
	state.reg2[ref] -= t
	
	t = state.read4(4) + state.reg4[r118] + 0x830f6f9c
		
	state.next = t & 0xFFFF
	state.chEIP(+6)
	

def OP_4f2(state, log):
	s = [0, ] * 6
	d = [0, ] * 6
	s[0] = state.read2(4)
	s[1] = state.read2(0)
	s[2] = state.read2(6)
	s[3] = state.read2(0x16)
	s[4] = state.read2(0xc)
	s[5] = state.read2(0x18)
	
	d[0] = state.read2(0xe)
	d[1] = state.read2(0x10)
	d[2] = state.read2(0x14)
	d[3] = state.read2(0x12)
	d[4] = state.read2(0xa)
	d[5] = state.read2(2)
	
	state.VM_UNSHUFFLE(log, s, d)
	
	t = state.read2(8) ^ 0x172b7ae6
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x1a)


def OP_5a7(state, log):
	t = state.read2(4) + state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg2[ref] ^= t
	
	t = state.read4(0) ^ state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r114] -= t
	state.reg4[r8] -= t
	
	
	r = state.reg2[ref] ^ 0xb5a9
	v = state.reg4[r114] ^ 0x65d0261b
	
	state.VM_CMP_R4_V4(log, r, v)
			
	t = (state.read2(8))
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0xe)

def OP_335(state, log):
	r = state.read2(8)
	t = state.read(10)
	j = state.read4(4)
	
	ins = state.read2(0)
	
	state.VM_JCC(log, t, j, ins)
	
	t = state.read2(11) - state.reg4[r118] ^ 0x45f451fc
	
	state.next = t & 0xFFFF
	state.chEIP(+0xd)


def OP_22d(state, log):
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(10))
		
	t = state.read4(4) ^ state.reg4[r118] - state.reg4[r102]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xd41c54a6
	state.reg4[r114] -= t
	state.reg4[r8] ^= t
	
	t = state.read2(0) + state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] += 0x611cfd8a
	state.reg4[ref] ^= t	
	
	r = UW(state.reg2[ref] + 0x452d)
	v = UDW(state.reg4[r114] + 0xc2abd481)
	
	state.VM_IMUL_R_V(log, r, v)
		
	t = (state.read2(8) + 0xa75c0a46)
	
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_38b(state, log):
	state.reg4[r102] ^= 0x2ba770c1
	state.reg4[r118] ^= 0x2ba770c1
	
	r1 = state.read2(2)
	r2 = state.read2(6)
	
	t = state.read2(4)
	
	state.VM_REP_MOV(log, r1, r2, t)
	
	t = state.read2(0) - state.reg4[r118] + 0x4a433dbf
	
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)

def OP_41f(state, log):
	state.reg4[r102] ^= 0x5057e06e
	
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(0xc))
	state.VM_XCHG_R_R(log, state.read2(10), state.read2(0xe))
	
	t = state.read2(6) - state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg2[ref] += t
	
	r = state.reg2[ref]
	
	state.VM_DEC_R8(log, r)
	
	t = state.read2(4) + state.reg4[r118] + 0x91d02eaa
	
	state.reg4[r118] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)


def OP_281(state, log):
	state.reg2[ref] -= state.read2(2) + state.reg4[r118]
	
	t = state.read2(0)
	state.reg4[r102] &= 0x1d2239cf
	state.reg2[r2f] -= (t + state.reg4[r8])
	
	if state.reg4[r102] & 1:
		state.reg4[r102] ^= 0x311d579f
	
	r = state.reg2[ref] ^ 0xa958
	v = state.reg2[r2f] ^ 0x9db1 & 7
	
	state.VM_ROL_R1(log, r, v)
	
	t = state.read2(6) + 0xbbb23287
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_478(state, log):
	t = state.read2(10) - state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0x2b23d1cc
	state.reg4[ref] ^= t
	
	t = state.read4(12) + state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r118] &= t
	state.reg4[r114] -= t
	state.reg4[r8] |= t
	
	state.reg4[r118] -= state.read4(4)
	
	r = UW(state.reg2[ref] + 0xc89a)
	v = UDW(state.reg4[r114] + 0x88e2a03b)
	
	state.VM_IMUL_R4_V(log, r, v)
	
	t = state.read2(8) + state.reg4[r118] + 0x963aaedd
	state.reg8[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)


def OP_47e(state, log):
	ins = state.read2(0)
	jmp = state.read4(4)
	
	state.VM_JMP(log, jmp, ins)


def OP_225(state, log):
	t = state.read2(6) + state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] &= t
	state.reg4[r102] += 0xdaf9b4a1
	state.reg2[ref] -= t
	state.reg4[r118] |= 0x5595d631
	state.reg4[r102] &= 0x3887afbc
	state.reg4[r102] += 0x6e3b936e
	
	t = state.read4(0) + state.reg4[r118] - state.reg4[r102]
	state.reg4[r102] += 0x83e3620b
	state.reg4[r114] -= t
		
	r = state.reg2[ref] ^ 0x3cd1
	v = state.reg4[r114] ^ 0x2e700f70
	
	state.VM_MOV_R8_V(log, r, v)
	
	t = state.read2(4) - state.reg4[r118] + 0x3ff52e3f
	
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+8)



def OP_11b(state, log):
	t = state.read2(6) + state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r102] &= 0x14e2f991
	state.reg2[ref] -= t
	
	t = (state.read4(0) ^ state.reg4[r118]) - state.reg4[r102]
	state.reg4[r118] |= t
	state.reg4[r114] ^= t
	state.reg4[r8] += t
	state.reg4[r102] ^= 0x386bae3e
	state.reg4[r118] &= state.read4(8)
	
	if state.reg4[r102] & 1:
		state.reg4[r102] ^= 0x5925e9d
	
	r = state.reg2[ref] ^ 0x45bd
	v = state.reg4[r114]
	
	state.VM_ADD_R8_V(log, r, v)
	
	t = (state.read2(4) ^ state.reg4[r118]) + 0xfbd65ef7
	
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0xe)


def OP_0e(state, log):
	t = state.read2(4) + state.reg4[r118] + state.reg4[r8]
	state.reg4[r118] += t
	state.reg2[r2f] += t
	
	t = state.read2(2) + state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] += 0x8b51f5af
	state.reg2[ref] += t
	
	r1 = state.reg2[ref]
	r2 = state.reg2[r2f] ^ 0x89e8
	
	state.VM_MOV_R8_MR(log, r1, r2)
	
	state.reg4[r118] ^= 0x530a3c99
	state.reg4[r118] ^= 0x3724ba70

	t = (state.read2(0) - state.reg4[r118]) + 0x5c646b23
		
	state.next = t & 0xFFFF
	state.chEIP(+6)


def OP_4d2(state, log):
	t = (state.read2(4) ^ state.reg4[r118]) - state.reg4[r8]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0x7a883cf1
	state.reg2[r2f] += t
	
	t = state.read2(0) ^ state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg2[ref] ^= t
	
	r1 = state.reg2[ref] ^ 0x9dca
	r2 = state.reg2[r2f] ^ 0x91dc
	
	state.VM_MOV_MR_R8(log, r1, r2)
	
	t = (state.read2(2)) + 0xf61c848
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+6)


def OP_137(state, log):
	t = (state.read2(2) + state.reg4[r118]) - state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x4701d0d1
	state.reg2[ref] -= t
	
	t = state.read(10) + state.reg4[r102]
	state.reg4[r118] |= t
	state.reg4[r102] &= 0x2b18163f
	state.reg4[r114] += t
	state.reg4[r8] ^= t
	
	r = state.reg2[ref]
	v = (state.reg4[r114] ^ 0x50) & 0x3f
	
	state.VM_RCL_R8_V(log, r, v)
	
	state.reg4[r118] += state.read4(6)
	state.reg4[r118] ^= 0x7a8d7a82
	
	t = (state.read2(4)) + 0xeb322f01
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+11)


def OP_21(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(8))
	
	t = state.read2(2) - state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] |= 0x41efb921
	state.reg2[ref] += t
	
	r = state.reg2[ref]
	
	state.VM_PUSH_R8(log, r)
	
	#state.VM_ADD_R8_V(log, state.read2(6), -8)
	
	t = state.read2(6) ^ 0xedf2eb6
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0xc)


def OP_5cb(state, log):	
	r1 = state.read2(6)
	r2 = state.read2(0)
	
	t = state.read2(10)
	
	state.VM_REP_MOV(log, r1, r2, t)
	
	state.reg4[r118] += 0x59e9dde7
	state.reg4[r102] += 0x10f6fbf4
	
	state.VM_XCHG_R_R(log, state.read2(4), state.read2(2))
	
	t = (state.read2(8) ^ state.reg4[r118]) + 0xf1ea9e2b
	
	state.reg4[r118] &= t	
	
	state.next = t & 0xFFFF
	state.chEIP(+0xc)


def OP_314(state, log):
	state.VM_XCHG_R_R(log, state.read2(4), state.read2(0))
	
	t = state.read2(2) - state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] &= 0x45068e82
	state.reg2[ref] -= t
	
	t = state.read4(8) ^ state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0x3f7bb0b8
	state.reg4[r114] ^= t
	state.reg4[r8] -= t
	state.reg4[r118] ^= 0x7d667082
	
	
	r = UW(state.reg2[ref] - 0xc8)
	v = state.reg4[r114]
	
	state.VM_CMP_R4_V4(log, r, v)
			
	t = (state.read2(0xe) ^ state.reg4[r118] ^ 0x4884f7e3)
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)


def OP_25a(state, log):
	state.VM_XCHG_R_R(log, state.read2(4), state.read2(6))
	
	t = state.read2(10) ^ state.reg4[r8]
	state.reg4[r118] &= t
	state.reg4[r102] += 0x7aeb3939
	state.reg2[r2f] ^= t
	
	t = state.read2(8) ^ state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg4[r102] ^= 0x26dd98f6
	state.reg2[ref] ^= t
	
	r1 = UW(state.reg2[ref] - 0xaf2)
	r2 = UW(state.reg2[r2f] + 0x73b6)
	
	state.VM_MOV_R8_MR(log, r1, r2)
	
	t = state.read2(2) - state.reg4[r118] ^  0x4588591
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0xe)

def OP_408(state, log):
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(10))
	
	t = state.read2(0) + state.reg4[r125]
	state.reg4[r102] |= 0xeacb7d5
	state.reg2[ref] += t
	
	t = state.read4(4) + state.reg4[r102]
	state.reg4[r118] |= t
	state.reg4[r102] ^= 0x11affad8
	state.reg4[r114] -= t
	state.reg4[r8] |= t	
	
	r = UW(state.reg2[ref] + 0xca0d)
	v = UDW(state.reg4[r114] + 0x90651c86)
	
	state.VM_CMP_R4_V4(log, r, v)
	
	state.reg4[r118] += state.read4(0xe)
			
	t = (state.read2(0xc) + state.reg4[r118])
	
	state.reg4[r118] &= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x12)


def OP_21e(state, log):
	ins = state.read2(0)
	jmp = state.read4(4)
	
	state.VM_JMP(log, jmp, ins)


def OP_4f9(state, log):
	r = state.read2(8)
	t = state.read(10)
	j = state.read4(4)
	
	ins = state.read2(0)
	
	state.VM_JCC(log, t, j, ins)
	
	t = state.read2(11) - state.reg4[r118] ^ 0x664704be
	
	state.next = t & 0xFFFF
	state.chEIP(+0xd)


def OP_599(state, log):
	
	t = state.read2(6) - state.reg4[r8]
	state.reg4[r118] -= t
	state.reg4[r102] |= 0x27ab5cd4
	state.reg2[r2f] += t
	
	t = state.read2(8) - state.reg4[r118] - state.reg4[r125]
	state.reg4[r102] |= 0x78181f57
	state.reg2[ref] += t
	
	r1 = UW(state.reg2[ref] + 0x5ac4)
	r2 = UW(state.reg2[r2f])
	
	state.VM_MOV_R8_MR(log, r1, r2)
	
	state.reg4[r102] &= 0x6147847b
	state.reg4[r118] &= state.read4(0)
	
	t = state.read2(4) - state.reg4[r118]
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_e1(state, log):
	t = state.read2(8) - state.reg4[r118] ^ state.reg4[r8]
	state.reg4[r118] |= t
	state.reg4[r102] += 0xef03d273
	state.reg2[r2f] -= t
	
	t = state.read2(6) + state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] |= t
	state.reg4[r102] += 0x1e61e6df
	state.reg2[ref] += t
	
	r1 = state.reg2[ref]
	r2 = UW(state.reg2[r2f] + 0x4990)
	
	state.VM_MOV_MR_R8(log, r1, r2)
	
	t = (state.read2(4)) - state.reg4[r118]
	
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_6d(state, log):
	t = state.read(0xc) - state.reg4[r118]
	state.reg4[r118] &= t
	state.reg4[r102] += 0x8653d380
	state.reg4[r114] -= t
	state.reg4[r8] &= t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] &= 0xc20ac26
	
	state.reg4[r118] += 0xc20ac26
	
	t = state.read2(8) ^ state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] &= 0x105f0cde
	state.reg2[ref] += t
	
	r = state.reg2[ref] ^ 0xb4fc
	v = UB(state.reg4[r114] - 0x1ebdce64)
	
	state.VM_MOV_MR_V1(log, r, v)
	
	t = (state.read2(6))
	
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+13)

def OP_4c(state, log):
	state.VM_XCHG_R_R(log, state.read2(0xe), state.read2(0xc))

	t = state.read4(4) - state.reg4[r118] + state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r114] -= t
	state.reg4[r8] ^= t
	
	state.reg4[r106] = state.read4(8)
		
	t = (state.read2(0) ^ state.reg4[r118]) + state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xd0b423e0
	state.reg2[ref] += t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] ^= 0x1e9d0b9c
	
	r = UW(state.reg2[ref] + 0xa3d2)
	v = UDW(state.reg4[r114] + 0x51efb5ee)
	v2 = UDW(state.reg4[r106] + 0x78456a27)
	
	state.VM_MOV_R8_V(log, r, v | (v2 << 32))
	
	t = (state.read2(0x12)) ^ 0x48b7fef1
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+20)

def OP_398(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(2))

	t = state.read2(10) - state.reg4[r118]
	state.reg4[r118] -= t
	state.reg4[r102] += 0x1b409ed2
	state.reg2[ref] ^= t
	
	
	r = UW(state.reg2[ref] + 0xacd)
	
	state.VM_PUSH_MR(log, r)
		
	#state.VM_ADD_R8_V(log, state.read2(4), -8)
	
	t = (state.read2(6)) + state.reg4[r118]
	
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_466(state, log):
	t = state.read2(2) + state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] |= 0x257fd4a7
	state.reg2[ref] += t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0xd2fe0dd0
	
	r = UW(state.reg2[ref] + 0xb031)
	
	state.VM_PUSH_R8(log, r)
		
	#state.VM_ADD_R8_V(log, state.read2(6), -8)
	
	state.reg4[r102] += 0x8428b0df
	state.reg4[r102] ^= 0x60af7a7e
	
	t = (state.read2(0)) + 0x55f5d7b1
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_167(state, log):
	state.VM_XCHG_R_R(log, state.read2(4), state.read2(2))

	t = state.read2(0) + state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] ^= 0x1f4713a9
	state.reg2[ref] -= t
	
	r = UW(state.reg2[ref] ^ 0x5389)
	
	state.VM_PUSH_R8(log, r)		
	#state.VM_ADD_R8_V(log, state.read2(8), -8)
	
	t = (state.read2(10)) + state.reg4[r118]
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_13f(state, log):
	if state.reg4[r102] & 1:
		state.reg4[r102] |= 0x3bf20e6c
		
	state.VM_XCHG_R_R(log, state.read2(8), state.read2(6))

	r = state.read2(2)	
	
	state.VM_PUSH_R8(log, r)		
	#state.VM_ADD_R8_V(log, state.read2(10), -8)
	
	t = (state.read2(4)) + state.reg4[r118]
	
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_3b6(state, log):
	t = (state.read2(0)) + state.reg4[r118]
	
	state.next = t & 0xFFFF
	state.chEIP(+2)
	
	
def OP_2d(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)


def OP_42(state, log):
	state.reg4[r102] += 0x33e64737
	state.reg4[r118] |= 0x29361eaa

	t = state.read2(6) ^ state.reg4[r125]
	state.reg4[r102] ^= 0x290cf171
	state.reg2[ref] += t
	
	t = state.read4(0) ^ state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r102] += 0xe464c340
	state.reg4[r114] += t
	state.reg4[r8] += t	
	
	r = UW(state.reg2[ref] + 0x6c47)
	v = UDW(state.reg4[r114] + 0x48cc69c)
	
	state.VM_SUB_R8_V(log, r, v)

	t = (state.read2(10) ^ state.reg4[r118])
	
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+0xe)


def OP_29c(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)


def OP_00(state, log):
	state.reg4[r118] += 0x78294376

	t = state.read2(5) ^ state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] ^= 0x51ac6586
	state.reg2[ref] += t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0xf008b673
	
	t = state.read(4) ^ state.reg4[r118]
	state.reg4[r118] -= t
	state.reg4[r102] += 0x8f5641ed
	state.reg4[r114] -= t
	state.reg4[r8] -= t	
	
	r = UW(state.reg2[ref] + 0x1ecd)
	v = UB(state.reg4[r114] + 0x68)
	
	state.VM_AND_R1_V(log, r, v)

	t = (state.read2(2)) + 0xa84553b1
	
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+7)


def OP_1e2(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(4))


	t = state.read2(0xc) - state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x482bbb
	state.reg2[ref] ^= t
	
	r = UW(state.reg2[ref] - 0x2b9b)
	state.VM_PUSH_MR(log, r)		
	#state.VM_ADD_R8_V(log, state.read2(6), -8)
	
	t = (state.read2(10) ^ state.reg4[r118]) + 0x5e596e0a
			
	state.next = t & 0xFFFF
	state.chEIP(+14)

def OP_3a7(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)

def OP_5a(state, log):
	t = (state.read2(0) + state.reg4[r125])
	state.reg4[r102] += 0xc979163e
	state.reg2[ref] ^= t
	
	t = state.read2(2) + state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg2[r2f] -= t
	
	state.reg4[r118] &= state.read4(6)
	state.reg4[r118] &= state.read4(10)
	
	r1 = UW(state.reg2[ref] + 0xe4e)
	r2 = state.reg2[r2f]
	
	state.VM_MOV_MR_R8(log, r1, r2)
	
	t = (state.read2(4)) + 0x704c3f7e
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+14)


def OP_4ad(state, log):
	state.reg4[r118] &= 0x64b645b2
	state.reg4[r118] ^= 0x792e5d66
	
	t = state.read4(2) + state.reg4[r102]
	state.reg4[r118] &= t
	state.reg4[r114] -= t
	
	state.reg4[r106] = state.read4(6)
			
	t = (state.read2(10) ^ state.reg4[r118]) + state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x67c53de3
	state.reg2[ref] += t
	
	state.reg4[r118] += 0x8d54cf59
	state.reg4[r102] += 0xaf2817ce
	
	r = UW(state.reg2[ref])
	v = UDW(state.reg4[r114] + 0xd13aee22)
	v2 = UDW(state.reg4[r106] + 0x3f9709a)
	
	state.VM_MOV_R8_V(log, r, v | (v2 << 32))
	
	t = (state.read2(0))
	
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+12)
	
def OP_538(state, log):
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x6727c861
		
	state.reg4[r118] += state.read4(8)
	state.reg4[r118] |= 0x11a2a9ae
		
	r = state.read2(12)	
	
	state.VM_PUSH_R8(log, r)		
	#state.VM_ADD_R8_V(log, state.read2(0), -8)
	
	state.reg4[r118] |= state.read4(4)
	
	t = (state.read2(2)) + 0xf8d58b35
	
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+14)
	
def OP_4fd(state, log):	
	t = (state.read4(8) ^ state.reg4[r118]) - state.reg4[r102]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x209186f
	state.reg4[r114] -= t
	state.reg4[r8] ^= t
	
	state.reg4[r106] = state.read4(12)
	
	state.reg4[r118] += 0xdc8a0267
	state.reg4[r102] += 0xfe4070df
			
	t = (state.read2(0) + state.reg4[r118]) + state.reg4[r125]
	state.reg4[r102] += 0x430846c
	state.reg2[ref] -= t
	
	state.reg4[r118] -= state.read4(2)
	
	r = UW(state.reg2[ref] + 0x8d14)
	v = UDW(state.reg4[r114] + 0x14c31138)
	v2 = UDW(state.reg4[r106] + 0xa2820109)
	
	state.VM_MOV_R8_V(log, r, v | (v2 << 32))
	
	t = (state.read2(6) + state.reg4[r118]) + 0x34a097a3
	
	state.reg4[r118] |= t
		
	state.next = t & 0xFFFF
	state.chEIP(+18)

def OP_347(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(8))

	t = state.read2(2) + state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0xcfdf26f2
	state.reg2[ref] ^= t
	state.reg4[r118] ^= 0x5ebe6fad
	state.reg4[r102] += 0x6edd4fca
	
	r = UW(state.reg2[ref])
	
	state.VM_PUSH_MR(log, r)		
	#state.VM_ADD_R8_V(log, state.read2(4), -8)
	
	t = (state.read2(6)) + 0x12d51bdd
	
	state.reg4[r118] |= t
		
	state.next = t & 0xFFFF
	state.chEIP(+10)

def OP_232(state, log):
	t = (state.read2(2) - state.reg4[r118]) ^ state.reg4[r8]
	state.reg4[r118] |= 0xaa2152a
	state.reg4[r102] += 0x2f389827
	state.reg2[r2f] ^= t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] &= 0xaa2152a
	
	state.reg4[r102] += 0x69fd7bb1
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0xbc644004
	
	t = state.read2(4) + state.reg4[r118]
	state.reg4[r118] += t
	state.reg4[r102] += 0xb7f0c51
	state.reg2[ref] += t
	
	if state.reg4[r102] & 1:
		state.reg4[r102] |= 0x3f1ecc06
	
	r1 = state.reg2[ref] ^ 0x5e29
	r2 = UW(state.reg2[r2f] + 0xace1)
	
	state.VM_MOV_MR_R8(log, r1, r2)
	
	t = (state.read2(0)) ^ state.reg4[r118]
	
	state.reg4[r118] ^= t
		
	state.next = t & 0xFFFF
	state.chEIP(+6)

def OP_4ab(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)

def OP_125(state, log):	
	state.reg4[r118] &= 0x659c47a3
	
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(10))
	
	t = state.read4(6) ^ state.reg4[r102]
	state.reg4[r118] &= t
	state.reg4[r102] |= 0x3c3502e6
	state.reg4[r114] -= t
	state.reg4[r8] |= t
	
	t = state.read2(4) + state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x6d3e85f2
	state.reg2[ref] -= t	
	
	r = UW(state.reg2[ref])
	v = state.reg4[r114]
	state.VM_MOV_R8_V(log, r, v)
		
	t = (state.read2(0) + state.reg4[r118])
		
	state.next = t & 0xFFFF
	state.chEIP(+12)

def OP_54a(state, log):
	state.reg4[r102] += 0x3e9c9a2c
	
	t = state.read(8) + state.reg4[r118] + state.reg4[r102]
	state.reg4[r118] &= t
	state.reg4[r102] += 0x1dbdea62
	state.reg4[r114] += t
	state.reg4[r8] |= t
	
	t = state.read2(6) + state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xd5cd7854
	state.reg2[ref] -= t
	
	state.reg4[r118] |= state.read4(0)
		
	r = UW(state.reg2[ref] + 0xa99e)
	v = UB(state.reg4[r114] - 0x78069923)
	state.VM_AND_R1_V(log, r, v)
	
	state.reg4[r118] += state.read4(9)
	state.reg4[r118] += 0x49a82c9e
	
	state.reg4[r102] ^= 0x25973280
		
	t = (state.read2(4) - state.reg4[r118])
	
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+15)


def OP_441(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(10))
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(12))
	
	t = state.read4(4) - state.reg4[r118] + state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x353dab22
	state.reg4[r114] += t
	
	t = state.read2(8) - state.reg4[r118]
	state.reg4[r118] += t
	state.reg4[r102] += 0xc0779b5e
	state.reg2[ref] += t	
	
	r = UW(state.reg2[ref] + 0xaaf6)
	v = UDW(state.reg4[r114] ^ 0x4cbe1414)
	state.VM_ADD_R8_V(log, r, v)
		
	t = (state.read2(16) + state.reg4[r118]) + 0x2deb6fa8
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0x12)
	
def OP_5f5(state, log):
	t = (state.read4(2) ^ state.reg4[r118]) + state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] ^= 0x6f54e069
	state.reg4[r114] += t
	state.reg4[r8] ^= t
	
	t = state.read2(6) + state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] &= t
	state.reg2[ref] += t
	state.reg4[r118] &= 0x687dcc79
	
	state.reg4[r102] += 0xf79fdf7a
	
	r = UW(state.reg2[ref])
	v = UDW(state.reg4[r114] ^ 0xcaa05eb)
	state.VM_SUB_R8_V(log, r, v)
	
	state.reg4[r118] ^= 0x7a135576
		
	t = (state.read2(0) ^ state.reg4[r118]) ^ 0x40a5cadb
		
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_548(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)


def OP_4d5(state, log):

	t = state.read2(4) + state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x4b809858
	state.reg2[ref] += t
	
	t = state.read2(2) - state.reg4[r118]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x13191184
	state.reg2[r2f] ^= t
		
	r1 = UW(state.reg2[ref] ^ 0x8b7)
	r2 = UW(state.reg2[r2f] + 0x69e1)
	state.VM_TEST_R_R(log, r1, r2)
			
	t = (state.read2(6) + state.reg4[r118]) + 0xc0ca458e
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_38e(state, log):
	t = state.read2(8) + state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r102] |= 0x56e1b6b3
	state.reg2[ref] -= t
	
	t = state.read4(2) - state.reg4[r118] + state.reg4[r102]
	state.reg4[r118] += t
	state.reg4[r102] += 0x900fe669
	state.reg4[r114] ^= t
	state.reg4[r8] ^= t
		
	r = UW(state.reg2[ref])
	v = UDW(state.reg4[r114] + 0x9490fe0e)
	state.VM_SUB_R8_V(log, r, v)
	
	state.reg4[r118] += 0xb1f0cedb
			
	t = (state.read2(0) - state.reg4[r118]) + 0xe3e817ce
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_4fe(state, log):
	t = (state.read2(2) ^ state.reg4[r118]) + state.reg4[r8]
	state.reg4[r118] -= t
	state.reg2[r2f] -= t
	
	t = state.read2(0) + state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] += 0x69a9b812
	state.reg2[ref] -= t
		
	r1 = UW(state.reg2[ref] + 0x5dcc)
	r2 = UW(state.reg2[r2f] ^ 0xe1e3)
	state.VM_TEST_R_R(log, r1, r2)
			
	t = (state.read2(6) ^ state.reg4[r118]) ^ 0x406c5172
	state.reg4[r118] |= t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_149(state, log):
	t = (state.read2(14) - state.reg4[r118]) - state.reg4[r125]
	state.reg4[r118] |= t
	state.reg4[r102] += 0xdb0b88ee
	state.reg2[ref] += t
	
	t = state.read4(2) + state.reg4[r102]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x2ff623c1
	state.reg4[r114] -= t
	state.reg4[r8] += t
		
	r = UW(state.reg2[ref] ^ 0x4bd2)
	v = UDW(state.reg4[r114] + 0xc25a2cbb)
	state.VM_CMP_MR4_V4(log, r, v)
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x1ff1f8b
			
	t = (state.read2(12) ^ state.reg4[r118]) ^ 0x39e03e30
	state.reg4[r118] -= t
		
	state.next = t & 0xFFFF
	state.chEIP(+16)

def OP_28(state, log):
	stk = state.read2(4) - 8
	v1 = state.read2(6)
	v2 = state.read4(0) + state.imgbase
	log.append("{}CALL {}    RET  {:08x}".format(state.GetPos(), state.RegName(v1), v2))
	
	state.run = False
	
	if state.OnEnd:
		state.OnEnd(state, log)


def OP_4f5(state, log):
	state.VM_XCHG_R_R(log, state.read2(10), state.read2(4))
	state.VM_XCHG_R_R(log, state.read2(2), state.read2(6))

	t = state.read(0x14) + state.reg4[r118]
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x72101b35
	state.reg4[r114] += t
	state.reg4[r8] |= t
	
	t = state.read2(0x12) ^ state.reg4[r125]
	state.reg4[r102] |= 0x494c0457
	state.reg2[ref] -= t
			
	r = UW(state.reg2[ref])
	v = UB(state.reg4[r114] ^ 0x72c21020)
	state.VM_AND_R1_V(log, r, v)
	
	t = (state.read2(0xe) + state.reg4[r118]) + 0x2ea57efb
	
	state.reg4[r118] ^= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0x15)


def OP_3ab(state, log):
	state.reg4[r118] |= 0x4d678201
	
	t = state.read2(2) + state.reg4[r118] + state.reg4[r8]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xf93caf65
	state.reg2[r2f] += t
	
	t = state.read2(4) - state.reg4[r118] + state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x6e134fc
	state.reg2[ref] ^= t
	state.reg4[r102] += 0x36f3a91e
			
	r1 = UW(state.reg2[ref] + 0xcb4a)
	r2 = UW(state.reg2[r2f] + 0xb7f3)
	state.VM_MOV_R8_MR2(log, r1, r2)
	
	t = (state.read2(0)) + 0x73603bef
	
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+6)

def OP_4bd(state, log):
	state.reg4[r118] += state.read4(8)
	
	state.VM_XCHG_R_R(log, state.read2(14), state.read2(4))

	t = state.read2(0) - state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] &= t
	state.reg2[ref] += t
		
	t = state.read2(6) ^ state.reg4[r8]
	state.reg4[r118] |= t
	state.reg2[r2f] ^= t
			
	r1 = UW(state.reg2[ref] + 0xab46)
	r2 = UW(state.reg2[r2f] ^ 0x357d)
	state.VM_MOV_R8_MR2(log, r1, r2)
	
	t = (state.read2(2))
	
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0x10)

def OP_430(state, log):
	t = (state.read(4) ^ state.reg4[r118]) + state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] += 0xb721d72d
	state.reg4[r114] += t
	state.reg4[r8] -= t
	state.reg4[r118] += 0x7539cb94
		
	t = state.read2(0) + state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xd2a7b8
	state.reg2[ref] += t
	
	r = UW(state.reg2[ref] + 0x40e2)
	v = UB(state.reg4[r114] - 0x3e9f0561) & 0x3F
	state.VM_SHL_R8_R4_V(log, r, r, v)
	
	t = (state.read2(2)) + 0x4d467317
	
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+7)


def OP_45e(state, log):
	t = state.read2(0) - state.reg4[r118] ^ state.reg4[r125]
	state.reg2[ref] -= t
	state.reg4[r102] += 0x8fdbbcdd
	
	state.reg4[r118] ^= state.read4(2)
		
	t = state.read2(10) + state.reg4[r8]
	state.reg4[r118] -= t
	state.reg4[r102] |= 0x5d85503
	state.reg2[r2f] -= t
	
	r1 = UW(state.reg2[ref] + 0xa5c5)
	r2 = UW(state.reg2[r2f] + 0xc78d)
	state.VM_OR_R8_R4_R4(log, r1, r1, r2)
	
	t = state.read2(12) + state.reg4[r118] ^ 0x4fbe42ed
	
	state.reg4[r118] ^= t
		
	state.next = t & 0xFFFF
	state.chEIP(+14)


def OP_31c(state, log):
	t = state.read2(4) ^ state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] ^= 0x5cd3eb57
	state.reg2[ref] ^= t
	
	t = state.read2(0) - state.reg4[r118] ^ state.reg4[r8]
	state.reg4[r118] += t
	state.reg4[r102] += 0x5893b658
	state.reg2[r2f] += t
	state.reg4[r118] |= 0x529a771
	
	r1 = UW(state.reg2[ref] + 0xb871)
	r2 = UW(state.reg2[r2f] + 0xb04b)
	state.VM_ADD_R8_R4_R4(log, r1, r1, r2)
	
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x62484f5b
	
	t = state.read2(2) ^ state.reg4[r118] ^ 0x79a6ca70
	
	state.reg4[r118] |= t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)

def OP_43f(state, log):
	t = state.read2(0) - state.reg4[r118] ^ state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg2[ref] ^= t
	
	t = state.read4(4) - state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r118] |= t
	state.reg4[r102] &= 0x40da7079
	state.reg4[r8] -= t
	state.reg4[r114] -= t
	
	state.reg4[r102] |= 0x424261d9
	
	r = UW(state.reg2[ref])
	v = UDW(state.reg4[r114])
	state.VM_ADD_R8_R4_V(log, r, r, v)
		
	t = state.read2(8) + state.reg4[r118] + 0x7de24821
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_6a(state, log):
	state.reg4[r118] ^= 0x5e163c8d
	
	t = (state.read2(14) ^ state.reg4[r118]) + state.reg4[r125]
	state.reg2[ref] ^= t
	
	t = state.read2(0) + state.reg4[r118] + state.reg4[r8]
	state.reg4[r118] ^= t
	state.reg2[r2f] += t
	
	r1 = UW(state.reg2[ref] ^ 0x8c4c)
	r2 = UW(state.reg2[r2f] + 0x9279)
	state.VM_XOR_R8_R4_R4(log, r1, r1, r2)
	
	state.reg4[r118] -= state.read4(8)
	state.reg4[r118] += state.read4(4)
		
	t = state.read2(12) + state.reg4[r118] + 0x4e66a6be
	
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x10)
	

def OP_3a9(state, log):
	if state.reg4[r102] & 1:
		state.reg4[r102] &= 0x2483f728
	
	state.VM_XCHG_R_R(log, state.read2(4), state.read2(8))
	
	t = (state.read2(0) + state.reg4[r118]) ^ state.reg4[r8]
	state.reg4[r102] += 0x716e0f65
	state.reg2[r2f] ^= t
	
	t = state.read2(6) + state.reg4[r118] - state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] ^= 0x7e8ff4c0
	state.reg2[ref] += t
	
	r1 = UW(state.reg2[ref] - 0x93e)
	r2 = UW(state.reg2[r2f] ^ 0xf1e)
	state.VM_MOV_MR4_R4(log, r1, r2)
		
	t = (state.read2(2) ^ state.reg4[r118]) + 0x2e47446b
	
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+10)


def OP_2d3(state, log):
	t = (state.read2(4) + state.reg4[r118])
	state.reg4[r118] ^= t
	state.reg4[r102] += 0x415d3c08
	state.reg2[ref] ^= t
	
	t = state.read2(6) + state.reg4[r118]
	state.reg4[r118] += t
	state.reg4[r102] += 0xb32cdcc8
	state.reg4[r114] += t
	state.reg4[r8] -= t
	state.reg4[r118] |= 0x23db3af2
		
	r = UW(state.reg2[ref] + 0xc05c)
	v = UW(state.reg4[r114] + 0xc60)
	state.VM_TEST_R2_V(log, r, v)
			
	t = (state.read2(2) ^ state.reg4[r118]) + 0x74ec5bdc
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+8)


def OP_3ec(state, log):
	state.reg4[r118] += 0x1dd09cb5
	
	t = (state.read2(2) ^ state.reg4[r118]) + state.reg4[r8]
	state.reg4[r118] |= t
	state.reg2[r2f] ^= t
	
	t = (state.read2(4) ^ state.reg4[r118]) + state.reg4[r125]
	state.reg4[r118] |= t
	state.reg4[r102] += 0xb7b1ae62
	state.reg2[ref] ^= t
		
	r1 = UW(state.reg2[ref] + 0xe4c9)
	r2 = UW(state.reg2[r2f])
	state.VM_TEST_R4_R4(log, r1, r2)
	
	state.reg4[r118] &= 0xf2516a6
	state.reg4[r102] += 0xc85521ba
	state.reg4[r118] += state.read4(6)
			
	t = (state.read2(0) - state.reg4[r118]) + 0x3b2c78a7
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+12)

def OP_20a(state, log):
	if state.reg4[r102] & 1:
		state.reg4[r102] += 0x6e15fef5
	
	t = (state.read4(14) + state.reg4[r118]) + state.reg4[r102]
	state.reg4[r118] |= t
	state.reg4[r102] ^= 0x3224367d
	state.reg4[r114] ^= t
	
	t = (state.read2(4) - state.reg4[r118]) - state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] &= 0x38ca3a14
	state.reg2[ref] += t
	state.reg4[r102] |= 0x2ff890ae
		
	r = UW(state.reg2[ref] + 0x49b5)
	v = UDW(state.reg4[r114])
	state.VM_MOV_R4_V(log, r, v)
	
	state.reg4[r118] |= state.read4(0)
			
	t = (state.read2(12) + state.reg4[r118]) + 0x50452ed7
	state.reg4[r118] ^= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0x12)


def OP_36e(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(4))
		
	t = (state.read2(6) - state.reg4[r118]) ^ state.reg4[r125]
	state.reg4[r118] += t
	state.reg4[r102] |= 0x2273b1c4
	state.reg2[ref] += t
	state.reg4[r118] += 0x18a30788
	
	t = (state.read4(8) - state.reg4[r118]) - state.reg4[r102]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x237ed3dc
	state.reg4[r114] -= t
	state.reg4[r8] |= t
		
	r = UW(state.reg2[ref])
	v = UDW(state.reg4[r114] ^ 0x17fe22a2)
	state.VM_MOV_MR4_V(log, r, v)
	
	t = (state.read2(2) ^ state.reg4[r118]) ^ 0x4a59e0f2
	state.reg4[r118] ^= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0xe)

def OP_38f(state, log):
	state.reg4[r118] += 0xe75ed939
	state.reg4[r102] &= 0x5ff161b

	t = (state.read(0xe) ^ state.reg4[r118]) ^ state.reg4[r102]
	state.reg4[r102] |= 0x5f7c93fc
	state.reg4[r114] -= t
	state.reg4[r8] &= t
	
	t = (state.read4(8)) + state.reg4[r125]
	state.reg4[r118] |= t
	state.reg2[ref] += t
		
	r = UW(state.reg2[ref] - 0xf9d)
	v = UB(state.reg4[r114] - 0x274d8f6b)
	state.VM_AND_R1_V(log, r, v)
	
	state.reg4[r118] -= state.read4(0xf)
	
	t = (state.read2(6) ^ state.reg4[r118]) + 0x1633a6a3
	state.reg4[r118] &= t
		
	state.next = t & 0xFFFF
	state.chEIP(+0x13)


def OP_58d(state, log):
	t = (state.read2(4) ^ state.reg4[r118]) - state.reg4[r125]
	state.reg4[r118] &= t
	state.reg4[r102] ^= 0x617767ba
	state.reg2[ref] += t
	
	t = (state.read2(0) + state.reg4[r118]) - state.reg4[r8]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x6b458e55
	state.reg2[r2f] ^= t
	
	r1 = UW(state.reg2[ref] + 0x1871)
	r2 = UW(state.reg2[r2f] + 0x4405)
	state.VM_TEST_R_R(log, r1, r2)
			
	t = (state.read2(2) - state.reg4[r118]) ^ 0x355dc45f
	state.reg4[r118] += t
		
	state.next = t & 0xFFFF
	state.chEIP(+16)

def OP_5df(state, log):
	t = state.read(2)
	state.reg4[r102] ^= 0x7aead761
	state.reg4[r114] ^= t
	state.reg4[r8] ^= t
	
	t = state.read2(0) - state.reg4[r118]
	state.reg4[r118] -= t
	state.reg4[r102] += 0xb8f47287
	state.reg2[ref] += t
	
	r = UW(state.reg2[ref] + 0xb6e7)
	v = UB(state.reg4[r114])
	
	state.VM_AND_R1_V(log, r, v)
	
	state.reg4[r118] -= state.read4(5)

	t = (state.read2(3)) ^ 0x28bf9590
	
	state.reg4[r118] |= t
	
	state.next = t & 0xFFFF
	state.chEIP(+9)


def OP_42c(state, log):
	state.reg4[r118] -= state.read4(8)
	
	t = (state.read2(4) - state.reg4[r118]) + state.reg4[r125]
	state.reg4[r118] |= t
	state.reg4[r102] &= 0x42d227c6
	state.reg2[ref] += t
	
	t = state.read4(14) ^ state.reg4[r118] ^ state.reg4[r102]
	state.reg4[r118] -= t
	state.reg4[r102] &= 0x13b2d5be
	state.reg4[r114] ^= t
	state.reg4[r8] += t
	state.reg4[r102] ^= 0x60e90b35
	
	state.reg4[r118] ^= state.read4(0)
	
	r = UW(state.reg2[ref] + 0x453d)
	v = UDW(state.reg4[r114] + 0x4628658d)
	
	state.VM_MOV_MR4_V(log, r, v)
		
	t = (state.read2(6) + state.reg4[r118]) + 0xb1da3c2a
	
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+0x14)


def OP_19(state, log):
	stk = state.read2(0)
	v = state.read2(2)
	log.append("{}JMP OUT {} ".format(state.GetPos(), state.RegName(v)))
	
	state.run = False

def OP_18c(state, log):
	state.VM_XCHG_R_R(log, state.read2(0), state.read2(9))

	t = (state.read2(6) + state.reg4[r118]) ^ state.reg4[r125]
	state.reg4[r118] -= t
	state.reg4[r102] ^= 0x32d94f46
	state.reg2[ref] -= t
		
	t = state.read(8) + state.reg4[r118] - state.reg4[r102]
	state.reg4[r102] += 0x608d1a92
	state.reg4[r114] += t
	state.reg4[r8] ^= t	
	
	r = UW(state.reg2[ref] ^ 0xcd05)
	v = UB(state.reg4[r114] ^ 0xf3a123a)
	
	state.VM_AND_R1_V(log, r, v)

	t = (state.read2(2) + state.reg4[r118]) ^ 0x221f5380
	
	state.reg4[r118] ^= t
	
	state.next = t & 0xFFFF
	state.chEIP(+11)


def OP_188(state, log):
	state.reg4[r118] |= 0x3acc60a1

	t = (state.read2(4) + state.reg4[r118]) ^ state.reg4[r125]
	state.reg4[r118] ^= t
	state.reg4[r102] |= 0x271cbbe1
	state.reg2[ref] += t
		
	t = (state.read2(2) - state.reg4[r118]) ^ state.reg4[r8]
	state.reg4[r118] |= t
	state.reg4[r102] += 0xeca48405
	state.reg2[r2f] += t
	
	r1 = UW(state.reg2[ref])
	r2 = UB(state.reg2[r2f])
	
	state.VM_MOV_R8_MR4(log, r1, r2)

	t = (state.read2(0) - state.reg4[r118]) ^ 0x59b5f6c1
	
	state.reg4[r118] += t
	
	state.next = t & 0xFFFF
	state.chEIP(+6)

def OP_308(state, log):
	t = (state.read2(10) - state.reg4[r118]) - state.reg4[r125]
	state.reg4[r118] |= t
	state.reg4[r102] += 0x51652c45
	state.reg2[ref] ^= t
	state.reg4[r102] |= 0x27959793
		
	t = (state.read4(0))
	state.reg4[r102] &= 0x31861101
	state.reg4[r114] += t
	state.reg4[r8] &= t
	
	r = UW(state.reg2[ref] ^ 0x7272)
	v = UDW(state.reg4[r114])
	
	state.VM_XOR_R8_R4_V(log, r, r, v)

	t = (state.read2(6)) ^ 0x7f86a985
	
	state.reg4[r118] -= t
	
	state.next = t & 0xFFFF
	state.chEIP(+12)


def OP_207(state, log):
	stk = state.read2(2)
	v = state.read2(0)
	log.append("{}JMP OUT {} ".format(state.GetPos(), state.RegName(v)))
	
	state.run = False


def GetFunc(opid):
	opname = "OP_{:02x}".format(opid)
	if opname in globals():
		return globals()[opname]
	return None


def Parse(state):
	ERR = list()
	PARSED = dict()

	for rt in state.Routes:
		state.mem = rt.mem
		state.next = rt.next
		state.reg4[R_EIP] = rt.eip
		state.esp = rt.esp
		state.popping = rt.pops
		state.regnames = rt.regnms
		state.run = True
		print("Route {:02X}".format(rt.eip))
		while(state.run):
			eip = state.reg4[R_EIP]
			if eip in PARSED:
				print("Already parsed, BREAK!")
				break
			
			if len(state.data) - eip < 4:
				break

			log = list()
			PARSED[eip] = log
			
			#log.append("--OP 0x{:02X}  Addr: 0x{:08x}   \t| 0x{:02X}/0x{:02X}".format(state.next, state.dataaddr + state.reg4[R_EIP], state.reg4[R_EIP], len(state.data)) + "    " + state.data[state.reg4[R_EIP]: state.reg4[R_EIP] + 4].hex())
			#log.append("r118 {:x}  r102 {:x}  ref {:x}".format(state.reg4[r118], state.reg4[r102], state.reg2[ref]))
				
	
			func = GetFunc(state.next)
			if func == None:
				log.append("UNKNOWN !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				break
			func(state, log)
			
			
			
	print("\n\n#################################################\n\n")
	return PARSED, ERR
	
if __name__ == "__main__":

	#for n in sorted(VMAsm):
	#	print(hex(n))
	pass