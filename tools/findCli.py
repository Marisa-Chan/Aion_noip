#!/usr/bin/python3

VERSION = "TEST"

pairs = list()
unknown = list()

#unknown.append( crypted )
#unknown.append( (val+/-, crypted) )
#unknown.append( ((from, to), crypted) )

#C_VERSION		0 [game] send version
#C_LOGOUT		2 [game] send login_out
#C_ASK_QUIT		3 [game] send quit
#C_READY_TO_QUIT	4 [game] send ready to quit

#C_LEVEL_READY	9 [game] send level_ready

#C_L2AUTH_LOGIN 149(4.7.5,4.8,4.9) 150(7.7)  [game] send login_l2 

#C_RECONNECT_AUTH 183(4.7.5, 4.8, 4.9) 184(7.7) [game] send reconnect_auth

#C_ACCUSE_CHAT_SPAMMER		(4.7.5, 4.8, 4.9 : 245,  7.7 : 246) near ConsoleClientMsgID(0xdcf7f,0,0,0,0);
#


A = 0  # in GetCmdS ( (id ^ xx) - A ). Near recv server packets and decrypt with "nKO/WctQ..................."

if VERSION == "TEST":
	#4.7.5
	pairs.append( (0,0xc2) ) #C_VERSION    
	pairs.append( (2,0xa4) ) #C_LOGOUT
	pairs.append( (3,0xa5) ) #C_ASK_QUIT
	pairs.append( (4,0xa6) ) #C_READY_TO_QUIT
	
	unknown.append( (150, 0x177) ) #C_L2AUTH_LOGIN 
	unknown.append( (184, 0x199) ) #C_RECONNECT_AUTH
	
	A = 0xCE
elif VERSION == 475:
	#4.7.5
	pairs.append( (0,0xc2) ) #C_VERSION    
	pairs.append( (2,0xa4) ) #C_LOGOUT
	pairs.append( (3,0xa5) ) #C_ASK_QUIT
	pairs.append( (4,0xa6) ) #C_READY_TO_QUIT
	
	pairs.append( (149,0x177) ) #C_L2AUTH_LOGIN

	pairs.append( (245,0x1d7) ) #C_ACCUSE_CHAT_SPAMMER
	
	A = 0xCE
elif VERSION == 48:
	#4.8
	pairs.append( (0,0xc3) ) #C_VERSION    
	pairs.append( (2,0xa5) ) #C_LOGOUT
	pairs.append( (3,0xa6) ) #C_ASK_QUIT
	pairs.append( (4,0xa7) ) #C_READY_TO_QUIT

	pairs.append( (245,0x1d8) ) #C_ACCUSE_CHAT_SPAMMER

	A = 0xCF
elif VERSION == 49:
	#4.9
	pairs.append( (0,0xDE) ) #C_VERSION
	pairs.append( (2,0xDC) ) #C_LOGOUT
	pairs.append( (3,0xDD) ) #C_ASK_QUIT
	pairs.append( (4,0xc2) ) #C_READY_TO_QUIT

	pairs.append( (6,0xc0) ) #C_CHECK_LEVEL_DATA_VERSION

	pairs.append( (8,0xc6) ) #C_CHECK_LEVEL_DATA_VERSION

	pairs.append( (14,0xc8) ) #C_CAPTCHA

	pairs.append( (27,0xD5) ) #C_SAY

	pairs.append( (41,0xE7) ) #C_BUILDER_COMMAND

	pairs.append( (145,0x16F) ) #C_RECONNECT

	pairs.append( (155,0x155) ) #C_LOOT

	pairs.append( (209,0x1af) ) #C_COMPOUND_ENCHANT_ITEM

	pairs.append( (245,0x1b3) ) #C_ACCUSE_CHAT_SPAMMER

	A = 0xD0
elif VERSION == 77:
	#7.7
	pairs.append( (0,0xd6) ) #C_VERSION    
	pairs.append( (2,0xd4) ) #C_LOGOUT
	pairs.append( (3,0xd5) ) #C_ASK_QUIT
	pairs.append( (4,0xca) ) #C_READY_TO_QUIT
	
	pairs.append( (9, 0xdf) ) #C_LEVEL_READY
	
	
	pairs.append( (150,0x158) ) #C_L2AUTH_LOGIN


	pairs.append( (246,0x1b8) ) #C_ACCUSE_CHAT_SPAMMER
	
	A = 0xD8
	
	
	

#for A in range(0x80, 0x100):

srt = list()
nmax = 0


for B in range(0x80, 0x100):
	for C in range(0x80, 0x100):
		klkt = 0
		for (ik, ok) in pairs:
			compu = (((ik + A) ^ B) + 0xC) ^ C
			if (compu == ok):
				klkt += 1
		
		if klkt >= 1: #len(pairs) / 2:
			srt.append( (klkt, "(((K + {:02X}) ^ {:02X}) + 0xC) ^ {:02X}".format(A,B,C), (A,B,C)) )
		
		if nmax < klkt:
			nmax = klkt





# Additional calculations for encrypted 

maxl = list()

print(nmax, "/", len(pairs))
for n,s,t in srt:
	if n == nmax:
		print(s)
		maxl.append( t )
	
if len(unknown) > 0:
	print("Trying to find correct ids for packets")
	wei = dict()
	for i in range(len(maxl)):
		wei[i] = 0
	
	cpi = dict()
	for i in range(len(unknown)):
		cpi[i] = list()
		
		a = 0
		b = 360
		crid = 0
		
		if type(unknown[i]) is tuple:
			tpl = unknown[i][0]
			crid = unknown[i][1]
		
			if type(tpl) is tuple:
				a = tpl[0]
				b = tpl[1] + 1
			else:
				a = tpl - 0xF
				b = tpl + 0xF
		else:
			crid = unknown[i]
		
		print("\tFor 0x{:02X} possible is: ".format(crid))
		
		for p in range(len(maxl)):
			pars = maxl[p]
			did = (((crid ^ pars[2]) - 0xC) ^ pars[1]) - pars[0]
			if did in range(a,b):
				wei[p] += 1
				cpi[i].append( (did, p) )
				print("\t\t {:d}({:02X}) --> (((K + {:02X}) ^ {:02X}) + 0xC) ^ {:02X}".format(did,did,pars[0],pars[1],pars[2]))
	
	print("Weights for pairs")
	for a,b in sorted(wei.items(), key=lambda item: item[1], reverse=True):
		pars = maxl[a]
		print("\t {:d}   (((K + {:02X}) ^ {:02X}) + 0xC) ^ {:02X}".format(b, pars[0],pars[1],pars[2]))
	
			


		
		
