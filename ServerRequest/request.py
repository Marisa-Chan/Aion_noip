#!/usr/bin/python3

#import socks
import socket
import sys


CompanyID = 0
GameID = b'AION_KOR'


RespNames = {
0:"CompanyInfo [0]",
1:"ServiceInfoGameList [1]",
2:"GameInfoLanuch [2]",
3:"GameInfoUpdate [3]",
4:"GameInfoExeEnable [4]",
5:"ServiceInfoDisplay [5]",
6:"VersionInfoRelease [6]",
7:"VersionInfoForward [7]",
8:"GameInfoLanguage [8]",
9:"GameInfoLevelUpdate [9]"
}

Responses = dict()
Responses[0] = {1:"CompanyID", 2:"CompanyName", 3:"LicenseVersion"}
Responses[1] = {1:"CompanyID", 2:"Count", 3:"GameID"}
Responses[2] = {1:"GameID", 2:"ExeArgument", 3:"ExeFileName", 4:"GameName", 5:"UpdateMethodCode", 6:"UpdateServerAddress2", 
				7:"AutoUpdateFlag", 8:"AutoExeFlag", 9:"AutoSeparateUpdateFlag", 10:"AutoInstallFlag", 11:"AutoExitFlag", 12:"HideFlag"}
Responses[3] = {1:"GameID", 2:"RepositoryServerAddress", 3:"TrackerAddress"}
Responses[4] = {1:"GameID", 2:"ExeEnableFlag"}
Responses[5] = {1:"GameID", 2:"CompanyID", 3:"SkinName", 4:"PostPageUrl", 5:"FullDownloadUrl", 6:"FullDownloadType", 7:"FullDownloadSize",
				8:"FullDownloadVersion", 9:"GameDisplayCode"}
Responses[6] = {1:"GameID", 2:"P2PEnableFlag", 3:"P2PPeerCount", 4:"GlobalVersion", 5:"DownloadFileIndex", 6:"TotalDownloadFileCount", 
				7:"MultiVersionUpdateMode", 8:"SequentialUpdateThreshold", 9:"DirectUpdateThreshold", 10:"FileInfoHashValue"}
Responses[7] = {1:"GameID", 2:"P2PEnableFlag", 3:"P2PPeerCount", 4:"ForwardVersion", 5:"ForwardMultiVersionUpdateMode", 6:"ForwardSequentialUpdateThreshold", 
				7:"ForwardDirectUpdateThreshold", 8:"ForwardFileInfoHashValue"}
Responses[8] = {1:"GameID", 2:"GameLanguageArgument", 3:"GameLanguagePak"}
Responses[9] = {1:"GameID", 2:"GameLevelUpdate"}

def pbufWVariant(i):
	bt = bytearray()
	if i == 0:
		bt.append(0)
		return bt
	else:
		while i > 0:
			if (i & 0x80):
				bt.append( 0x80 | (i & 0x7F) )
			else:
				bt.append( i & 0x7F )
			i >>= 7
	return bt


def pbufRVariant(data):
	i = 0
	j = 0
	while j < 10:
		b = data[ j ]
		i |= (b & 0x7F) << (j * 7)
		
		j += 1
		
		if (b & 0x80) == 0:
			break
	return (data[ j: ], i)


def pbufW0(fld, i):
	bt = bytearray()
	bt.append( (fld & 0xF) << 3 )
	bt += pbufWVariant(i)
	return bt

def pbufR0(data):
	fld = (data[0] >> 3) & 0xF
	(data, i) = pbufRVariant(data[1:])	
	return (data, fld, i)

def pbufW2(fld, st):
	bt = bytearray()
	bt.append( (fld & 0xF) << 3 | 2 )
	bt += pbufWVariant( len(st) )
	bt += st
	return bt

def pbufR2(data):
	fld = (data[0] >> 3) & 0xF
	(data, ln) = pbufRVariant(data[1:])
	btstr = data[:ln]
	return (data[ln:], fld, btstr)



def assemblePkt(cmdID, data):
	tmp = (4 + len(data)).to_bytes(2, byteorder="little")
	tmp += cmdID.to_bytes(2, byteorder="little")
	tmp += data
	return tmp



def parsePkt(data):
	if len(data) <= 4:
		return list()
	
	ln = int.from_bytes(data[0:2], byteorder = "little")
	cmdid = int.from_bytes(data[2:4], byteorder = "little")
	if (ln != len(data)):
		return list()
	
	pdat = list()
	pdat.append(cmdid)
	
	data = data[8:]
	
	while len(data) > 0:
		tp = data[0] & 0x7
		if (tp == 0):
			(data, fld, i) = pbufR0(data)
			if (fld != 0):
				pdat.append( (fld, i) )
		elif (tp == 2):
			(data, fld, bts) = pbufR2(data)
			if (fld != 0):
				pdat.append( (fld, bts) )

	return pdat 


def PrintResponse(dt):
	if len(dt) == 0:
		return
	
	if dt[0] not in RespNames:
		print("Unknown Response")
		print(dt)
		return
	
	print ( "Response:", RespNames[ dt[0] ] )
	
	respDict = Responses[ dt[0] ]
	
	for f in dt:
		if isinstance(f, tuple):
			fid = f[0]
			fdat = f[1]
			if fid in respDict:
				print( "{}: {}".format( respDict[fid], fdat ) )
			else:
				print( "{}: {}".format( fid, fdat ) )
	





sock = socket.socket()
#sock = socks.socksocket()
#sock.set_proxy(socks.SOCKS5, "211.104.160.132", 1080)

sock.connect( ("up4svr.plaync.com", 27500) ) #From Localization.dll

PKTS = dict()

##Launcher -> Serv   
# CompanyID - NCSoft_Kor = 0

# CompanyInfo
# ID 0   1: Type0 - CompanyID
PKTS[0] = assemblePkt(0, pbufW0(1, CompanyID) )

# ServiceInfoGameList
# ID 1   1: Type0 - CompanyID
PKTS[1] = assemblePkt(1, pbufW0(1, CompanyID) )

# GameInfoLanuch
# ID 2   1: Type2 - GameID
PKTS[2] = assemblePkt(2, pbufW2(1, GameID) )

# GameInfoUpdate
# ID 3   1: Type2 - GameID
PKTS[3] = assemblePkt(3, pbufW2(1, GameID) )

# GameInfoExeEnable
# ID 4   1: Type2 - GameID
PKTS[4] = assemblePkt(4, pbufW2(1, GameID) )

# ServiceInfoDisplay
# ID 5   1: Type2 - GameID     2: Type0 - CompanyID
PKTS[5] = assemblePkt(5, pbufW2(1, GameID) + pbufW0(2, CompanyID) )

# VersionInfoRelease
# ID 6   1: Type2 - GameID
PKTS[6] = assemblePkt(6, pbufW2(1, GameID) )

# VersionInfoForward
# ID 7   1: Type2 - GameID
PKTS[7] = assemblePkt(7, pbufW2(1, GameID) )

# GameInfoLanguage
# ID 8   1: Type2 - GameID
PKTS[8] = assemblePkt(8, pbufW2(1, GameID) )

# GameInfoLevelUpdate
# ID 9   1: Type2 - GameID
PKTS[9] = assemblePkt(9, pbufW2(1, GameID) )


if len(sys.argv) != 2:
	print("Specify request ID:")
	for i in range(0,10):
		print(RespNames[i])
	exit()

i = int(sys.argv[1])
sock.send( PKTS[i] )


data = sock.recv(4096)

readed = parsePkt(data)
PrintResponse(readed)
#print( readed )

sock.close()