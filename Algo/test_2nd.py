from twofish import Twofish


servkey = b'\xee\x59\x28\xd7\xa1\x6c\x54\x87'
testdata = bytearray(b'\xe2\x22\xb5\x78\xe2\x76\x36\x35\xda\xf6\x2e\x69\x66\x9a\xe2\x02\x57\xe9\xf7\xd7\xbb\xd3\x39\x24\xb4\x17\xc3\x05\x9d\x9f\x20\xf0\x21\x91\x53\xbc\x53\x9c\x85\xb0\x2a\xa9\xba\x17\x0f\x19\x08\x2c')




default2ndKey = bytearray(b'\x93\xd8\x2c\xf1\xe8\x03\x5a\x7d\x88\x5f\xdb\xa7\x14\x9c\xbe\x63')
staticKey = b"nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9"


xorkey = servkey[:4]

def RandomizeSecondPwdKey(xorkey):
	key = bytearray(default2ndKey)
	key[0] ^= xorkey[0]
	
	for i in range(1, 16):
		key[i] ^= staticKey[i & 0x3F] ^ xorkey[i & 3] ^ key[i - 1]
	
	return key
	
def RandomizeSecondPwdShuffleKey(xorkey):
	key = bytearray(default2ndKey)
	key[0] ^= xorkey[1]
	j = 15
	k = 2
	for i in range(1, 16):
		key[i] ^= staticKey[(16 - i) & 0x3F] ^ xorkey[ (i + 1) & 3 ] ^ key[ i - 1 ]
	
	return key


# def RandomizeSecondPwdContentsKey(shuffle):
# 	key = bytearray(default2ndKey)
# 	for b in shuffle:
# 		key[0] ^= b
# 	
# 	key[0] ^= key[15]
# 	key[15] ^= key[0]
# 	return key

SecondPwdKey = RandomizeSecondPwdKey(xorkey)
SecondPwdShuffledKey = RandomizeSecondPwdShuffleKey(xorkey)

fish = Twofish(bytes(SecondPwdKey))

decr = fish.decrypt(bytes(testdata[:16])) + fish.decrypt(bytes(testdata[16:32])) + fish.decrypt(bytes(testdata[32:]))

strLen = decr[1] ^ SecondPwdShuffledKey[1]
multiplier = decr[0] ^ SecondPwdShuffledKey[0]

decr2 = bytearray(strLen)

for i in range(strLen):
	index = 2 + ((multiplier * (i + 1)) % 43)
	decr2[i] = SecondPwdShuffledKey[index & 0xf] ^ decr[index]

print(decr2)