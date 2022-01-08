#!/usr/bin/python3

#10594edd

import sys
import TVM

def FNC(state, log):
	eip = state.reg4[TVM.R_EIP]
	if eip == 0xFBC:
		log.append("\n#memset     \n")

		tmp = state.esp
		log.append(hex(state.esp))
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x141777a - 0x14167b4)
		log.append("#Jump to route {:02X}".format(0x141777a - 0x14167b4))
	elif eip == 0x10EF:
		log.append("\n#FUN_100b0780     \n")

		tmp = state.esp
		log.append(hex(state.esp))
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x14178ad - 0x14167b4)
		log.append("#Jump to route {:02X}".format(0x14178ad - 0x14167b4))
	elif eip == 0x11FE:
		log.append("\n#FUN_1005a280     \n")

		tmp = state.esp
		log.append(hex(state.esp))
		state.push(0xFF0F0000) #eflags
		state.push(0xFF1F0000) #eax
		state.push(0xFF2F0000) #ecx
		state.push(0xFF3F0000) #edx
		state.push(0xFF4F0000) #ebx
		state.push(tmp) #esp
		state.push(0xFF6F0000) #ebp
		state.push(0xFF7F0000) #esi
		state.push(0xFF8F0000) #edi
		
		state.AddRoute(0x444, 0x14179bc - 0x14167b4)
		log.append("#Jump to route {:02X}".format(0x14179bc - 0x14167b4))
	else:
		log.append("\n\n#OnEnd {:02X}\n\n".format(eip))


state = TVM.VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\x3c\x03\xce\x4d\x7a\x00\x82\xbe\x3d\x00\xb8\x00\x28\x00\x82\xbe\x3d\x00\xaa\x00\x41\x00\x15\xbd\x3d\x00\x3d\x00\xf5\x04\x90\x00\x01\x9b\x52\x00\x02\xfb\x04\xf7\x3d\x00\x86\x93\x7a\x00\x11\xae\x3d\x00\x3d\x00\x3c\x03\x41\x00\x72\x1c\x7a\x00\xbe\xff\x90\x00\xb7\x1f\x3d\x00\xf5\x77\x75\x00\x11\x00\x3d\x00\x49\x05\x08\x3d\x00\x20\x75\x75\x00\x7a\x00\x1b\xb8\x3d\x00\x75\x00\x1e\xe4\x41\x00\x56\xf4\x75\x00\x61\x2b\x5e\x7e\x41\x00\xaf\x35\x3c\x14\x0b\xf1\x75\x00\x75\x00\x3c\xdc\x22\x04\x9a\x9a\xc1\x48\x26\xc8\x76\x02\x12\xde\x75\x00\x7a\x00\x3d\x00\x75\x00\x72\x07\x75\x00\x52\x00\x3d\x00\x3d\x00\xe8\x02\x28\x00\x72\x40\x28\x00\x47\x98\x11\x00\x3d\x00\x98\x9e\x0a\x3e\xd6\x61\x29\xa6\x8c\x91\x22\xed\x2c\x49\x88\xa3\xdf\x47\x41\x00\x1e\xf5\x7a\x00\x3d\x00\x63\xa7\xa0\xeb\x7d\xec\x52\x00\x08\xe8\x7a\x00\x7e\xee\xa3\xd9\x75\x00\xcc\x93\x3d\x00\x18\xa7\x67\x28\xf8\xe5\x3d\xc3\x75\x00\x3c\x59\x0e\x66\x52\x00\x75\x00\x27\x3b\x52\x00\xd7\x39\x2c\x0a\x72\x32\x91\xcc\xa8\xb9\xad\x8a\x75\x00\x90\x00\xa6\x6f\x41\x00\x9a\xf1\xfb\x1b\x75\x00\xce\x8c\x0d\xbd\xac\xf8\xd6\x9b\x3d\x00\x4b\xc1\xb6\x5a\xc2\x41\x35\x2d\x04\xd1\x4d\x52\x84\x45\x32\x3e\x90\x00\x3d\x00\x3d\xfa\xfd\xdc\x5a\xee\x2a\x91\x82\x00\x7b\x9d\x7a\x9b\xbc\xb3\x40\x23\x9f\x68\x5c\x31\x25\x2f\x04\x77\x92\x3f\x16\x7a\xc3\x15\x17\x20\x0b\xd2\xc0\xb3\x1a\x03\x09\x17\xc8\x19\x3d\x00\xf8\x1e\xed\x7f\x70\x0a\x3d\x00\x05\xa2\x72\x80\x6a\xc2\x75\x00\x69\x01\xe6\x5e\x7a\x00\xf8\x29\x68\x06\x47\xc0\x19\x40\x2b\x2f\x05\xba\x7a\x00\xf8\x1a\x97\x63\x7a\x00\x73\xa4\x75\x00\x28\x00\x75\x00\x3a\xd1\x75\x00\x39\x9a\x28\x00\xf2\x0a\x20\x0a\x8f\x4d\x90\x00\xad\xb9\x3d\x00\xb8\x6b\x76\xd4\x99\x6c\x63\x75\x75\x00\x4e\x5c\x3d\x00\xa2\xeb\x0e\xd7\xfb\x59\x2a\x7d\xe0\x30\x00\x49\x33\x5e\x3f\x43\x7a\x00\xb2\xe8\xd0\xfe\xc0\xf8\x0f\xfa\x11\x00\x75\x00\x52\x00\x75\x00\x7a\x00\x52\x00\x41\x00\x90\x00\x7e\x1b\x90\x00\x28\x00\x11\x00\x52\x00\x11\x00\x41\x00\x28\x00\x7a\x00\x51\x00\x00\x00\x95\x00\x00\x00\x75\x00\xa2\xb4\x7d\xff\x7a\x11\x44\x3d\x00\x29\x27\xed\x72\xf6\x36\x47\x00\xe9\x3f\x39\x0a\x95\xa2\x27\x41\x42\x76\x64\x37\x75\x00\x0f\x87\x3d\x00\x5b\xad\xd1\x9c\x1f\x56\x52\x00\x75\x00\x46\xe3\x11\x00\x28\x00\xea\x58\x3d\x00\x75\x31\x7a\x00\x9f\x74\x6c\xc7\x52\x00\x0c\xcc\x75\x00\x28\x00\x75\x00\x44\xe6\x3d\x00\x35\x47\x7a\x00\x52\x00\x41\x00\x41\x00\xc9\xea\x90\x00\x11\x00\x28\x00\x52\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x51\x00\x00\x00\x95\x02\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x08\xec\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x91\x04\x52\x00\x0b\x29\xa6\x03\x75\x00\x07\x50\xfe\x64\x7a\x00\x52\x00\x41\x00\x41\x00\x0e\x19\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x05\x01\x00\x00\x75\x00\xa2\x75\x7f\x68\x68\x75\x00\x11\x00\xf3\xb8\x3d\x00\xa1\x44\xad\x42\x3e\x70\x6f\xa1\x82\xc1\x3f\xed\xfc\x27\xe2\xf3\xf7\x1d\xe8\x77\x75\x00\xda\xc1\xf3\x5c\xe5\x77\x57\xb7\x89\x52\xf0\x3d\x89\x1a\xd1\x76\x41\x00\x1f\x72\xa2\x94\x41\x00\x42\xc1\x75\x00\x52\x00\x75\x00\x47\x18\x75\x00\x41\x00\x67\x90\x78\x27\xb1\x22\x75\x00\x3d\x00\x45\x07\x96\xa2\x23\x56\x41\x00\x75\x00\xb7\x88\x82\x69\x2b\x6d\x3d\x00\x28\x15\x16\xef\x14\x42\xab\x4f\x1f\x28\x0b\xee\x6a\x0c\x2d\xf4\x3d\x00\x56\x6e\x52\x00\x14\x1d\x90\x00\x93\x1c\xf9\xa1\x75\x00\x0e\x6a\x3d\x00\x6b\xda\xfc\xce\x6f\xed\x0c\x87\x8a\x18\x41\xec\x67\x9f\x5e\x17\x11\x00\xcb\xef\x22\x94\x8f\x12\x75\x00\x90\x84\x7c\x25\x81\xb3\x75\x00\x3d\x00\xdc\xd6\xc3\x04\x09\x4e\x98\x20\x4c\xf7\x4d\x2a\xa2\xea\x29\x41\x11\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xdf\xa8\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x52\x00\x51\x00\x00\x00\x68\x01\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x26\xa8\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x03\x97\x38\x75\x00\x52\x00\x84\xbb\x3d\x00\x8f\xc2\x08\xee\x14\x7b\x90\x65\xe7\xd0\x58\x76\x07\x05\x62\x55\xeb\xeb\x49\x4b\x88\x4c\xd6\x17\x7a\x00\x34\x56\x20\x4a\x75\x00\xab\xc4\x76\xcc\xff\x7b\x3b\xa0\xae\xc8\xe7\x81\x21\x6d\x5b\x5c\x3d\x00\x3d\x00\xfd\xf8\xb3\xcf\x07\x3e\x1c\xc0\x75\x00\xeb\x75\x78\x6d\x52\x00\x3b\xfc\x2e\xed\xe6\xd2\x64\x14\x20\x05\x3d\x00\xc5\xa2\xad\x1c\x75\x00\xd9\x39\x17\xc8\x52\x00\xde\x38\x75\x00\x28\x00\xf3\xb8\x3d\x00\xa7\x42\xb3\x65\xc8\xce\x6c\xd4\xa8\xf6\x41\x04\x58\xab\x51\x00\x93\x75\x75\x00\x41\x00\xc3\xae\x13\x6a\x50\xaa\x11\x00\x41\x00\xfc\xe5\x57\x29\x7a\x00\x8c\x0b\x34\x56\xf7\xbf\xc8\xf1\x90\x00\x75\x00\x90\x00\x78\xaa\x4d\x2d\x75\x00\xe0\x55\x75\x00\x28\x00\x89\xd1\x12\x58\x3d\x00\x11\x00\x5d\x7f\x11\x00\x7a\x00\x4c\x7d\x52\x00\xde\x89\x75\x00\x75\x00\x55\x2d\xc4\x15\x9d\xd0\x70\x34\x63\x93\xa6\x52\xad\xdd\x52\xe0\x75\x00\x8c\x32\x6a\xa9\xfb\x5a\x3d\x00\x14\x00\x11\x00\xd7\xbf\x90\x00\x11\xd5\x3d\x00\x5d\xf4\xb1\x33\x97\x51\x41\x00\xf0\xba\x28\x00\x90\x00\x4a\x80\x41\x00\x18\xe9\x52\x00\x9f\xd3\x77\x11\x41\x78\xd8\xfb\x0b\x53\x0b\xee\x2f\x76\xee\xe0\x3d\x00\x9f\x71\xa8\x05\xe2\xc3\x4b\xc7\x76\x82\x90\x00\x11\x00\x75\x00\x3d\x00\xf0\x16\x7a\x00\x52\x00\x41\x00\x7a\x00\xf5\xdb\x90\x00\x41\x00\x28\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa6\x03\x0a\x6a\xea\x7f\x00\x00\x61\xe8\x66\xde\x24\x2f\x8c\x38\x09\x42\xed\xee\x47\xb4\x11\xc1\x96\xe2\xef\x39\xa0\xc2\x75\x00\xef\x4d\x3c\x11\x52\x00\x8d\x0d\x75\x00\x11\x00\x5d\xb8\x3d\x00\x79\xe2\x55\x53\x31\x37\xdc\x5d\x52\x0f\x41\x00\xcf\x7e\xf5\x59\x52\x00\x6a\xca\x75\x00\x90\x00\x75\x00\x5c\x77\xdb\x2f\xb5\x61\xaf\xa5\x75\x00\x55\x64\xa3\x92\x27\xa7\x0c\xd3\x2c\x4d\xce\x95\x09\x88\x27\xd9\xbb\xdb\x1d\x18\x91\x54\x3d\x00\x04\x5d\xab\x73\xdd\xeb\x56\x65\x3d\x00\x04\xac\x90\x8a\x0b\x77\x52\x00\x75\x00\x0b\x90\x41\x00\x3b\xf0\x28\x00\x11\x00\x61\xf6\x11\x00\x79\x7f\x90\x00\x46\x28\xce\x95\x7d\x37\x60\x46\xde\x35\x0b\xee\xc3\x72\x45\xf4\x3d\x00\xd2\x59\x75\x00\xc8\x0a\xde\x07\xca\x3e\x39\x07\x37\xda\x9c\x02\x3d\x00\x7a\x78\x75\x00\xdd\xb0\x11\x00\x24\x89\x34\xcd\x9b\x4e\xd6\xb8\xed\x6d\x64\x91\x3a\x6e\x76\xf0\x9f\x5f\x18\x7b\x25\x63\x94\x74\x24\xe4\xf2\x17\xde\x97\x3d\x00\xca\xdc\x90\x00\x3d\x00\xb4\x7b\xc5\x07\x7b\x3c\x1d\xc4\x3d\x00\x9a\x04\x7a\x00\x23\x10\x11\x00\x41\x00\x75\x00\x89\x37\x6b\x87\x75\x00\x33\xc2\xd1\x45\x28\x08\x75\x00\x72\xcd\xa7\x8d\x45\x9c\x80\xc5\x28\x00\x41\x00\x90\x00\x90\x00\x3e\xd5\x11\x00\x4f\x68\x91\x3f\x11\x00\x6c\x11\x75\x00\x90\x00\x75\x00\xf7\x32\xe6\x17\xd0\x6e\x3d\x00\x75\x00\x56\x5a\x7a\x00\xf0\x9a\x8f\xd5\x77\xd0\x08\x43\x3d\x00\x75\x00\xc4\x84\x59\x76\x94\x1f\xc1\x50\xe8\x7c\x67\x0e\x3d\x00\x36\x13\xca\x80\x98\xf7\xe2\x79\x11\x00\x52\x00\x75\x00\x01\xbc\x28\x00\xc4\x3e\x3d\x00\xb8\x00\x11\x00\x76\xb8\x3d\x00\x7c\x60\x4a\x32\x75\x00\x4d\xb9\x11\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x30\x1d\x90\x00\x28\x00\x7a\x00\x52\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\x5b\x02\x00\x00\x75\x00\x80\x00\x02\x7a\x00\x52\x00\x41\x00\x41\x00\x5b\xe4\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xe8\x02\x7e\x03\x41\x00\x3d\x00\x00\xc7\x12\x55\xc1\xb4\x44\x33\x8a\x31\x89\x65\xc6\xc4\x75\x00\xae\x82\xfe\x04\x7a\x00\x7d\xad\x31\x42\x39\x5f\xa6\xb0\x75\x00\x11\x00\xa4\xb9\x3d\x00\x75\x00\x2b\xd2\x41\x00\x71\xaa\x97\xe1\x63\x19\x33\x61\xf0\xd2\x21\x63\x92\x13\x37\x08\xc6\x14\xaf\x98\x7c\x96\xca\x26\xd1\xb4\xde\x21\x7a\x00\x28\x00\x75\x00\xb3\x91\x9d\x93\x43\x74\xa0\x77\x3b\xe8\xbf\x98\x3d\x00\x34\x69\x32\x32\x2c\x56\xe2\xe1\xb6\x89\x75\x00\x52\x00\x5d\x2b\x70\x8e\x75\x00\x46\x51\xb3\xb3\x75\x00\x11\x00\x4f\x33\x93\x23\xaf\x91\x75\x00\x4a\xd7\x4f\xfb\xca\xa9\xd5\x82\x28\x00\x7a\x00\x75\x00\x1b\xeb\x15\x41\x3d\x00\x00\x04\x28\x00\xb0\x79\x61\xd5\xe2\x11\x75\x00\x7a\x00\x51\xa6\xda\x7e\xae\xa1\x49\xb0\x61\x15\x75\x00\x75\x00\x22\xb6\xff\x72\xe1\x4c\x9f\x51\xa5\xdb\x75\x00\xe0\xfe\xf9\xf4\x52\x00\x9d\x0b\x3d\x00\x28\x00\x90\x00\xf8\x65\x99\x05\xb7\x54\x75\x00\x0f\x38\x75\x00\x11\x00\x26\xba\x3d\x00\x8a\xa1\x94\x1f\x75\x00\xc3\x24\xba\x84\x52\x00\xc9\x7d\x11\x44\x3d\x00\x02\x16\x87\x3a\x7b\x98\x1c\xb9\x08\x95\x92\xe9\x75\x00\x0c\x07\x52\x00\x22\x4d\x43\xca\xaa\x49\xec\xcb\x59\x14\x75\x6e\x69\x46\xa4\xed\xef\xca\x4c\xa3\x75\x00\x1d\xab\x9b\x0a\xd7\xeb\x3d\x00\xfc\x02\x52\x00\x09\x6e\x90\x00\x75\x00\x94\x7a\x11\x00\xf4\x14\x52\xd0\xa5\x80\x02\x4f\xd4\x42\x2a\x1c\xfb\x47\xea\x55\xdb\x36\x9b\xb7\xf3\x73\x8c\xef\x7e\x74\x75\x00\x52\x00\xfa\xe9\xca\xff\x01\x08\x4d\xe1\x63\x15\xfa\x44\x10\x9d\x96\xc4\x1a\x31\xc5\x1e\x86\x4e\x75\x00\x87\xf2\x44\x15\x8d\xa8\xaf\x72\x4c\x7d\x11\x00\xc2\xba\x3d\x00\x7a\x4d\x62\x43\x3d\x00\x75\x00\x86\xb2\x52\x00\x72\x3b\x92\x52\x82\x4d\x15\x41\x3d\x00\x7c\xf0\x41\x00\xc2\xdf\x0f\x70\x93\x6f\x75\x00\x90\x00\xa6\x0c\x31\x06\x41\x00\x98\xc3\x75\x00\x52\x00\x75\x00\x38\x95\x07\x7b\x28\xe6\x28\x00\x52\x00\xf7\xb9\x28\x00\x07\xd7\x11\x00\xa0\xc4\x38\x6b\x75\x00\x7a\x9e\x3d\x00\xac\x01\x90\x00\x5a\xb5\x41\x00\x9a\x2f\x65\x97\x5d\x7f\xc5\xaa\x75\x00\xc0\xa6\x28\x70\xf3\x85\x3d\x00\xe6\x69\x1a\xcd\x21\x69\x65\x19\xb1\xed\x77\x52\x13\x9a\xaf\x12\x41\x00\x3d\x00\xb1\x62\x7a\x00\x52\x00\x41\x00\x41\x00\x69\x16\x90\x00\x11\x00\x28\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x52\x00\x51\x00\x00\x00\x1e\x05\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xb4\x17\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xfc\x02\x75\x00\x7e\xff\x11\x00\x7e\xff\x8e\x07\xe5\x3f\xb4\x30\x61\xef\x77\xd3\xaf\x92\x95\x25\x84\x19\x6b\xb5\x52\x00\xab\x95\x90\x00\x7a\x00\x53\x81\x28\x00\xa1\xee\x28\x00\x52\x00\x02\x64\x90\x00\x90\x00\x9d\x5d\x90\x00\x38\x6c\x75\x00\x75\x00\xe3\x4b\x16\xac\xe1\x1c\x00\x84\xd4\x5c\x40\xee\x34\x95\xbc\x88\x7a\x00\x75\x00\x7a\x00\x11\x00\x00\x47\x7a\x29\x75\x00\xc2\x65\x7a\x00\x95\xa2\x10\xda\xf7\x14\x8a\xe6\x2c\x29\xa4\xdf\x60\x48\xb9\x0d\x18\x9a\xaa\x57\x25\xee\x18\x8a\xd2\x07\xe5\x4a\x4c\x06\xa0\x57\x0e\x00\x56\xeb\x11\x00\xca\xae\x11\x00\x8a\xef\x56\x13\x75\x00\x68\xd5\x3d\x00\x39\x68\x24\xcc\x8e\xee\x9f\xb2\x75\x00\x2d\xbb\x41\x00\xa0\x8d\x5a\x9c\xd5\x02\xa9\xe0\x61\x78\x22\x05\x3b\xe1\x73\xb6\xb8\xf4\x06\xb8\x8c\x47\x7a\x4a\x75\x00\x3d\x00\x98\x95\x26\xc8\x12\x8d\xce\x8b\x70\x86\xe5\x47\x48\x46\x56\xee\xc7\xb7\x97\x10\x5a\x8f\xaf\x12\x47\xf4\x3d\x00\x9b\xdc\x05\xe8\xcd\x7d\x2b\xfb\x75\x00\x1a\xa0\x7f\xeb\xab\xae\x90\x00\x75\x00\x43\x92\x79\x4b\xa0\x39\x1e\xfe\x42\x41\x3d\x00\x06\x04\x96\xe5\x20\x09\x75\x00\xff\x7c\xaf\x72\x2d\xf1\x46\x79\x93\x7a\xac\x01\x4f\x93\x30\x5a\x05\xdc\x52\x83\x75\x00\xe8\xfa\xe5\x0f\x1f\xda\x28\x00\x41\x00\xc5\x58\x3d\x00\x40\x0d\x3d\x00\xec\x72\x41\x00\xbc\x6d\x28\x00\x5d\x06\x43\x8e\x75\x00\x12\x85\x43\x55\xe4\x41\x3d\x00\xdb\x12\xb9\xa4\x75\x00\x63\xe7\x23\xf0\x90\x00\x65\xb8\xb7\xb5\x75\x00\x53\x4e\xe9\x56\x75\x00\x00\xa9\x85\x79\x52\xeb\xe0\x05\xdf\x52\xbb\x00\x11\x00\xe5\xd6\x15\x76\xfb\xd0\x90\x79\xa6\x6c\x75\x00\x75\x00\x2e\x93\xd9\xeb\x64\x42\xdb\x5c\x0b\x06\x9e\x41\x5f\x45\xbc\x08\x59\xf0\x2b\xe1\x83\x63\x04\x7b\x75\x00\x8a\x51\x2e\x91\x3d\x00\x2d\xd4\x36\x50\x67\x11\x77\x3c\xb1\xc1\x78\x31\x6f\xbf\xe7\x71\x11\x00\x08\xce\xa2\xc2\x08\x77\x6e\x1c\x75\x00\x80\x5c\xde\x7f\x75\x00\x52\x00\x26\xba\x3d\x00\x3d\xa3\x2c\xa3\x75\x00\x89\x3e\xba\x1f\x7a\x00\x11\x00\x9a\xde\xc8\x03\xfd\xbc\x5e\xf6\x8a\x0a\x75\x00\x75\x00\xb7\xcf\x70\x05\xa8\xfe\xe6\x06\xf5\x51\x41\x00\x75\x00\xac\x1f\x75\x00\x2e\xa6\x28\x00\x90\x00\xac\x73\x15\x99\x75\x00\xd9\x7a\xf1\x03\x3d\x02\x3d\x00\x1b\xf9\x3d\x00\x21\x6f\xc1\x7b\xee\xf8\xfe\x54\xfc\x5a\x3d\xef\xcd\x15\x0c\x03\xea\x45\xb2\x1e\xca\xb9\x34\x3a\xea\x46\x67\x6c\x57\x7a\x87\x0e\x75\x00\xd8\x69\x77\x8c\xe2\xb8\x75\x00\xc6\x80\x90\x00\xa9\x36\x75\x00\xc0\x59\x25\xeb\x8f\xe8\x3d\x00\x75\x00\xe5\xd2\x52\x00\xe6\xd2\xef\xcd\xe0\x45\x79\xe7\x9c\x31\xdb\x5e\x4b\x31\x83\xeb\xc8\x1e\x43\x14\xf8\xe4\x3d\x00\xbb\x03\x94\xf0\x98\x53\x0f\xed\xe4\x41\x3d\x00\xfe\xfb\x51\x54\x75\x00\x81\x30\xbb\xa6\x28\x00\xde\x6e\x41\x20\x81\x84\x75\x00\x51\x43\x38\xee\x01\x13\xb4\xf2\xf4\x9d\x9a\xa8\x22\x7a\xf7\x3b\xb9\xcd\x2d\x6e\x30\x8d\x54\x05\xaa\xbe\x5c\x1b\x55\x7d\x5c\x06\x75\x00\x87\xe7\x7a\x00\xa5\x5f\x2d\x54\x37\x97\xb5\xda\x75\x00\x90\x00\x7a\x00\xf8\x57\x3d\x00\xd2\x8b\x3d\x00\xe6\x01\x28\x00\x29\x07\x90\x00\x75\x00\xc6\x7e\xdc\x5e\xd6\x9d\x19\x87\x69\xe2\x98\x01\x28\x00\x17\xe3\x90\x00\x41\x00\xa8\x16\x7a\x00\x6f\x38\x75\x00\x75\x00\xf1\x88\x18\x48\x70\x59\x2c\x34\x79\x26\x76\xf0\xa2\xad\x3e\x3d\xfd\x62\x9e\xa8\xe5\xeb\x9f\x51\x8c\xfe\x7e\xdb\xbb\x83\xc1\xba\xbb\x39\xd2\xf6\x83\x27\x01\xee\xf5\xc7\x92\x2d\xd0\x5f\xf6\x26\x47\x19\x28\x00\x52\x00\x75\x00\x75\x00\x36\xa9\x88\xe7\x05\xba\xb2\x21\x47\x37\x36\xe6\x3e\x4e\x8a\x61\x80\x0a\x9d\xba\x5c\x67\x0f\x63\x84\x02\x40\xc6\x90\x00\x11\x00\x75\x00\x75\x00\xdd\x0f\x39\x82\x4e\x51\xf1\x2a\x54\x46\x75\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\xd4\x09\x90\x00\x90\x00\x11\x00\x41\x00\x11\x00\x52\x00\x28\x00\x28\x00\x51\x00\x00\x00\xa9\x00\x00\x00\x75\x00\x04\x88\x7d\x23\x17\x22\x33\x3d\x00\x1a\xfc\x3d\x00\x92\x0e\x0d\x7a\xe8\xfa\xe6\xee\x28\x00\x5a\xb8\x11\x00\x7a\x00\xdf\x29\x90\x00\x36\x46\x52\x00\x41\x00\x9d\xc3\xdf\xeb\x41\x00\x66\x04\x75\x00\x41\x00\x75\x00\xc0\x85\x3d\x00\xc7\x80\x8f\x09\x36\x48\x23\x73\xf9\x01\x28\x00\x75\x00\x41\x00\xb6\x17\x49\xb1\x3d\x00\x52\x00\x41\x00\xf8\x57\x3d\x00\x26\x60\x3d\x00\x70\x02\x11\x00\x8e\xa5\x28\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x16\x46\x90\x00\x28\x00\x52\x00\x7a\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\xa2\x00\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x35\x41\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x03\x97\x38\x75\x00\x90\x00\xf7\xbb\x3d\x00\xe3\xc7\x11\x00\x95\xe3\x84\x87\xbd\xf8\x75\x00\x75\x00\x7a\x00\x54\x1b\x7e\x01\xa8\x1f\x75\x00\x28\x00\x11\x00\xa1\x59\x3d\x00\x3d\xe1\xf0\x68\x43\x68\xee\xa2\x75\x00\x89\x2d\x23\x64\x76\x62\x75\x00\x69\xc1\x41\x00\xb8\xd8\x75\x00\x0d\x2b\x75\x00\x75\xce\x03\x76\x7a\x3c\x0c\x26\x02\x30\x7c\x00\x58\x66\x90\x00\x25\xc0\x54\x23\x75\x00\x48\x44\xf0\xed\x1b\x63\x7a\x00\x52\x00\x41\x00\x41\x00\x1b\xf4\x90\x00\x11\x00\x28\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x69\x01\x7a\x00\x75\x00\x55\x46\x7a\x00\x1b\xbc\x41\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x22\xa1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x49\x00\x00\x00\x75\x00\x80\xb0\x9c\x7a\x00\x52\x00\x41\x00\x41\x00\xf6\x19\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x0e\x07\x00\x80\x7a\x00\x52\x00\x41\x00\x41\x00\x2b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x07\x05\x1e\x77\xac\xe4\x90\x1d\x07\x1b\x62\x43\x3d\x00\x75\x00\xe9\x34\x90\x00\x84\xfe\x90\xd1\x11\x00\x00\xd7\x0a\x56\x11\x00\x97\x16\x75\x00\x11\x00\x75\x00\xae\xd7\xb1\x16\x60\x75\x3d\x00\x41\x04\x1d\x31\xd7\xe1\x95\x71\x28\xcc\xf2\x0a\x75\x00\x7a\x00\x7a\xba\x32\x26\xca\x1d\x75\x00\x4b\x2e\x13\x26\x3d\x00\xda\x49\xbc\x62\x47\x60\x3d\x00\x10\x16\x45\x99\x72\x7a\x54\x25\xdd\x67\x63\x75\xc4\xac\x6f\x6c\x11\x00\x3d\x00\xa6\xc8\x9c\x77\xb4\x9c\x9c\x90\xe6\x17\xf3\x74\x3d\x00\x75\x00\xb6\x8d\x7a\x00\x05\xa3\x5f\x37\x30\x32\xe4\x41\x3d\x00\xf8\xb0\xc7\xd7\x75\x00\x83\x5e\x58\x2b\x11\x00\x83\x12\x90\x00\x0a\x6d\xcd\x93\x75\x00\x20\xfd\x9a\x12\xa3\x12\xfa\xef\x11\x00\xde\x58\x74\xbc\xd3\xef\x28\x00\x75\x00\xbd\xec\x7d\x6e\x32\xa2\xd6\xf7\x75\x00\x9f\x98\xf7\xba\x9f\x61\x41\x00\x75\x00\xfa\x31\x28\x00\xd6\x53\x0c\xbc\x41\x00\xc8\x43\x75\x00\x11\x00\x75\x00\x3a\xa8\x75\x00\x6d\x51\x11\x00\x77\x1b\x75\x00\xb3\x9c\x83\x17\x93\x37\x3d\x00\x9a\x6f\xbd\x27\x62\x07\x05\x48\x75\x00\x1b\x67\x09\xf8\x58\x47\x28\x00\x90\x00\xc5\x58\x3d\x00\xf5\x63\x3d\x00\xf2\xe3\xe2\xd3\x3d\x00\xc0\x66\xa0\x78\xa3\x13\x21\x89\xb8\x6b\x33\x1c\xb7\xb8\x07\x46\x66\xce\xde\x67\xf6\x8a\x42\xf0\x29\x12\xee\x1d\x56\x55\x21\x81\x3d\x00\x66\x19\x75\x00\xa1\xe1\x90\x3b\xc5\xe6\x03\xa5\xab\x07\x9c\x02\x3d\x00\xd6\x47\x05\xdc\xc2\x83\x7a\x00\xc6\xf4\x11\x00\x3d\x00\x75\x00\x15\xbf\x90\x00\xb5\xd9\x23\xbe\x20\x4d\x28\x00\x3d\x00\x24\x23\x58\x61\xaa\xb0\x9a\xce\xed\x38\x75\x00\x41\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x41\x00\xf8\xba\x3d\x00\xdd\x87\xdc\x42\x3d\x00\xd7\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\x7b\x16\xfd\x2b\x3d\x00\x53\x5c\x75\x00\x41\x00\xc4\xba\x3d\x00\x7b\x16\x5b\x8a\x3d\x00\x7c\x5c\x75\x00\x7a\x00\x39\xb8\x3d\x00\xb1\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\x7b\x16\x93\x39\x3d\x00\x46\x5c\x75\x00\x7a\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x90\x00\xb7\xcc\x90\x00\x41\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x28\x00\x2e\xd2\x8f\x7a\x41\x01\x20\x00\x80\xce\x68\x00\x3d\x00\x51\x00\xac\x02\x41\x00\x11\x00\xd5\x58\x3d\x00\x34\xfb\x90\x00\x41\x00\x1e\x5b\x3d\x00\x0c\xfe\xed\xb3\x6b\xdb\x3d\x00\x38\x00\xf5\xd4\x3d\x00\x28\x00\x7a\x00\x1e\x5b\x3d\x00\xfa\xf5\x7c\xb4\x2f\xba\x3d\x00\x3d\x00\xcf\x01\x41\x00\xc1\x62\x90\x00\x3d\x00\xd7\x02\x28\x00\xc0\xc8\x28\x00\x74\x04\x75\x00\x90\x00\x3d\x00\x68\x76\x08\x3d\x00\x28\x00\xc6\x99\xfb\x45\x11\x00\x7d\xdb\x75\x00\x11\x00\x75\x00\x9b\x1c\x3d\x00\xc6\x55\xf8\x68\xb9\x2c\x7a\x00\xbe\xe6\x41\x00\x3d\x00\x6f\x34\xd8\xed\x59\xb1\x51\x8e\x42\x41\x3d\x00\x5e\x3c\xd6\xff\xd4\xd9\xc7\x5d\x56\x15\xd4\x09\xc8\xf3\x54\x50\x04\x0d\x69\xc8\x6a\x3a\x75\x00\x04\x78\x7a\x00\x28\x40\x50\x21\x38\x1c\x11\x44\x3d\x00\x57\x1f\xd9\x76\xa1\xb0\x0f\x92\x40\xe0\x7b\x08\xe8\xa3\x16\xce\x25\x38\x75\x00\x7a\x00\xc4\xba\x3d\x00\x86\x14\xea\xa3\x3d\x00\x6c\x17\x92\x29\x3d\x00\xd7\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\xba\x14\xbc\xe0\x3d\x00\xdf\x8a\x02\x42\x3d\x00\xba\x14\x48\xfc\x3d\x00\x82\xfd\x02\x42\x3d\x00\x7b\x16\xab\x67\x3d\x00\x1a\x5c\x75\x00\x41\x00\x39\xb8\x3d\x00\xf3\x00\x75\x00\x11\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x01\xa3\x90\x00\x41\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\x24\xbe\x9e\x7a\x41\x01\x20\x00\x80\x07\x0b\x00\x3d\x00\x51\x00\xac\x02\x52\x00\x52\x00\x1e\x5b\x3d\x00\x34\xfb\x33\xb4\x8d\xda\x3d\x00\xe6\x00\x8f\xd2\x3d\x00\x3d\x00\x91\xc1\x27\xde\xa5\x4d\xc8\x4c\x93\xd9\xa3\x5b\x02\x3c\xdb\x0b\x7a\x00\xa3\x6d\x62\x77\x3d\x00\x86\x93\x41\x00\x72\x34\x3d\x00\x3d\x00\x3b\xc3\xeb\xb6\xe5\xf1\x04\x7e\x21\x87\xa0\x63\xb2\xe1\x7f\x03\x52\x00\x3d\x00\xbb\x9c\x67\xfa\x00\xfe\x99\x51\xfa\x3a\x9b\x36\xc3\xcb\xe9\x70\x90\x00\x64\x8e\x75\x00\x28\x00\x3d\x00\x25\xff\x08\x3d\x00\x75\x00\x91\x39\x59\x18\x44\x8f\xf7\x7f\xd6\xfb\x9c\x02\x3d\x00\xc0\x53\x1f\xaf\x18\x0c\x75\x00\x54\x1a\x7a\x00\x75\x00\x74\x11\x7a\x00\x3d\x17\x3c\x19\x7c\x38\x75\x00\x7a\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x11\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x7a\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x90\x00\xc4\xba\x3d\x00\x7b\x16\x2a\x4c\x3d\x00\x4a\x5c\x75\x00\x52\x00\xf8\xba\x3d\x00\x00\xd5\x02\x42\x3d\x00\x86\x14\x58\x84\x3d\x00\xba\x14\x28\xd6\x3d\x00\x52\x65\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x06\x7d\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x9f\x63\xad\x7a\x41\x01\x20\x00\x80\xa2\x05\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x8d\x24\x3d\x00\xd9\x93\x90\x00\x82\xdf\x3d\x00\x3d\x00\x3c\x03\x7a\x00\x46\xd7\x7a\x00\xc7\xff\x90\x00\xc9\x1e\x3d\x00\x3d\x00\xac\x02\x28\x00\x97\x77\x7a\x00\x41\x00\x90\x00\xd5\x58\x3d\x00\x6a\xbe\x41\x00\x90\x00\xd5\x58\x3d\x00\xc5\x07\x7a\x00\x52\x00\x6f\x5a\x3d\x00\xc7\x0f\xac\xc8\x75\x00\x3d\x00\x17\x70\x08\x3d\x00\x3b\xf7\x97\xbb\x34\x74\xe9\x80\x41\x8b\x41\x00\xad\x74\x6b\x01\xdc\x42\x3d\x00\x9c\xde\x75\x00\x52\x00\x3d\x00\x75\x00\x3f\x38\x75\x00\x11\x00\xc4\xba\x3d\x00\x7b\x16\x68\x25\x3d\x00\x62\x5c\x75\x00\x52\x00\x39\xb8\x3d\x00\x1b\x00\x75\x00\x28\x00\xc4\xba\x3d\x00\x7b\x16\x2f\x45\x3d\x00\x2b\x5c\x75\x00\x52\x00\xf8\xba\x3d\x00\x0d\xc5\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xa1\x90\x00\x52\x00\x11\x00\x28\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x71\xbc\x24\x4f\x59\x00\x20\x00\x68\x7a\x77\x41\x01'

state.esp = 0x6F8A8
state.VMA = 0x10f0429c ##Where VM registers in mem
TVM.VMA = 0x10f0429c

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

state.reg4[TVM.R_EIP] = 0
state.reg4[TVM.R_31] = 0xFCB2A014
state.reg4[TVM.R_ImgBase] = 0x10000000 #imgBase


state.wMem(0x000A2EC0, b'\x0A\xB2\xAC\x0A')


state.wMem(0x10EFD721, b'\x4e\x67\x9b\xb8')
state.wMem(0x1103f789, b'\x08\x10\x43\x11') #0x11431008
state.wMem(0x11431008, b'\x0A\xB2\xAC\x0A')

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

state.OnEnd = FNC
#state.AddRoute(0x444, 0, False)

PARSED, ERR = TVM.Parse(state)
for k,v in sorted(PARSED.items()):
	for l in v:
		print(l)
		pass
	print()


for l in ERR:
	print(l)
	pass
