#!/usr/bin/python3

#10594b0b

import sys
import TVM

def FNC(state, log):
	eip = state.reg4[TVM.R_EIP]
	if eip == 0x115D:
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
		
		state.AddRoute(0x444, 0x141532c - 0x14141c5)
		log.append("#Jump to route {:02X}".format(0x141532c - 0x14141c5))
	elif eip == 0x1296:
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
		
		state.AddRoute(0x444, 0x1415465 - 0x14141c5)
		log.append("#Jump to route {:02X}".format(0x1415465 - 0x14141c5))
	elif eip == 0x139B:
		log.append("\n#FUN_1005a180     \n")

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
		
		state.AddRoute(0x444, 0x141556a - 0x14141c5)
		log.append("#Jump to route {:02X}".format(0x141556a - 0x14141c5))
	elif eip == 0x14A4:
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
		
		state.AddRoute(0x444, 0x1415673 - 0x14141c5)
		log.append("#Jump to route {:02X}".format(0x1415673 - 0x14141c5))
	elif eip == 0x15FD:
		log.append("\n#FUN_100b06c0     \n")

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
		
		state.AddRoute(0x444, 0x14157cc - 0x14141c5)
		log.append("#Jump to route {:02X}".format(0x14157cc - 0x14141c5))
	else:
		log.append("\n\n#OnEnd {:02X}\n\n".format(eip))


state = TVM.VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\x12\x02\x3d\x00\xc1\x74\x70\xff\x9d\xb3\x01\x65\x3a\x88\x41\x03\x77\xb1\xb9\x39\x52\x00\x3d\x00\xfd\x69\x68\x00\x3a\x26\x7e\x42\xb3\x40\x4f\x3e\x66\x89\x18\x3d\x90\x00\x3d\x00\xac\x02\x7a\x00\x59\x52\x7a\x00\x7a\x00\x41\x00\xd5\x58\x3d\x00\x01\xf4\x41\x00\x90\x00\x3b\x58\x3d\x00\x58\xad\x3d\x00\x4b\x93\x75\xf5\xab\x00\x5b\x2e\x13\x5d\xd8\x4b\x59\xaf\xe9\x0e\x11\x00\x3d\x00\xcf\x01\x90\x00\xf6\xad\x7a\x00\x3d\x00\x46\x04\x28\x00\x7d\xfa\x7a\x00\x66\x72\x75\x00\x3d\x00\x77\xce\x08\x3d\x00\x0e\x72\xdc\x42\x3d\x00\x12\xde\x75\x00\x41\x00\x3d\x00\x75\x00\x8f\xb6\x75\x00\x41\x00\x3d\x00\x90\x00\x77\xb1\x00\x00\x56\x91\x87\xf7\x10\x7c\xf8\x05\x7a\x00\x06\x04\x6b\x96\x75\x00\xec\xfc\x75\x00\x11\x00\x40\x97\x7a\xd7\x52\x00\x7a\x00\x8a\x59\x3d\x00\xf7\xdb\xa3\xc3\x75\x00\x7a\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x7a\x00\x56\xb9\x3d\x00\xc4\x56\x52\x00\x72\xb5\xec\x75\x00\x3d\x00\x44\x3c\x34\xdf\xf7\xa9\x4d\x68\xea\x7b\xac\x15\x2a\x7e\xf6\x49\x90\x00\xaf\x94\x6d\x4f\x00\x6c\xf9\x1b\x75\x00\x41\x00\x39\x44\x3c\xd5\xf8\x92\xf9\x4a\xfa\x39\x75\x00\x31\x70\x3d\x00\x51\x99\xab\xce\x00\x01\x0e\x1e\x91\x8c\x8c\x3f\xc4\x06\x0a\x61\x41\x00\x98\x16\x3a\xda\x3d\x00\x8b\xc1\x52\x81\x11\x00\x40\x88\x7a\x00\x11\x00\x7a\x00\xd6\x82\xec\x6a\x75\x00\x75\x00\x25\x7a\x00\x45\x52\x41\x00\x26\x6c\x12\xde\x75\x00\x28\x00\x3d\x00\x75\x00\x30\xaa\x75\x00\x90\x00\x3d\x00\x39\xdf\x75\x00\x7a\x00\x3d\x00\x75\x00\x75\x00\x11\x00\xb6\x54\xaf\x92\x28\x00\x5f\x38\xa0\x24\x75\x00\x90\x00\x3d\x00\x3d\x00\x39\x02\x90\x00\x80\xf8\x41\x00\xac\xfb\x3d\x00\x73\xeb\x69\x72\xbf\x0a\x6f\x8c\x30\x23\x2a\xd0\xbf\xc2\x75\x00\xa7\xd0\x72\x0c\x41\x00\x0e\x21\x58\x51\xd2\xc3\x75\x00\x6a\xe2\xc4\x1e\x11\x00\x04\x27\x72\x20\xfa\x4c\x3d\x00\xcc\xa6\x2e\xed\x74\x4f\xc7\x14\x56\x46\x3d\x00\x0b\xd5\x6f\xed\xb4\x22\x51\x39\x5a\xee\x7d\x2a\x82\x00\x2e\x40\x11\x00\x20\xbf\x52\x00\x90\x00\x3c\x4b\x52\x00\xb0\x61\x75\x00\x75\x00\x7f\xec\xee\x0e\xb5\x25\xbd\x1f\xe8\x89\x23\x47\x9c\x50\x37\xa4\xf4\x89\xbe\x4d\x31\x49\xe7\x49\x3d\x11\x04\xcd\x75\x00\x52\x00\x26\xb8\x3d\x00\xb0\x7f\xb2\xdf\x6a\xc2\x75\x00\x40\xff\xcf\x56\x11\x00\xd0\xb9\x56\x57\x0d\x33\x8a\x9e\x5e\x85\x57\xaf\x0c\xc9\x86\x10\xe0\x53\x1a\x36\x75\x00\x4f\x32\x7a\x00\x1a\x31\x28\x00\x90\x00\xcb\x7c\x41\x00\x62\xf5\x90\x00\x41\x00\xa5\xdf\xb3\xa5\x7a\x00\x8a\x21\x75\x00\x11\x00\x75\x00\x16\x3c\x3d\x00\x30\x9d\x52\x00\x52\x00\x25\x09\xdf\x27\x49\xed\x75\x00\x78\x4e\x7a\x00\x52\x00\x41\x00\x7a\x00\x2b\x01\x90\x00\x52\x00\x90\x00\x41\x00\x11\x00\x11\x00\x28\x00\x28\x00\x51\x00\x00\x00\xf6\x00\x00\x00\x75\x00\xa2\x84\x8f\x86\x14\xd5\xec\x3d\x00\xb5\x15\x69\x01\x3d\x00\x00\xae\x7a\x00\x04\xa0\x44\x8d\xa0\xb1\x75\x00\x5c\x5e\xf3\xe5\x75\x00\xb4\x7b\xd6\x49\x28\x00\x59\x4d\x39\x67\x0f\xb6\xa1\xb2\xb8\x74\x75\x00\x75\x00\x3d\x93\x48\x64\xe1\xcb\x25\x80\xb1\x9f\x37\x23\xb5\x2f\x06\x58\x72\xed\x16\x4d\x63\x9d\x86\x26\x5d\x75\x00\xe1\xbc\x28\x00\xcf\x56\x75\x00\xdc\x85\xeb\x8d\xa6\x78\xf5\xc4\x90\x00\x52\x00\x7a\x00\x11\x00\x7b\x9a\x2b\x32\xfb\x0f\xe0\xe6\x07\xdb\x51\x1e\xef\x05\x63\x3e\x11\xf7\x52\x00\xaa\x80\x82\x39\x41\x00\xa7\x38\x75\x00\x28\x00\x75\x00\xc5\x89\x24\x98\x68\x27\x6e\x1c\x90\x00\x7a\x00\x6c\x59\x3d\x00\x2c\x7c\x75\x00\x6f\x68\x7a\x00\x72\x7a\x75\x00\x4a\x15\x4d\x4d\x90\x00\x02\xe2\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\x48\x1f\x90\x00\x28\x00\x90\x00\x11\x00\x11\x00\x7a\x00\x28\x00\x41\x00\x51\x00\x00\x00\xe7\x02\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x6b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x6f\x03\x6b\xd3\xaa\x57\xc7\x5a\x4c\x34\x52\x00\x75\x00\x41\x00\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x3a\x19\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xeb\x00\x00\x00\x75\x00\xa2\x73\x77\xc7\x14\xc3\xea\x3d\x00\xba\x9b\xa5\xed\xcd\x22\x00\xa4\x31\x78\xbc\x81\x3d\x00\x86\x85\x28\x00\x71\xbe\x3d\x00\x75\x00\xd3\x62\x90\x00\x76\x52\x75\x00\xa1\xc0\x3d\x00\xa0\x01\x52\x00\x4f\x6c\x7a\x00\xb3\x53\xe4\x41\x3d\x00\xa5\x2b\x9c\x2c\x75\x00\x20\xf1\xa2\xd6\x41\x00\x72\xb8\xb8\x74\x74\x8c\x20\xab\xfb\xbb\xe0\xc4\x11\x00\x75\x00\x6c\xcc\x75\x00\x77\xa8\x28\x00\x7a\x00\x3d\x00\xa8\x54\xfb\xed\x13\x0f\x38\xc2\x75\x00\xd8\xd2\xcb\x42\x41\x00\x42\xa6\x82\x9a\x75\x00\x41\x00\x3d\x00\x76\x03\x11\x00\x40\xaa\x90\x00\x6e\x70\xd2\x63\xe8\x77\x74\x81\xda\x25\xf7\xec\xda\x26\x2f\xb7\xc5\x6d\xa1\x7a\x1d\x3a\x75\x00\x12\xa6\x7a\x00\xe7\xb6\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xda\x1e\x90\x00\x28\x00\x7a\x00\x52\x00\x11\x00\x90\x00\x28\x00\x11\x00\x51\x00\x00\x00\xd0\x01\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x1b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x9c\x01\x82\x14\x44\x64\x3d\x00\x28\x00\x26\x6f\x41\x00\x52\x00\x7b\xf2\x90\x00\x3a\x9d\x75\x00\x75\x00\xe4\x35\xbd\x90\x21\xdb\xd8\x67\x75\x00\xaf\xcc\x7f\x24\x75\x7c\x75\x00\x9f\x80\xfc\x96\xb7\x53\xc6\x15\x43\xde\x3d\x00\xa2\xef\xc8\xe7\xe7\x92\x4e\x7f\xfe\x53\x2e\xd8\xe1\x5c\xd1\x8b\x43\x56\x82\xd2\x6a\x5c\xd1\x71\x3d\x00\x59\x4b\x1a\x67\x84\x37\x3d\x00\x98\x01\x52\x00\x43\x08\x41\x00\x11\x00\x26\x83\x28\x00\x52\x00\xa8\xa4\x41\x00\xdd\x21\x75\x00\x75\x00\x1b\x9e\x0a\x49\x59\x5a\xe7\xd1\x21\x2f\x51\x36\xc8\xb7\x05\x74\x7a\x00\xe6\x18\x72\xc5\x3d\x00\x3d\x00\x9c\x02\x41\x00\x3d\xa9\x7a\x00\x3d\x00\xaf\xd9\x4d\x60\x6c\xa6\xa0\xc2\x75\x00\x46\x52\xc8\x3c\x11\x00\x5b\x0e\x75\x00\x41\x00\x4b\xb9\x3d\x00\x32\xce\xcd\xd8\xf3\xad\x3d\x00\x3d\x00\xfc\x02\x28\x00\xe3\x14\x28\x00\x75\x00\xad\x40\x90\x00\x54\x66\xe0\x0e\xd3\xe4\x8c\x0b\x7d\x5b\xcd\xa6\x9a\x7f\x28\xef\xb2\x59\x12\xe9\x73\xe3\x75\x00\x2e\x7e\xf6\x81\xc8\x80\x41\x00\x75\x00\x7a\x00\x06\x8d\x11\x00\x28\x00\xd4\x20\x11\x00\x7f\x36\x75\x00\x75\x00\x90\x3b\xc7\xcb\x81\x46\x00\x07\x87\x70\xaf\xeb\xd8\xca\x78\x57\x93\xad\xcf\x2b\xce\xab\x75\x00\x52\x00\x75\x00\x43\x53\x52\x00\x7e\x51\x93\x53\xf0\xc2\xcf\x2e\x16\xc7\x29\x05\x9b\xd3\x19\x2d\xcc\x51\xc3\x6a\x75\x00\x30\x8b\xce\x46\x89\x28\xb9\xd1\x28\x00\x52\x00\x30\x5b\x3d\x00\xf5\x28\x74\x73\x0e\xe2\x3a\x26\xf3\x99\xd8\x8c\x81\x94\x3d\x00\x76\x23\x8e\xee\xa9\x07\x75\x00\xbb\xe0\x90\x00\xac\xf8\x06\xff\x55\xf1\x46\xa8\xd1\xa0\xeb\xfd\x90\x00\x28\x00\x75\x00\x00\x00\xde\x47\xbb\xc7\x1e\x22\x52\x00\x11\x00\x75\x00\x83\xb3\xcc\x4d\x09\x92\x3d\x00\x9c\x02\x90\x00\xff\x79\x90\x00\x3d\x00\x7f\xe9\x7a\x00\x52\x00\x41\x00\x52\x00\x46\x8e\x90\x00\x11\x00\x90\x00\x41\x00\x11\x00\x7a\x00\x28\x00\x28\x00\xa6\x03\x0a\x6a\x28\x80\x00\x00\xeb\x9e\xb0\x01\x7b\x5e\x1b\x62\x3f\xff\x67\x70\xd9\x58\x64\x27\xd1\x1f\x38\x58\xf8\xc3\x75\x00\xe2\x31\x38\x5b\x7a\x00\x3b\xd3\x3d\x00\xe4\x36\x75\x78\x61\xa9\xb7\x50\x18\xc6\x10\xef\x72\x9c\xbd\xbd\x44\x74\x8a\xc1\x75\x00\xa6\xdd\x4a\x26\x28\x00\x3d\x00\xa7\xb0\xd5\x66\xa5\x14\x28\x00\x75\x00\x0e\x40\x52\x00\x89\x16\x52\x00\x28\x00\xec\x01\x90\x00\x2e\x69\x52\x00\xe2\x2d\x50\xf6\x08\x06\x11\x37\x75\x00\x3d\x00\x89\x5b\x28\x00\x68\x5a\x0c\xef\x11\x00\x3f\x95\x75\x00\x28\x00\x75\x00\xbf\xf8\x3d\x00\x9e\x11\x36\xf6\x0d\xc9\x03\xbd\x52\xfb\x51\x48\x1c\x3b\xac\xe5\x3c\x57\x37\xf0\x47\xcd\x56\xbe\x28\x00\xbc\x9b\x11\x00\x90\x00\x2a\x59\x11\x00\xe3\xe3\x7a\x00\xe3\x87\x75\x00\x41\x00\xf3\xb8\x3d\x00\xf2\x9a\x68\x70\x1c\x2d\xcf\x30\xef\xb4\x18\xc2\x75\x00\xb8\x0e\x41\x00\x7f\x58\xe4\x2d\x7a\x00\xb7\x2f\x52\x00\x90\x00\x78\x82\x90\x00\x80\xee\x90\x00\xe6\x17\xff\xea\x3d\x00\x75\x00\x64\x51\x7a\x00\x1d\xa8\xc7\xd7\xe8\xad\xbc\x0f\x17\x44\x5e\xb2\xf5\xcf\x64\x58\xa3\x6f\xa7\xe1\xd4\x96\x52\xb7\xd9\x45\x9d\x09\x28\x00\x52\x00\x75\x00\x4f\x23\xd0\x43\x56\x03\x52\x00\x11\x00\xc5\x58\x3d\x00\xa5\x2b\x3d\x00\xc7\x9e\x75\x00\x8a\x82\xe8\x0c\x06\xa9\x52\x00\x11\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xfa\x1b\x90\x00\x52\x00\x11\x00\x28\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x51\x00\x00\x00\xc7\x02\x00\x00\x75\x00\x80\x87\x76\x7a\x00\x52\x00\x41\x00\x41\x00\xdb\x1a\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x03\x2e\x38\x75\x00\x52\x00\xa4\xb9\x3d\x00\x75\x00\xaf\x1b\x11\x00\xcc\x53\x6f\xe0\x55\xf1\x06\xcd\xc8\xee\x2a\x35\x52\x00\x90\x00\x75\x00\xeb\x4e\xdd\x3e\x52\x00\x75\x00\xf1\xbf\x75\x00\x09\xaa\x28\x00\x11\x00\x2f\x47\xb4\x1d\x72\x27\x5e\x4d\x11\x00\x05\x4d\x3d\x00\x3d\x00\x1b\x53\xfc\x13\x10\xef\x14\x3f\xbb\x17\xa6\x0e\xd5\xc1\x75\x00\xeb\x82\xc1\x41\x7a\x00\x94\x52\x3d\x00\xd9\xc9\x52\x30\x36\x4f\x3d\x00\x9c\x01\x28\x00\xf2\x48\x41\x00\x82\x14\xe0\x19\x3d\x00\x41\x00\x18\x20\x7a\x00\x7a\x00\x77\x27\x7a\x00\x78\x19\x75\x00\x75\x00\xa3\x53\xe5\x0c\xc1\x15\xb0\xf3\x57\x14\x1b\xed\x52\x2c\x93\xb9\x98\xe7\x59\xaf\xbf\xff\xbc\xca\x75\x00\x40\x98\xe4\xc0\x88\xe5\x3d\x00\x9c\x02\x28\x00\x25\xeb\x7a\x00\x3d\x00\x2b\xd0\xdf\x3e\x3a\xdf\xc5\x66\x54\x5c\x11\x00\x52\x00\x75\x00\xd9\x83\x77\x7f\xb2\x69\x59\x97\x75\x00\xbe\xab\xe5\x7f\x75\x00\x52\x00\xf7\xbb\x3d\x00\xde\x87\x7a\x00\x86\xf5\xf7\xc0\x8c\x09\x75\x00\x41\x00\x26\xe3\x57\x6b\x28\x00\x60\x33\x75\x00\x28\x00\x75\x00\x5e\x02\x72\x6c\x69\xed\x75\x00\x54\x5c\x61\x92\xe4\x70\xde\x3a\x75\x00\xb2\xdf\x2e\xf6\xfa\x1e\x27\xdd\x11\x00\xff\x2a\x3d\x00\x31\x30\xfe\x48\x75\x00\xd4\xce\x75\x00\x52\x00\x64\x14\xba\x96\x3d\x00\x77\x89\x34\x05\x75\x00\xfe\xb3\xb5\xa6\x7a\x00\xaa\xe6\x65\x00\xd8\x64\xf0\xac\x4a\x7d\x11\x00\x52\x00\xfd\x0e\x75\x00\xb5\x15\xc1\x45\x3d\x00\xae\xf2\x28\x00\xdf\x93\x23\xb2\xc9\x15\x75\x00\xe6\xbb\x6e\xbe\x5d\x4f\x93\x10\x74\x1b\x91\xe6\x48\x0b\x54\x09\x75\x00\xc3\x4f\xec\xb0\x75\x00\x0e\xbd\x7a\x00\x3d\x00\x7c\x00\x52\x00\x0a\x53\x28\x00\xf0\xaa\x41\x00\x94\x33\xac\x7a\x75\x00\x0f\x07\xc2\x67\xfa\x0a\xc9\xa9\x8a\xa7\x45\xf4\xa3\xd3\x15\x73\xb3\xaa\x39\xfa\x5d\x52\xd3\xd8\x04\x04\xaf\xeb\xa4\x0b\x3d\x27\xdf\x2a\xd3\xa7\xfe\x65\x75\x00\x7a\x00\x3d\x00\xa0\x01\x7a\x00\x49\x96\x11\x00\x64\x44\xe4\x43\x3d\x00\xd4\xa4\x2b\x1d\xc4\xc2\x75\x00\x8d\x09\x41\x63\x90\x00\xe5\x8d\xbe\x84\x92\x63\x45\x29\x92\x56\x18\x35\xfb\xfd\xc7\x57\xb8\x2c\x75\x00\xcd\x36\x00\x00\x0e\xb3\xfc\xff\x75\x00\x44\xf2\x75\x00\x7a\x00\xc0\xba\x3d\x00\x11\x00\xe9\xc5\x52\x00\x90\x00\x1a\x43\x7a\x00\x9a\xa4\x75\x00\x75\x00\xd9\x3a\x6e\x00\xa8\xea\x9b\xd7\xa4\xdf\x84\x29\x59\x58\x21\x08\x3d\x00\xfc\x4d\xff\x25\xa8\x2b\x11\x00\x75\x00\x1d\x9c\x3d\x00\x05\x03\x41\x00\xec\x7d\x52\x00\x37\xd8\x96\x7a\xb7\xc4\x71\x27\x0f\x28\x93\xb0\x8d\x34\x43\xf3\x16\xbc\x22\xa3\x66\x05\xc4\xdb\x7d\x63\x52\x00\xaf\x8c\x3d\x00\x7a\x00\x49\x2a\x28\x00\x7a\x00\xc5\x58\x3d\x00\x0f\x71\x3d\x00\xd0\x57\x7a\x00\x52\x00\x41\x00\x90\x00\x6c\x1c\x90\x00\x28\x00\x7a\x00\x41\x00\x11\x00\x11\x00\x28\x00\x52\x00\x51\x00\x00\x00\x7c\x05\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x95\x1c\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa6\x03\x0a\x6a\xea\x7f\x00\x00\x61\xe8\x7c\x9a\xa9\x60\x65\x54\xd5\x2c\x37\xf0\xe7\xe8\xf6\x8f\x7a\x00\x0e\xee\x90\x00\x41\x00\xe7\xdb\x90\x00\xe3\x4e\x11\x00\x41\x15\x17\x56\xce\xbf\x3e\xb6\x6a\x25\x1b\x59\x0e\x5f\x76\x65\x93\x31\x3e\x39\x04\xa1\x52\x00\x75\x00\x11\x00\x41\x00\x2e\xd6\x00\x35\x75\x00\xe2\x67\x11\x00\xaf\xff\x32\x26\x75\x00\x00\xd6\x28\x00\x64\x15\x78\x78\x8f\xa3\x08\x57\xdf\x05\x02\x4a\xd4\x27\x01\xee\xd6\x80\x59\xc8\x90\x60\xb7\x68\x7c\x28\x52\x00\x41\x00\x75\x00\x75\x00\x7b\x16\x44\x3a\x3d\x00\x96\x5b\x75\x00\x41\x00\x26\xba\x3d\x00\x3e\xcf\x72\x8e\x75\x00\x91\xf5\x4d\x60\x11\x00\xf9\x34\x97\xaa\xb4\x28\x94\x5f\x5e\x0c\x5d\x17\xa5\xc1\x66\xf2\xe1\x00\x1e\xd4\x6b\xb4\x35\x13\x75\x00\x51\x51\x4d\x94\x0d\xae\x11\x00\x75\x00\xf7\x1b\xdf\x9b\x96\xe2\x3f\xcf\xc7\x14\x49\x8f\xa5\x98\x66\xa6\x58\x35\x62\xa8\x30\x34\x75\x00\x7b\x1f\x5d\xb8\xfb\x5a\x07\x2d\xc6\xe6\xcb\x99\x07\xa8\x2e\x69\x4e\x7f\xc1\x93\x61\x63\x11\xee\xb0\x9e\xdd\x38\x75\x00\x05\x2a\x61\xdf\xe1\x5e\xfb\x88\x3d\x00\x3c\x03\x28\x00\xcc\x3f\x52\x00\xac\xff\x41\x00\xa5\x3d\x3d\x00\x5e\x22\xef\x7c\x00\xb0\x75\x00\x30\x4c\xec\xb0\x8a\x0e\x2b\xfd\xdd\xed\x55\x53\xc0\x1d\xba\xef\xd4\x1b\x2a\x0a\x5d\x1e\xba\xeb\x41\xa4\x65\xcf\x3d\x00\xa0\x77\x0c\xb8\xf7\x44\x41\x00\x75\x00\x26\xc4\x8f\x77\xa2\x26\x0c\x19\xf0\x1e\x42\x41\x3d\x00\x4e\x6e\xc4\xff\x50\x0e\x73\x08\xf0\x49\xd2\xca\xd5\x17\x8d\x12\x6b\x38\x7a\x1c\x09\xd7\xfe\x96\x68\x3e\x70\xac\x9e\xd8\x28\x00\x11\x00\x75\x00\x33\x9a\xc4\x36\x2f\x7c\x11\x77\x13\x62\x3d\x00\x3d\x00\x53\xf4\xb1\x16\xde\xbd\x3d\x00\xcf\x14\x4b\x23\xee\xcd\x79\x87\xab\x84\x59\x03\x58\x1f\x41\x13\x7b\xc8\x7e\xb0\x7b\x65\xfd\x1f\x90\x00\x75\x00\x7a\x00\x56\xa7\xe4\x41\x3d\x00\x36\xdc\x0a\xf3\x75\x00\x34\x1f\x9a\x06\x52\x00\x75\x00\x9a\x0c\x90\x00\x94\x68\x75\x00\x36\x30\x0e\x4d\x52\x00\xd0\xfb\x3d\x00\x58\xf9\x93\xa6\x75\x00\xe0\x5a\x3d\x00\x19\x80\xcf\x57\x34\x8e\x2f\x2c\x99\x21\xe8\x1e\xf1\x6f\x0c\x76\x41\x00\xb1\xb9\x75\x00\xa2\xa6\x74\x81\x75\x00\x9f\x7c\xeb\x0c\x8b\xdf\x6b\x75\x39\x8e\xa0\x01\x48\x7d\xe4\x41\x3d\x00\x31\x32\x0d\x15\x75\x00\x4a\xe8\x41\xd3\x52\x00\x21\x9d\xfb\x06\x55\xe3\x11\x9b\xad\x50\xd7\x65\xc3\x07\xab\x0b\xb5\xc7\x9a\xb8\x75\x00\xb5\x15\x4e\xfc\x3d\x00\x0e\x95\x41\x00\xcc\xe4\x86\xf5\xbd\xb2\x75\x00\x75\x00\xae\xaa\x7e\x16\x6b\xb3\x30\xbb\x8b\x75\xe6\x03\x75\x00\x28\x00\x3c\xdb\xea\x24\x82\x22\x75\x00\x05\x53\x52\x00\x94\xfc\x42\x8f\x75\x00\x60\x3c\x44\xec\x12\x2b\x3d\x00\x9b\x02\x11\x00\x6d\x15\x11\x00\x0d\xc5\xcd\xb9\xb4\x70\x4a\xc7\x75\x00\xa0\xe0\x44\x0a\x11\x00\xb2\xba\x3d\x00\x41\x00\x02\x62\x28\x00\x7a\x00\x3d\xce\x90\x00\xcf\xed\x75\x00\x75\x00\xe5\xbe\xb9\x07\x2f\x3d\x97\x98\x21\x2c\xba\xeb\x88\x8f\xb3\x11\x3d\x00\x5c\x6c\x6c\x0a\x9b\x6d\x41\x00\x75\x00\x9e\x63\x37\x79\x11\x00\x48\x8a\x67\xc4\x67\x21\x75\x00\x11\x00\x28\x00\x52\x00\x41\x00\x75\x00\xc4\x09\xd7\xea\xeb\x56\x75\x00\x19\x3f\x50\x0b\xac\x1d\x4a\x25\x55\x8c\x9c\x02\x3d\x00\x97\x84\xef\x47\x11\x44\x3d\x00\xbb\x73\xc3\x1d\x1a\xd1\xd1\xbf\x7b\xa3\x61\x07\xcf\x07\x8c\x0a\x52\x4c\xd3\x04\x75\x00\xbd\x3b\x75\x00\x38\x38\xd8\x10\x02\x02\x90\x00\xcb\x44\x69\xfb\x75\x00\xad\x12\xaf\x36\xee\x15\x75\x00\x11\x00\x7a\x00\x24\xa7\x73\x49\xa7\x6c\xc3\x45\x7f\x96\x11\x00\x28\x00\x4d\xbd\x59\xcf\x75\x00\xa5\x82\x7a\x00\x3d\x00\x05\x03\x41\x00\x22\xd9\x90\x00\xbc\x3a\xe0\xa7\x49\xf3\xbf\x86\x3b\x24\xd3\xf3\xd9\x59\xdf\x96\xb3\xc3\x79\x3f\x03\x17\x5f\x4a\xb3\x24\x69\x88\x5f\xd1\x0e\x07\x81\xb3\x01\x21\x75\x00\x82\xf6\x28\x00\xb4\x45\x85\x63\xde\xe4\xf0\x4e\xbe\x06\x66\xf5\xca\xad\x7b\x0a\xff\x14\x16\x14\xf7\x37\x75\x00\xe6\x64\xf8\xda\x7a\x00\x82\xe6\x7a\x00\x28\x00\x1d\xe0\x7a\x00\x82\xf0\x75\x00\x75\x00\xa8\x19\x93\x1c\xb0\xde\x89\xd4\xa4\xaa\xa5\x79\xa2\xb1\xb0\xa7\x18\x43\xc8\x44\xc1\xcc\x90\x00\x28\x46\xc6\x48\x11\x00\x75\x00\xfe\x1a\x7a\x00\x52\x00\x41\x00\x7a\x00\xda\x17\x90\x00\x90\x00\x28\x00\x52\x00\x11\x00\x11\x00\x28\x00\x41\x00\x51\x00\x00\x00\xa7\x00\x00\x00\x75\x00\x04\xd3\x81\xb1\x16\x20\xf1\x3d\x00\xd5\x1e\xf7\x44\x85\x49\x37\x0e\xa2\x64\xe8\x81\x75\x00\xb4\x90\x7a\x00\xad\x49\xc3\xcd\x30\x85\xbd\x56\x3d\x00\x87\x7c\x6d\x7c\xf7\x97\xec\x37\x0f\x46\x0d\x88\xa7\xc6\x90\x00\x28\x00\x11\x00\x7a\x00\x8f\x32\x75\x00\xc4\x7d\x8c\x67\x6b\x79\x2c\xd9\xa2\x29\xbb\x00\x90\x00\xe6\x65\xab\x5e\xad\x14\x9b\xc6\x7a\x3b\x75\x00\x75\x00\x69\x07\xc5\x2f\x22\x3e\x7a\x00\x52\x00\x41\x00\x41\x00\xdd\x75\x90\x00\x90\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x28\x00\x51\x00\x00\x00\x9a\x00\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x24\x75\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x9c\x01\x64\x14\x3c\x64\x3d\x00\xb1\xa8\x2d\xbe\x75\x00\xda\xf9\xfe\xb0\x52\x00\x75\x00\x41\x00\x53\x1b\x80\x19\xde\x1d\x75\x00\x23\x56\xe4\x23\x3d\x00\x75\x00\xe5\x3f\x00\x13\xc7\x49\x45\x77\x3e\xea\x8b\x02\x0d\x9b\x35\x64\x28\x00\x7a\x00\x43\x1b\x90\x00\x20\x5c\x52\x00\x1d\xf3\x56\x12\x75\x00\x55\x01\x5d\xa7\x24\x9b\x52\x00\x75\x00\x58\x21\x75\x00\x4b\xa8\x28\x00\x7a\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\x23\x90\x00\x52\x00\x11\x00\x28\x00\x11\x00\x90\x00\x28\x00\x7a\x00\x87\x02\x38\x58\x75\x00\x8b\x3f\xf2\x2b\xfe\xf9\xf1\x96\x7a\x00\x52\x00\x41\x00\x41\x00\x85\x24\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x49\x00\x00\x00\x75\x00\x80\x64\x7e\x7a\x00\x52\x00\x41\x00\x41\x00\x59\x25\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xd8\x07\x00\x80\x7a\x00\x52\x00\x41\x00\x41\x00\xa0\x25\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xc8\x04\x11\x00\x43\x15\x90\x00\x90\x00\x45\x55\x90\x00\xab\x11\x11\x00\xc6\x15\xbf\xf7\x3d\x00\xf8\x45\xf9\x1e\xdb\x21\x41\x00\xe2\xa0\x40\xe0\x41\x00\xae\xe2\x75\x00\x11\x00\x75\x00\x2f\x76\xa1\xc0\x75\x00\x41\x00\xf7\xbb\x3d\x00\x23\x49\x28\x00\xc4\x6e\x80\x7e\x8e\x11\x75\x00\x44\x4c\x5d\xce\xdd\xb7\x29\x06\x7a\x00\x90\x00\x75\x00\x72\xdb\x90\x00\x51\x64\x75\x00\x85\x16\xfc\xd2\xc2\xb3\x3d\x00\x34\xdf\x17\x6a\xc7\xbe\x3d\x00\x7f\xb1\xcf\x0b\x6c\xcb\xd1\x2a\x12\xb2\x08\x09\x00\xab\x8e\x65\x41\x00\x3d\x00\x8b\x28\x3d\x00\x1a\xdc\x61\x27\x77\x4d\x11\x00\x75\x00\x2e\xc9\x7a\x00\xcf\xd0\x28\x00\x41\x00\x7a\xe3\x90\x00\x6f\x49\x52\x00\xd5\x31\xc1\xc8\xbb\xb1\xdd\xb6\x28\x00\x52\x00\x75\x00\x3d\x00\x0b\x19\xf8\x75\xa3\x1f\xe2\xd8\x4a\x47\x75\x00\x3d\x00\xfd\x10\x3d\x00\xf0\xc3\xdf\xd4\xbf\x50\x52\x00\x75\x00\xf7\xe1\x8e\x25\x27\x44\x3d\x00\x9e\x9a\x62\x43\x3d\x00\x75\x00\xd2\xd4\x11\x00\x3f\x9e\xe1\xaf\xa8\x55\x72\x27\x7a\x09\xc5\xad\xf7\xf6\xd9\x51\xf4\x5a\xf7\xc3\x75\x00\x42\xa7\x36\x26\xd2\xfd\x77\x53\x3b\x4b\x2e\x04\x86\xc1\xd5\x05\xfc\x9f\x3d\x00\x9c\x02\x41\x00\xc1\xef\x52\x00\x3d\x00\xac\xf6\x16\x2a\xea\x8b\x90\x00\x6a\x43\x41\x00\x3d\x00\x7a\x00\xf1\x64\x90\x00\x11\x00\x41\x3d\x7a\x00\xde\x1e\x75\x00\x75\x00\x34\x1f\x62\xa7\x55\x42\x68\x03\x34\x19\x15\xef\xb0\xa9\xdf\x14\xb4\x23\xe4\xbb\x66\x39\x9f\xc4\x06\x42\x3d\x00\x10\xc4\x02\x42\x3d\x00\x7b\x16\x5c\xea\x3d\x00\xff\x5c\x75\x00\x90\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\x89\x70\x06\x42\x3d\x00\xe5\x38\xc7\x43\x3d\x00\x47\x38\x75\x00\x52\x00\x39\xb8\x3d\x00\x31\x00\x75\x00\x90\x00\xc4\xba\x3d\x00\x7b\x16\x51\x17\x3d\x00\x6a\x5c\x75\x00\x11\x00\xf8\xba\x3d\x00\x18\x59\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\x08\x29\x90\x00\x11\x00\x90\x00\x41\x00\x11\x00\x28\x00\x28\x00\x7a\x00\x0f\x35\xa9\x58\x41\x01\x20\x00\x80\xce\x68\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\x8a\xb0\x70\xff\x7c\x4f\xea\x0b\xb1\x61\x76\x58\xf7\x74\xda\x72\x28\x00\x97\x6d\xfb\x44\x3d\x00\x3d\x00\xcf\x01\x52\x00\x5a\xa4\x11\x00\x3d\x00\x3c\x03\x11\x00\x6b\xec\x28\x00\xff\xff\x52\x00\xb9\x24\x3d\x00\x6d\xf4\x0b\x6e\x3d\x00\x3d\x00\xf5\x04\x11\x00\x3d\xb9\x28\x00\x67\xee\xfa\xd7\x3d\x00\xb9\x5d\x75\x00\x11\x00\x3d\x00\xa5\x2f\x08\x3d\x00\x90\x00\xb5\xc8\xfb\x45\x90\x00\x2a\x82\x75\x00\x28\x00\x75\x00\x1a\x54\x3d\x00\x1c\xfd\x3a\xf9\x3d\x00\xda\xc3\x0a\x02\xa4\x54\xc3\x2d\x41\x00\xab\x92\x41\x00\x41\x00\x4e\x54\x28\x00\x80\x0e\x75\x00\x75\x00\x30\x17\x4d\x4e\x10\xca\xf4\xc1\x77\xb8\x9f\x35\xf5\xd6\x6f\xdb\x75\x00\xbe\x76\x90\x00\x00\x6d\x33\x92\x3f\x38\x75\x00\x11\x00\xf8\xba\x3d\x00\xf9\xa8\xe4\x41\x3d\x00\x61\xcc\xa1\xf0\x75\x00\x49\x06\xe6\x91\x41\x00\x94\x21\x24\x7f\xbe\x29\x02\x42\x3d\x00\x86\x14\x58\x72\x3d\x00\x6c\x17\x3e\x64\x3d\x00\xdb\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x88\xbe\x06\x42\x3d\x00\x07\x7c\x06\x42\x3d\x00\x97\x7b\x02\x42\x3d\x00\xba\x14\x06\xa4\x3d\x00\x63\x65\x02\x42\x3d\x00\xba\x14\x85\x38\x3d\x00\x07\x01\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xe1\x90\x00\x28\x00\x52\x00\x7a\x00\x11\x00\x11\x00\x28\x00\x90\x00\x8d\xfc\xb8\x58\x41\x01\x20\x00\x80\x07\x0b\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x28\x00\xf2\xbd\x3d\x00\x28\x00\x11\x00\xd5\x58\x3d\x00\x7b\xb6\x11\x00\x11\x00\xd5\x58\x3d\x00\xe7\xfd\x41\x00\x11\x00\x1e\x5b\x3d\x00\xcc\xfe\x07\xb4\x18\xd9\x3d\x00\xd6\x93\x41\x00\xda\x94\x3d\x00\x28\x00\x41\x00\x65\x59\x3d\x00\x59\x1c\xe9\xb6\x11\x00\x58\xbc\x3d\x00\xee\xcc\x75\x00\x3d\x00\x18\x72\x08\x3d\x00\x11\x00\x56\xa8\xc9\xc5\x7a\x00\xf1\xdf\x75\x00\x41\x00\x75\x00\x78\x27\x3d\x00\x46\x5a\xe6\x17\xd8\xc7\x3d\x00\x75\x00\x29\x6a\x52\x00\x7c\x30\x20\xfd\x6a\x86\x27\x7f\x43\x4b\x55\x75\xf4\xba\x1f\x3c\x62\xb8\x16\xbc\x69\x7b\x93\x1a\x78\x2b\xbb\xcf\xef\x1b\x7b\x16\x8b\x8c\x3d\x00\x5d\x5c\x75\x00\x52\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x11\x00\x3d\x00\x75\x00\x2c\x78\x02\x42\x3d\x00\x86\x14\xa9\x22\x3d\x00\xba\x14\x82\x72\x3d\x00\x2a\xe0\xc7\x43\x3d\x00\x8e\x38\x75\x00\x7a\x00\xc4\xba\x3d\x00\x86\x14\xf5\x44\x3d\x00\x6a\x17\xc6\x66\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x47\x71\x90\x00\x28\x00\x41\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\x40\x6d\xc7\x58\x41\x01\x20\x00\x80\xa1\x05\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\xf8\x8d\x70\xff\xad\xb3\xd2\x2e\x95\xfb\x33\x0d\x33\x65\xf9\x0a\x11\x00\x3d\x00\x85\x6d\x68\x00\x36\xb8\x2f\x7f\x02\xc7\x56\x7c\xda\x74\x62\x45\x52\x00\x3d\x00\xcc\x0a\xa6\xff\x72\x37\x7f\x2a\x50\x51\x98\x0c\x4a\x1f\x04\x02\x41\x00\xdb\x6c\xb5\xbb\x3d\x00\x3d\x00\xf5\x04\x41\x00\x00\x65\x90\x00\x9f\x24\x3e\x24\x3d\x00\x3d\x00\x26\xde\x88\x99\x8c\x42\x3b\x35\xa2\x6b\xec\x22\xeb\x76\x54\x47\x11\x00\x7a\x00\x90\x00\x6f\x5a\x3d\x00\x63\xf8\x0b\x73\x75\x00\x3d\x00\xa2\xcd\x08\x3d\x00\xd8\x42\x11\x00\x3d\x00\x00\x85\xc3\x0c\x76\xbb\x45\x71\x18\xc3\x75\x00\x28\x00\xf8\xba\x3d\x00\x9f\x6c\x06\x42\x3d\x00\xb6\x3c\x06\x42\x3d\x00\x9f\x3c\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x7a\x00\x3d\x00\x75\x00\xe7\x0b\x06\x42\x3d\x00\xa6\x0b\x06\x42\x3d\x00\xd7\xff\x02\x42\x3d\x00\x7b\x16\xdd\xa3\x3d\x00\xcd\x5c\x75\x00\x11\x00\xc4\xba\x3d\x00\xba\x14\x39\x2f\x3d\x00\x62\x35\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x45\xed\x90\x00\x28\x00\x11\x00\x90\x00\x11\x00\x52\x00\x28\x00\x41\x00\x42\xf1\xd6\x58\x41\x01\x20\x00\x80\xce\x68\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\x12\x02\x41\x00\x0f\x4d\x41\x00\x3d\x00\x8e\xd4\xc9\xb2\x01\xec\x85\x53\xfa\xa6\x5c\x68\xf3\xbb\xbf\x63\x41\x00\xf4\x4d\x28\x00\xd6\x09\x3d\x00\x3d\x00\xac\x02\x7a\x00\x72\x2a\x28\x00\x11\x00\x11\x00\x65\x59\x3d\x00\xcd\xf9\x93\xb6\x90\x00\x1c\xb3\x3d\x00\x3d\x00\x96\xcb\xa1\xf0\x69\xa3\x0b\x4d\x0e\x4e\x5e\x41\x7e\x62\x76\x59\x28\x00\x1d\x4d\x52\x00\xde\x0e\x3d\x00\xa4\x77\x75\x00\x28\x00\x3d\x00\x52\x18\x08\x3d\x00\x43\xa4\x0d\x7b\x22\x9e\xa5\x51\x41\x00\x90\x00\x75\x00\x3d\x00\x87\xce\x9c\xc1\x41\x00\x3d\x00\xad\x75\x9b\x35\x26\xec\x85\x1d\xbc\x32\x62\x43\x3d\x00\x75\x00\xdd\xe1\x90\x00\xd6\xa2\x51\xf9\x7e\x22\x32\x5b\x1a\x09\x00\x86\xca\x0b\x07\xed\x2c\xbc\x80\x6c\x28\x00\x19\xfb\x11\x00\x90\x00\xc6\x6e\x7a\x00\xa3\xae\x75\x00\x75\x00\x60\x39\x11\x44\x3d\x00\x58\xf1\x40\x00\x89\x47\xe5\x3f\xeb\x2b\xfd\x08\x04\xcb\x57\xcd\xab\xdb\x06\x42\x3d\x00\x9e\xdb\xc7\x43\x3d\x00\x3f\x38\x75\x00\x90\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x90\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x28\x00\xf8\xba\x3d\x00\xb7\x69\xc7\x43\x3d\x00\x85\x38\x75\x00\x11\x00\x39\xb8\x3d\x00\x32\x00\x75\x00\x11\x00\xf8\xba\x3d\x00\x88\x0b\x02\x42\x3d\x00\x6a\x17\xd9\x88\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x45\x1b\x90\x00\x7a\x00\x11\x00\x90\x00\x11\x00\x52\x00\x28\x00\x41\x00\x5d\x07\xe5\x58\x41\x01\x20\x00\xc0\x06\x0b\x00\x3d\x00\x51\x00\xac\x02\x90\x00\x7a\x00\x1e\x5b\x3d\x00\xde\xfb\x59\xb4\x1e\xd8\x3d\x00\x41\x00\x7a\x00\x3b\x58\x3d\x00\xff\x8b\x3d\x00\xc7\x0c\xd6\x8b\x1a\xe1\x83\x02\x64\xd2\x5c\x7c\xca\x02\x5c\x5c\x7a\x00\x52\x00\x11\x00\x65\x59\x3d\x00\x76\x1e\x10\xb6\x28\x00\x5a\x55\x3d\x00\x28\x00\x7a\x00\xf8\x57\x3d\x00\x31\xdc\x3d\x00\xd7\x02\x52\x00\x0a\x93\x28\x00\x89\x3e\x75\x00\x90\x00\x3d\x00\x7f\x51\x08\x3d\x00\x09\x3f\xbe\x9e\xd0\xe1\xa4\x69\x11\x00\x7a\x00\x75\x00\x3d\x00\xfc\xf0\x6c\x17\xe3\x06\x3d\x00\xd7\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x7b\x16\x3d\x11\x3d\x00\x7d\x5b\x75\x00\x11\x00\xf8\xba\x3d\x00\xde\x0b\xc7\x43\x3d\x00\xff\x38\x75\x00\x28\x00\xc4\xba\x3d\x00\xba\x14\x0a\xb1\x3d\x00\xfc\x79\x06\x42\x3d\x00\xcb\x75\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\x07\xe1\x90\x00\x11\x00\x28\x00\x90\x00\x11\x00\x7a\x00\x28\x00\x41\x00\x75\xfc\x6d\x4b\x59\x00\x20\x00\x68\x2c\x53\x41\x01'

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
