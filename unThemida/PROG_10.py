#!/usr/bin/python3

#10595db4

import sys
import TVM

def FNC(state, log):
	eip = state.reg4[TVM.R_EIP]
	if eip == 0xC1A:
		log.append("\n#CALL EAX     \n")

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
		
		state.AddRoute(0x444, 0x141ed31 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141ed31 - 0x141e10f))
	elif eip == 0xD11:
		log.append("\n#CALL dword ptr[0x1082A6BC]     \n")

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
		
		state.AddRoute(0x444, 0x141ee28 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141ee28 - 0x141e10f))
	elif eip == 0xF3C:
		log.append("\n#IMUL ECX,ECX,0x68\n")

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
		
		state.AddRoute(0x444, 0x141f058 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f058 - 0x141e10f))
	elif eip == 0x1062:
		log.append("\n#FUN_10594c20\n")

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
		
		state.AddRoute(0x444, 0x141f17b - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f17b - 0x141e10f))
	elif eip == 0x1155:
		log.append("\n#IMUL EAX,EAX,0x68\n")

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
		
		state.AddRoute(0x444, 0x141f271 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f271 - 0x141e10f))
	elif eip == 0x1267:
		log.append("\n#FUN_10594bb0\n")

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
		
		state.AddRoute(0x444, 0x141f380 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f380 - 0x141e10f))
	elif eip == 0x137E:
		log.append("\n#IMUL ECX,ECX,0x68\n")

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
		
		state.AddRoute(0x444, 0x141f49a - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f49a - 0x141e10f))
	elif eip == 0x1494:
		log.append("\n#FUN_10594e60\n")

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
		
		state.AddRoute(0x444, 0x141f5ad - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f5ad - 0x141e10f))
	elif eip == 0x16BF:
		log.append("\n#IMUL EDX,EDX,0x68\n")

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
		
		state.AddRoute(0x444, 0x141f7db - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f7db - 0x141e10f))
	elif eip == 0x1848:
		log.append("\n#CALL EAX\n")

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
		
		state.AddRoute(0x444, 0x141f95f - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141f95f - 0x141e10f))
	elif eip == 0x1952:
		log.append("\n#FUN_10594e60\n")

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
		
		state.AddRoute(0x444, 0x141fa6b - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141fa6b - 0x141e10f))
	elif eip == 0x1AD5:
		log.append("\n#JMP 10595E90\n")

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
	elif eip == 0x1B97:
		log.append("\n#IMUL ESI,ESI,0x68\n")

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
		
		state.AddRoute(0x444, 0x141fcb3 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141fcb3 - 0x141e10f))
	elif eip == 0x1C9F:
		log.append("\n#FUN_10594bb0\n")

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
		
		state.AddRoute(0x444, 0x141fdb8 - 0x141e10f)
		log.append("#Jump to route {:02X}".format(0x141fdb8 - 0x141e10f))
	else:
		log.append("\n\n#OnEnd {:02X}\n\n".format(eip))


state = TVM.VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\xac\x02\x7a\x00\x52\x00\x1e\x5b\x3d\x00\x34\xfb\x33\xb4\x8d\xda\x3d\x00\xe6\x00\x8f\xd2\x3d\x00\x3d\x00\x2c\xb8\x4f\xde\x29\x02\x73\x4d\x8f\x3a\x8f\x47\x28\xf0\xe4\x0f\x7a\x00\x7a\x00\x11\x00\xf8\x57\x3d\x00\xf7\x1b\x3d\x00\x3c\x03\x52\x00\xaa\x6d\x90\x00\xed\xff\x7a\x00\x9a\x26\x3d\x00\x3d\x00\x46\x04\x7a\x00\x4b\xea\x41\x00\xc6\x53\x75\x00\x3d\x00\xd7\xef\x08\x3d\x00\xf4\x52\x74\x42\x3d\x00\x5d\x56\x11\x00\x3b\xfa\xb2\x75\x00\x0a\xb6\x88\xa5\x7a\x00\x52\x00\x35\xb7\x90\x00\x75\x00\x70\xd9\x11\x00\xe5\xfa\x27\x12\x5a\xcd\x4c\x20\x37\x54\x52\x04\x44\x75\x00\x5e\x4d\x41\x00\x8c\xef\x3d\x00\x8a\x4d\xb2\x41\x3d\x00\xaf\xa8\x88\xdc\x41\x00\x16\xac\x11\x00\xd0\x6c\x28\x00\xc1\x94\x81\x56\x75\x00\x3d\x13\x3d\x04\xaa\x97\x75\x00\xe0\x92\x90\x00\xef\x11\x00\xd4\x3d\x00\x50\x1d\x57\x2c\x3d\x00\x1d\x13\x35\x25\x3d\x00\x44\xbc\x8c\x43\x3d\x00\x9a\x77\x50\x62\xda\x29\x0a\x1f\x19\x54\xf1\x9e\x75\x00\x81\xdf\x75\x00\x7a\x00\x3d\x00\x75\x00\x08\x47\x75\x00\x3d\x00\x10\x95\x27\x7c\x7e\x18\x75\x00\x7a\x00\x90\x00\x3c\x58\x3d\x00\x50\xb3\x21\xd8\xeb\x11\x3a\x1b\x3d\x00\x52\x49\x70\xce\x51\xc0\x75\x00\xd0\x95\x2f\x26\x90\x00\x08\xc3\xf3\xb2\x11\x00\xae\x7a\x90\x00\x3d\x00\x77\xea\xa5\xed\xd1\x69\x5f\x58\x90\x2f\xb7\x15\x3d\x00\xeb\x77\x5a\xee\x68\xa2\x82\x00\xcc\x07\x15\x3b\x8e\x3f\x64\x53\xdc\xf4\x38\x2b\xa9\xa9\xde\xbc\x69\x0e\x93\x03\xc2\x8b\x11\x70\x09\x8b\x2c\x6d\x9f\xf8\xc1\xdb\x13\x02\x7b\x16\x7d\x41\x3d\x00\xc5\x5c\x75\x00\x7a\x00\xf3\xb8\x3d\x00\xb1\xeb\x86\x14\xef\x3f\x55\xa3\x27\x26\x1d\xb3\x4b\xe3\x75\x00\x52\x00\xad\xbf\x3d\x00\xa6\xa1\x8c\x32\x3d\x00\x3d\x00\x03\x01\x7a\x00\xaf\x74\x11\x00\x90\xa4\x09\x0f\x64\x48\x0d\x53\x75\x00\xe4\x8c\x3d\x00\xed\x02\x90\x00\x40\x29\x90\x00\x52\x00\x41\x00\xbe\x24\x16\x2e\x44\xe6\x75\x00\x51\x52\x7a\x00\x52\x00\x41\x00\x41\x00\xa1\x1c\x90\x00\x90\x00\x52\x00\x28\x00\x11\x00\x11\x00\x28\x00\x7a\x00\x51\x00\x00\x00\xca\x00\x00\x00\x75\x00\xa2\x60\x9f\xe1\x6e\xe4\x43\x3d\x00\xce\x41\x47\x78\xa0\xc2\x75\x00\x1e\xc5\xac\x74\x41\x00\x6a\x0e\x75\x00\x90\x00\x26\xba\x3d\x00\x39\x37\x12\x19\x75\x00\x5b\xa2\x0b\x59\x7a\x00\x57\x7a\x00\x75\x00\x62\x21\x15\x3e\x7a\x00\xd9\x35\x00\x57\x86\x68\x28\x00\x75\x00\x9f\x9c\x75\x00\x41\x39\x53\x59\x9e\x2b\x14\x7f\x05\xe5\x98\x01\x7a\x00\xba\xf0\x41\x00\x7a\x00\xe3\x18\x28\x00\xde\xd7\x75\x00\x75\x00\x28\x00\x90\x00\xc4\x58\x3d\x00\xec\x02\x02\x88\xb5\x43\x0a\x6c\x8c\xd6\x75\x00\x51\x7b\x52\x00\x90\x00\x99\x58\x3d\x00\xe1\xfa\x7a\x00\x52\x00\x41\x00\x41\x00\x76\x19\x90\x00\x52\x00\x11\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x28\x00\x51\x00\x00\x00\x02\x03\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xab\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xed\x02\x7a\x00\x11\x00\xf9\xa7\x9e\x1f\xe9\x6e\x75\x00\xb8\x58\x7a\x00\x52\x00\x41\x00\x41\x00\xd1\x11\x90\x00\x28\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x36\x01\x00\x00\x75\x00\xa2\xf0\x0f\x7e\x56\x75\x00\x52\x00\xf3\xb8\x3d\x00\xe0\x28\xb4\x45\x32\x7d\x08\x42\x3f\xf0\x32\xfe\xfe\x4e\x41\x00\x52\x00\x84\x33\x75\x00\x25\x37\x75\x00\x28\x00\xf7\xbb\x3d\x00\xe3\x87\x28\x00\xbc\xd7\x02\x7f\x0a\xf3\x75\x00\x30\x2f\x79\xae\x75\x00\x13\x7a\x3d\x00\x61\x03\x52\x00\x74\x23\x28\x00\xed\x8a\x75\x00\x41\x00\xf7\xbb\x3d\x00\x25\x58\x11\x00\xb4\x71\x8e\xcb\xcf\xf2\x75\x00\x75\x81\x6e\xe5\x4b\xe3\x75\x00\x3d\x00\x9b\x02\x52\x00\xe7\x77\x41\x00\xdf\x1c\xc9\x1a\xd1\x46\xa7\xfe\x75\x00\x5b\xb1\x3d\x00\x7c\x00\x7a\x00\xba\x2a\x11\x00\xc5\xa1\x7a\x00\xaa\x69\xd6\xb1\x75\x00\xa5\x73\xbf\x2a\x4c\x29\x3d\x00\x2f\x13\x31\x3b\x9b\xab\x1c\xc0\x75\x00\xde\x49\x30\x0c\x28\x00\x99\xb0\x3d\xef\x16\x1e\x68\xc1\xdd\x28\x87\x89\xd6\x6a\xb3\xbf\x28\xca\x2c\x64\xa1\x75\x00\x9c\xc9\x4d\x83\x66\xa9\x73\x72\x41\x0b\xdc\x05\xf7\xec\xd3\xcf\xd9\x48\x10\x64\x40\x92\xc5\xc1\x75\x00\x3d\x00\x10\x2e\x7a\x6e\x40\x04\x6f\x6b\x1e\x63\x07\x46\x61\x50\x28\x3c\x7a\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x6b\x56\x90\x00\x41\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xa2\x01\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xaa\x50\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x03\x5e\x38\x75\x00\x52\x00\x5d\xb8\x3d\x00\xe9\x58\xfe\xd9\x8b\xee\x00\xd4\x88\x70\xe8\x34\xd9\xfc\x81\x10\xc2\xa8\x75\x00\xb5\x15\x3a\x95\x3d\x00\xbf\xb6\x90\x00\xc6\xea\xb1\x71\x4f\x12\x75\x00\xa2\x68\xef\xad\x25\xb7\x75\x00\x40\xa6\x11\x00\x82\xb3\x3d\x00\x78\x1c\x4f\x42\xc7\xfc\x90\x00\x90\x00\xc5\x58\x3d\x00\x66\x43\x3d\x00\x1b\x94\x23\xc2\x32\xed\x26\xd1\x2c\xd5\xe4\x41\x3d\x00\x93\xe9\x17\xbf\x75\x00\xc8\x0c\xde\x4e\x41\x00\x1d\x36\x15\x41\x3d\x00\xe0\xc1\x28\x00\x09\x4a\x12\x99\x2c\x48\x75\x00\xfc\x42\xd0\xa7\xee\xbf\x7c\x88\x1a\x0a\x98\x9c\x7e\x9d\x06\x08\x24\xd7\xc5\x03\x03\xef\x60\x7c\x44\x36\x11\x00\x08\x1a\x15\x4d\x75\x00\x43\x5a\x75\x00\xbb\x42\x31\xab\x3d\x00\x90\x00\xb9\x35\x28\x00\x11\x00\xa7\x9d\x52\x00\x83\x10\x75\x00\x75\x00\x8b\xc6\x57\x03\x55\x02\x68\xda\xb6\x69\x11\x26\xd5\x26\xd1\xf2\x73\x35\x0f\xaf\xfe\xab\x75\x00\x52\x00\x79\x28\xc4\xff\x9c\x0c\xc1\xc9\x5a\x5e\x08\x4c\xfd\x8e\xac\xd4\x20\x53\xd3\x0f\x7c\xf3\x7a\x00\x38\xe8\x4f\x88\xfb\x5a\x49\x5c\x75\x00\x7f\xda\xac\x39\x3d\x00\x56\xf3\x3d\x00\x8e\x16\xaa\x2b\xd9\x35\x3d\x00\x3b\x52\x8b\x54\xe7\x9c\xea\x70\x07\x57\xd4\x28\x80\xb2\x30\x5f\x11\x00\x82\x14\x0d\x80\x3d\x00\x28\x00\xe9\x07\x11\x00\x41\x00\x8c\xe8\x52\x00\x87\xad\x75\x00\x75\x00\x90\x00\x68\xfc\x44\xea\x52\x00\xf2\xc2\x75\x00\x28\x00\x75\x00\x85\x64\x9b\xf9\xb5\xb2\x45\xf4\x3e\x00\x52\x00\x28\x00\x75\x00\xb3\xd2\xc7\x11\x4f\x23\x62\x03\xf3\xba\x3d\x00\x3d\x00\x47\x98\x7a\x00\x52\x00\x41\x00\x52\x00\x1e\x5d\x90\x00\x41\x00\x28\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x11\x00\xdc\x00\xfe\xea\x04\xe7\x67\x73\x40\x93\x98\x0e\x31\x45\xfb\x72\x32\x6e\x1b\x6f\x98\xbb\xa8\x81\xbc\x18\x8e\xee\xad\x99\x75\x00\xa7\x71\x7a\x00\x55\x6c\x19\x32\xee\xe9\xa7\x60\xba\x6b\x96\x97\x92\x10\xba\xeb\xfa\x5f\x21\x46\x3d\x00\x0d\x81\x71\x7d\x5c\x2e\x11\x00\x75\x00\xa3\x42\x35\x8b\x7a\x74\x3c\xe5\xce\x8e\x3e\x54\x3f\xfe\x0c\x44\x3d\x00\xcb\x30\x1f\x83\x8c\x94\x86\x6b\x1a\x35\xc7\x4b\x6f\x09\x75\x00\x63\x27\x05\x90\x19\x69\x6a\xae\x11\x00\x7a\x00\x75\x00\xfa\x7f\x6c\xd9\x85\x34\x3d\x00\xe0\x1a\x6a\xc5\xdf\x2e\xb2\x4c\x04\xca\xce\x7d\x00\x8b\x5a\x7a\x11\x00\x3d\x00\xa0\xd2\x63\x38\x75\x00\x11\x00\x90\xbf\x3d\x00\x41\x00\x61\xcd\x52\x00\x7a\x00\x8f\x4d\x7a\x00\x85\xdc\x11\x00\xb4\x48\x62\x43\x3d\x00\x75\x00\xa7\xdf\x11\x00\xaf\xcf\xb5\x72\x5a\x81\x44\x55\x0d\x5f\xe3\x72\x29\x55\x0a\xec\x58\xf2\xbf\x99\xa0\x05\x2a\xd3\x01\xd5\xf9\x27\x7a\x00\x41\x00\x75\x00\x73\x29\x6b\xdd\xcb\x08\x3d\x00\x9c\x02\x52\x00\xf5\x6d\x52\x00\x3d\x00\xa9\x6c\x50\xda\xc4\x3f\xd9\xf5\xc1\xd1\x36\x4c\x29\x43\xaf\x33\x62\xe2\xda\x17\xfe\x4f\x81\x65\x3c\xf6\x3d\x00\xca\x13\xa9\x77\xb0\x07\x28\x00\x0a\xd0\xdb\xc1\x0b\xff\x38\x41\x75\x00\x3d\x00\x5e\xf2\x15\x10\xe4\xee\x20\x75\x17\x74\x85\x71\xb0\xd8\x02\x7f\x7a\x00\x29\x96\x06\x42\x3d\x00\xd5\x95\xf6\x41\x3d\x00\x5b\x29\xc5\xd1\x52\x00\xfd\xf4\x11\x00\x3d\x00\x1d\x4d\x52\x00\x44\xc1\x3d\x00\x7a\x00\x32\xf0\x06\x8e\x52\x00\x54\xa8\x75\x00\x28\x00\x75\x00\x45\x56\x9b\xf9\xa0\xc6\x10\xf8\x4b\x33\x41\x00\x52\x00\x75\x00\x52\x00\x6a\x71\xf3\x4c\xc5\x85\x00\x86\x08\x57\x75\x00\x75\x00\xaf\x19\x17\x6d\xed\x20\xaa\x63\x91\xa4\xac\xb0\xbd\x42\x9b\x16\x11\x00\x90\x00\xb1\x57\x3d\x00\x38\x45\xdb\x73\xed\xfc\x5c\x56\x75\x00\x3d\x00\x7c\x00\x41\x00\x06\xd8\x11\x00\xc1\xcc\x28\x00\x4c\x7c\xc3\xee\x75\x00\xac\xcb\x00\x35\x48\x67\xd6\x49\x61\xcb\x4f\x16\x65\x5c\x41\x00\x90\x00\x75\x00\x97\x83\x35\x7f\x70\x78\x6a\x98\x75\x00\x9c\xa4\xcc\x7f\x75\x00\x28\x00\xf3\xb8\x3d\x00\x3c\x90\x95\x25\x0f\x5f\xe9\x9b\x69\x35\xc2\xc3\x59\x64\x8d\x03\x8e\x0c\x00\x9f\xc4\x52\x52\x00\x75\x00\xe3\x36\xf1\x41\x28\x69\xb5\xdd\xe4\x7a\x48\x64\x12\x0e\xb7\xdf\xce\x47\x71\xd5\x3d\x20\x75\x00\x04\x98\xc3\xf4\x90\x00\xb3\x89\x3d\x00\xd8\x33\x00\x7c\x6b\x45\x74\xc7\x75\x00\x52\x00\x24\xfd\x41\x00\x28\x00\x73\x4f\x52\x00\x87\x2a\x75\x00\x75\x00\xf3\xd8\xfb\x31\xd6\x7f\x7d\x47\xf4\x1e\x83\xeb\xa1\x2b\x82\x11\xb1\xe6\x3d\x00\x16\xa3\x98\xf5\xc8\x1a\xa7\x76\x59\x02\xe6\xc3\xe6\x17\x97\xdd\x3d\x00\x75\x00\xea\x87\x41\x00\xc7\x88\xd1\x5d\xfe\xb5\x84\xb5\x26\x3b\x37\xae\xb7\x63\x1b\xed\x6d\xc7\x21\x77\x98\x99\xe9\x41\xbf\xff\xbc\xbc\x75\x00\x81\x11\xfb\x12\xbc\xf0\x3d\x00\x60\x41\x0c\xc1\xf6\x31\xa6\x2f\x6d\xa5\x41\x31\x00\x01\x6a\x53\x90\x00\x3d\x00\xda\x78\x59\xf1\xf0\x73\x4b\x94\x0a\x2e\x7a\x00\x11\x00\x75\x00\x7b\x16\x46\xc2\x3d\x00\xa3\x5c\x75\x00\x41\x00\xf7\xbb\x3d\x00\xf3\xeb\x52\x00\x8e\xf2\x3e\x2e\x25\x12\x75\x00\x7f\xb3\x27\x24\x75\x00\x9a\x5c\x98\xd0\x11\x00\x50\x03\xca\xf4\x75\x00\x52\x26\x90\x00\x3d\x00\x36\x65\x56\x26\x52\x96\x32\x09\x6a\x41\x93\x09\x9f\x6c\x49\x4b\x52\x00\x55\x94\xd6\x3c\x75\x00\x15\x27\x11\x00\x67\x77\x7c\x27\xaa\xe7\xb8\x68\x4a\x3f\xca\xc8\x88\x93\x90\x00\x90\x00\x75\x00\x3d\x00\x06\x93\xd9\xe8\x82\xae\x3d\x6e\x3f\xdd\x27\x17\x65\x16\xf4\x6a\x11\x25\x06\x4f\x6f\x74\x1f\x24\x75\x00\x7a\x00\xe5\xd6\x3d\x55\x1a\x67\x7a\x00\x70\x02\x2b\x47\x7a\x00\x52\x00\x41\x00\x41\x00\xf1\xe6\x90\x00\x52\x00\x28\x00\x11\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x51\x00\x00\x00\x45\x01\x00\x00\x75\x00\x80\xb4\x7d\x7a\x07\xe4\x43\x3d\x00\x29\xbd\xf8\x70\xbf\xc0\x75\x00\x81\xe4\xf4\x2d\x28\x00\xb1\x9c\xc6\xf6\x75\x00\x34\x43\xfd\x59\x52\x00\xb0\x3d\x75\x00\xbb\x2a\x7e\x85\x3d\x00\x6a\xa5\x22\xb3\x11\x25\x33\x53\x08\x45\x9a\x49\x55\x0a\xc2\x49\x28\x00\x75\x00\x41\x00\xf8\xc2\x6d\x10\x06\x21\x75\x00\x0b\x3f\x90\xe6\x28\x00\x75\x00\xc0\x29\x75\x00\x2f\xaa\x90\x00\x7a\x00\x90\x00\x28\x00\xba\xe9\x26\x0b\x7c\x88\x75\x00\xc6\x15\x1a\x68\x3d\x00\xcb\x40\xca\x07\x0a\x93\x55\x3e\xc7\x10\x19\xe9\x27\x56\x00\x5b\xf9\x44\x21\x0b\x0a\xe0\x52\x00\xde\x73\xc8\x6c\x41\x00\xe9\x2b\x75\x00\x7a\x00\x75\x00\xa8\xce\xe6\x17\x7f\xab\x3d\x00\x75\x00\x88\x80\x41\x00\x6b\x75\xda\xed\xd3\x2d\x74\xfc\x2b\x14\x00\x5c\x9f\x73\x83\xeb\x4e\x08\xf2\x25\xf0\xd6\x3d\x00\x72\x0f\x03\xc5\x0a\x40\x41\x00\x31\x14\x52\x00\x7a\x00\xe7\x52\x41\x00\x63\xbe\x11\x00\x75\x00\x13\x3a\xef\x5c\x5c\xa3\x6b\x29\xe2\xcd\x9c\x02\x3d\x00\x03\x98\x75\x00\x9d\xf1\x11\x00\x0c\x77\xb6\xec\xdf\xa0\x4a\x31\x18\xc6\xc3\xf5\x86\x2a\xac\x2b\x56\x99\xf1\x7f\xee\x96\x75\x00\x28\x00\x3d\x00\x7a\x00\x56\xb6\x3d\x00\xdc\x99\x75\x42\x1d\xae\x5e\x25\x01\x06\xad\x7d\x12\x4d\x44\x5a\x7a\x00\x3d\x00\xcf\x52\x7a\x00\x52\x00\x41\x00\x41\x00\x96\xe7\x90\x00\x7a\x00\x11\x00\x90\x00\x11\x00\x52\x00\x28\x00\x28\x00\xc8\x04\x52\x00\x43\x15\x28\x00\x52\x00\x45\x55\x28\x00\x70\x13\x11\x00\x91\x87\x75\x00\x41\x00\xfe\xb8\x3d\x00\x96\x03\x73\xbc\x1d\x38\xcd\x38\x75\x00\x90\x00\xf7\xbb\x3d\x00\xf1\xcb\x90\x00\x55\xbb\xa4\xe7\x24\x00\x75\x00\xb2\xc1\x75\x00\xcd\x96\x84\x74\xce\xbe\xbe\xd8\x48\x6b\x41\x00\x41\x00\x75\x00\x1f\x6c\x4d\x19\x1a\xc8\x75\x00\x63\x02\xac\x00\xed\x56\x75\x00\x90\x00\x14\x9b\x80\x32\x45\x76\x75\x00\x3d\x00\x95\xed\x68\xb1\xf2\x97\x27\x71\x14\xe8\x9a\x2e\xa8\xfd\xee\x7f\x90\x00\x75\x00\xc8\x22\x7d\x10\x96\x8e\x7e\x9f\xf2\xee\x2e\x04\xc9\xeb\x8f\xb9\x42\x01\x3d\x00\x6d\xaa\xe1\xa8\xf4\x11\x1a\x46\x70\x5a\x16\x0f\x0c\xc7\x98\x3e\x41\x00\x3d\x00\x52\x1f\xc0\x02\x3d\x00\xa1\xd9\xd0\x0a\x09\x5b\x3d\x00\xa0\x01\x28\x00\xb2\xf8\x90\x00\xce\x36\x6b\x43\x3d\x00\x72\xc7\x74\x08\x17\x86\x3d\xdf\x04\x71\x75\x00\x86\x2a\xac\x61\xf9\xb6\x12\x8f\x0c\xb9\xac\x01\x92\x37\xf7\xb7\x09\xc0\xda\x1d\x75\x00\x16\xae\x12\x2c\xfb\x6f\x5e\x4d\x7a\x00\x7c\x04\x3d\x00\x3d\x00\xad\x55\xf2\xc4\xb3\x4b\x8e\x70\x34\xb0\x75\x00\x90\x00\xf8\xba\x3d\x00\x23\xd7\x02\x43\x3d\x00\x3d\x00\xcf\x11\x3d\x00\x6b\x52\xa1\x77\xff\xa4\xf2\x32\x69\x8a\x4a\x4f\x6d\x9c\x62\x01\x7a\x00\x75\x00\xf4\x78\xb6\x2f\xa8\x98\x31\x21\xe6\x1c\xc1\x02\x41\x00\xf2\xfd\x53\x98\x41\x00\xab\x3e\x75\x00\x41\x00\x75\x00\x70\x94\x12\x08\x69\xf7\xe9\x87\x11\x00\x11\x00\xc5\x58\x3d\x00\x7c\xb1\x3d\x00\x61\x26\xa9\x72\xd2\xfa\xbe\x8e\x41\x00\x88\xb0\x90\x00\x11\x00\x8e\xa5\x7a\x00\x7c\xc2\x90\x00\x7a\x00\x88\xd6\x11\x00\x11\x00\xf7\xe8\x7a\x00\xc0\x3f\x75\x00\x75\x00\xc7\x0b\x71\xc5\xab\x2f\x78\xa9\x8e\x6b\x37\xf0\xf5\x5b\xc2\xee\x11\x00\x96\x3b\x11\x00\x28\x00\x83\x6e\x7a\x00\x79\x1a\x90\x00\x57\x0a\x02\x42\x3d\x00\x6c\x17\x41\xd7\x3d\x00\xdb\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x93\x9a\x06\x42\x3d\x00\x0c\x78\x02\x42\x3d\x00\xba\x14\xf6\x5e\x3d\x00\xee\xed\x02\x42\x3d\x00\x7b\x16\xc2\xc4\x3d\x00\x2b\x5c\x75\x00\x7a\x00\xf8\xba\x3d\x00\x75\x57\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x90\x00\x93\x21\x90\x00\x52\x00\x7a\x00\x11\x00\x11\x00\x41\x00\x28\x00\x28\x00\xa8\x3c\xd9\xfe\x41\x01\x20\x00\x11\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x8d\x24\x3d\x00\xd9\x93\x90\x00\x5f\xe0\x3d\x00\x52\x00\x7a\x00\xf8\x57\x3d\x00\xfd\x66\x3d\x00\x12\x02\x7a\x00\x26\x09\x52\x00\x3d\x00\x73\x9a\x7d\xfd\x27\x4c\x28\x2e\x3e\x4f\x68\x07\x76\x73\x7a\x2c\x90\x00\xbe\x9f\xe6\x2e\x3d\x00\xf5\xb0\xea\x31\x3d\x00\xe5\xc1\x98\x2a\x3d\x00\x5b\xaf\x75\x00\x7a\x00\x3d\x00\x5c\xde\x08\x3d\x00\x0c\x95\x3f\x5d\xcf\x91\xd9\x5d\x75\x00\x57\x6a\x15\x41\x3d\x00\x6f\xfc\x41\x00\x35\xec\xe5\x5e\x70\x17\x75\x00\xa9\x14\x4d\xae\x2e\x38\x75\x00\x28\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x7a\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x90\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x90\x00\xf8\xba\x3d\x00\x6c\x8d\x02\x42\x3d\x00\x7b\x16\xee\x03\x3d\x00\x94\x5c\x75\x00\x41\x00\xf8\xba\x3d\x00\x6e\xcd\xc7\x43\x3d\x00\xc7\x38\x75\x00\x41\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xed\x4b\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xee\x55\xe8\xfe\x41\x01\x20\x00\x00\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x52\x00\x82\xbe\x3d\x00\xb8\x00\x90\x00\x3b\xc0\x3d\x00\x97\x22\x65\x6f\x3d\x00\x85\x93\x28\x00\x07\x2d\x3d\x00\x90\x00\x7a\x00\x3b\x58\x3d\x00\x3d\xb3\x3d\x00\x06\x85\xd8\xf8\x00\xfd\x9b\x1f\x86\xc4\x61\x72\x3c\x54\x7a\x56\x90\x00\xc5\x6a\xaa\x36\x3d\x00\x3d\x00\xd7\x02\x52\x00\x68\x5d\x52\x00\x5f\x96\x75\x00\x28\x00\x3d\x00\x8e\xe4\x08\x3d\x00\x44\x79\xe7\x60\xa3\x65\x58\x9f\xb5\x49\x0b\xee\x54\x5d\x6d\xe8\x3d\x00\xe1\x96\x7d\x78\x41\x00\xb9\xa8\x05\x14\xe5\x0a\x75\x00\x03\xaa\x38\x79\x2c\x94\xdc\x42\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\x3f\x38\x75\x00\x11\x00\xf8\xba\x3d\x00\xfc\x79\x02\x42\x3d\x00\x86\x14\x26\xd0\x3d\x00\x86\x14\xd3\xcd\x3d\x00\xba\x14\xa2\x33\x3d\x00\xc9\x65\x06\x42\x3d\x00\x6b\x65\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xc5\xe3\x90\x00\x28\x00\x11\x00\x90\x00\x11\x00\x52\x00\x28\x00\x7a\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x43\xe1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x90\xff\x90\x5e\x59\x00\x20\x00\x75\x00\xfc\x3d\x00\x42\x3d\xd1\x6e\xf7\x83\x51\xbc\x32\x83\x7e\x58\x5f\x46\xea\x92\x5c\xbf\xe1\x27\xe2\x13\xe1\xe1\x9d\x8b\xa8\xf7\x16\xfa\x83\x76\x66\x48\xf6\x7e\x52\x00\x0a\x06\x39\x64\x24\x08\x75\x00\xee\xd8\xf9\x44\xaf\x10\x75\x00\x41\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\x07\x38\xc7\x43\x3d\x00\x7e\x38\x75\x00\x28\x00\xc4\xba\x3d\x00\x7b\x16\x36\x61\x3d\x00\x94\x5c\x75\x00\x11\x00\x39\xb8\x3d\x00\x08\x00\x75\x00\x90\x00\xc4\xba\x3d\x00\x86\x14\xd0\x4b\x3d\x00\x6a\x17\xe8\x4d\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xd5\xf3\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x53\xf1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xf5\xeb\x90\x5e\x59\x00\x20\x00\x75\x00\x3a\x3d\x00\xa0\x01\x40\x54\xdc\x42\x3d\x00\x9c\xde\x75\x00\x7a\x00\x3d\x00\x75\x00\x3f\x38\x75\x00\x28\x00\xf8\xba\x3d\x00\xfc\xf5\x06\x42\x3d\x00\x0d\xc0\x02\x42\x3d\x00\x7b\x16\xf9\x7f\x3d\x00\xa3\x5c\x75\x00\x90\x00\xf8\xba\x3d\x00\x1d\x45\xc7\x43\x3d\x00\x85\x38\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xba\x38\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7c\x22\xb7\x18\x38\xe3\x2b\x25\x2f\x7f\xfe\x41\x01\x20\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x46\x26\x3d\x00\xe8\x00\x8d\x26\x3d\x00\x3d\x00\xcf\x01\x41\x00\x76\xcc\x52\x00\x3d\x00\xcf\x01\x28\x00\xf5\x1c\x41\x00\x3d\x00\xac\x02\x52\x00\xc9\xd1\x41\x00\x11\x00\x41\x00\xd5\x58\x3d\x00\xf9\x74\x90\x00\x52\x00\xf8\x57\x3d\x00\x69\xd9\x3d\x00\x46\x04\x90\x00\x3e\x97\x52\x00\x81\x81\x75\x00\x3d\x00\x5c\x3d\x08\x3d\x00\x4a\x80\x0e\xee\x76\x8d\xa6\x90\x70\x38\xe4\x63\x38\x70\x44\x6d\x4b\xec\xaa\xe1\x2c\x27\x34\xe1\xca\xfd\x24\x0b\xba\x14\x8d\xab\x3d\x00\x3d\x8f\xfe\x41\x3d\x00\x90\x00\xaa\x86\x11\x00\x52\x00\x89\x25\x90\x00\x9e\xcb\x75\x00\x75\x00\xf0\xfc\x81\xed\x11\x00\x56\x2d\xb4\x4d\x60\x12\x85\x28\xfd\x65\x59\x74\x74\xee\x08\xea\xaf\xf6\xba\x50\xee\x72\x1d\x79\x74\x2f\x84\x20\x7b\x16\x7a\x26\x3d\x00\x5d\x5c\x75\x00\x90\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\x7b\x16\xf6\xfd\x3d\x00\x46\x5c\x75\x00\x7a\x00\xc4\xba\x3d\x00\xba\x14\xa4\x1d\x3d\x00\x42\xb9\x02\x42\x3d\x00\x86\x14\x36\x83\x3d\x00\xba\x14\xbe\x18\x3d\x00\xf9\xdb\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x05\x69\x90\x00\x90\x00\x41\x00\x7a\x00\x11\x00\x28\x00\x28\x00\x52\x00\x8b\x74\xf7\xfe\x41\x01\x20\x00\x20\x4c\x59\x00\x3d\x00\x51\x00\xac\x02\x7a\x00\x52\x00\x3b\x58\x3d\x00\x34\xfb\x3d\x00\xc8\x85\x0c\xfb\x65\xe7\x82\x33\xa3\x2d\xcc\x5e\x33\x0a\x6e\x19\x90\x00\x7a\x00\x7a\x00\xf8\x57\x3d\x00\x21\x18\x3d\x00\xac\x02\x52\x00\x21\x8f\x28\x00\x41\x00\x52\x00\xf8\x57\x3d\x00\x38\xb7\x3d\x00\xf5\x04\x11\x00\xa4\xac\x11\x00\xde\xd0\xc0\x52\x3d\x00\x9d\x16\xdd\x4c\x3d\x00\xc5\x7f\x75\x00\x3d\x00\x4f\xc1\x08\x3d\x00\x11\x1c\xf6\x17\x7e\x22\x81\xd1\x32\x73\x51\x2c\x36\x3f\x5e\xf1\xac\x8a\xf0\xb8\x9e\x2b\x1b\x97\x31\x60\x09\x8b\x0a\xe1\xb0\x27\x12\xa1\xe3\x70\x6c\x17\x25\x7a\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\xfd\x5b\x75\x00\x52\x00\xf8\xba\x3d\x00\x7d\xeb\xc7\x43\x3d\x00\x15\x38\x75\x00\x52\x00\xf8\xba\x3d\x00\xb3\xd7\xc7\x43\x3d\x00\xb7\x38\x75\x00\x28\x00\xf8\xba\x3d\x00\x9e\xdf\x02\x42\x3d\x00\x6a\x17\xe4\xef\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\xf5\x1f\x90\x00\x41\x00\x11\x00\x28\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x33\x05\x4a\x07\x1b\xd2\x82\xcf\x22\x91\xfe\x41\x01\x20\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x28\x00\x15\xbd\x3d\x00\x3d\x00\xac\x02\x52\x00\x1b\x9b\x28\x00\x7a\x00\x41\x00\xd5\x58\x3d\x00\xce\xab\x11\x00\x52\x00\x3b\x58\x3d\x00\x9a\xf5\x3d\x00\xfa\x2d\xa4\xfb\x6f\x73\xf7\x3f\xc6\x0d\xa4\x34\x01\x35\xc7\x0d\x90\x00\x3d\x00\x3c\x03\x11\x00\x78\x52\x41\x00\xad\xff\x52\x00\x73\xb3\x3d\x00\x3d\x00\x0e\x0a\x90\x18\x51\x36\x87\x58\x18\xae\xdb\x6f\x61\xae\xaf\x5f\x90\x00\x44\x1a\x75\x00\x90\x00\x3d\x00\x24\x68\x08\x3d\x00\x69\x3b\x9c\x8f\xb3\x99\xb3\xfb\x6b\x56\x8a\x51\xa9\xe1\x52\x00\x52\x00\x3b\xe7\xf2\x8e\x85\xe6\x52\x45\xb8\x6e\x8c\x07\x4b\xec\xce\x18\xa0\x62\x05\xf5\x05\x1e\xf3\xaf\x7d\xb6\x75\x00\x11\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x41\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\xba\x14\x2d\x9d\x3d\x00\x97\x39\x02\x42\x3d\x00\xba\x14\xb0\x02\x3d\x00\xd4\x6d\x06\x42\x3d\x00\x3a\x6d\x02\x42\x3d\x00\x7b\x16\x63\x0b\x3d\x00\xae\x5c\x75\x00\x7a\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\xed\x11\x90\x00\x41\x00\x52\x00\x11\x00\x11\x00\x28\x00\x28\x00\x90\x00\xf5\x0d\x06\xff\x41\x01\x20\x00\xb0\x4b\x59\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\xcf\x01\x90\x00\x0f\x4d\x90\x00\x3d\x00\xcf\x01\x7a\x00\x94\x9d\x11\x00\x3d\x00\xcf\x01\x52\x00\x82\x32\x7a\x00\x3d\x00\xac\x02\x11\x00\x93\x5f\x7a\x00\x7a\x00\x90\x00\x3b\x58\x3d\x00\xa0\xe7\x3d\x00\x9f\x2e\x5a\x54\x53\xb7\xce\x64\xda\xdc\x48\x1f\x81\x25\xca\x3d\x7a\x00\x0e\x4d\x28\x00\x1a\x72\x3d\x00\x3d\x00\x47\x08\x1a\xb5\x00\xf6\x1a\x66\xf2\x5c\x9b\x72\x3e\x4c\x1f\x30\x52\x00\x0c\xa8\x75\x00\x3d\x00\xb1\x16\x08\x3d\x00\x75\x00\xaf\x6d\x7a\x00\x13\x39\xee\x6f\x03\x8c\xa9\x50\xec\x41\xc1\xcb\xc7\x4d\x37\xf0\x81\x28\x16\x95\x90\x00\x9e\xf7\x90\x00\x41\x00\xdd\x9c\x28\x00\x3c\x4c\x11\x00\xc7\x2d\xbd\x8f\x7e\xef\x48\x38\x67\x29\x78\xf5\x75\x00\x11\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\x7a\xc9\x06\x42\x3d\x00\x9e\xb9\xc7\x43\x3d\x00\x4f\x38\x75\x00\x90\x00\x39\xb8\x3d\x00\xf3\x00\x75\x00\x41\x00\xf8\xba\x3d\x00\x3f\x8b\x06\x42\x3d\x00\x99\x7b\xc7\x43\x3d\x00\xbf\x38\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x74\x7e\x90\x00\x28\x00\x52\x00\x90\x00\x11\x00\x11\x00\x28\x00\x7a\x00\xb2\x64\xc2\x81\xc1\x5a\xc2\xa2\x15\xa3\xfe\x41\x01\x20\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x63\x23\x3d\x00\x3d\x00\xc6\xf4\xc7\xaf\x02\x52\xb0\x3a\xd2\x5b\x82\x60\xbb\x9b\xb9\x1b\x7a\x00\x3d\x00\xac\x02\x11\x00\xf9\x43\x41\x00\x11\x00\x28\x00\xf8\x57\x3d\x00\x18\x85\x3d\x00\xcf\x01\x90\x00\x42\x2c\x41\x00\x3d\x00\x12\x02\x90\x00\x68\xb5\x7a\x00\x3d\x00\x70\x3c\xd4\x1b\x9c\x6d\xa6\x1a\x19\x4e\x41\x4c\x05\xe9\x07\x54\x41\x00\x7a\x00\x28\x00\x6f\x5a\x3d\x00\xfe\xf5\x70\x93\x75\x00\x3d\x00\xad\x2f\x08\x3d\x00\xc1\x8f\x6c\xec\x56\xad\xa2\x88\x0e\x97\x41\x00\x07\x82\x2f\xa1\x2e\x4f\x74\x00\x89\x11\xe0\x51\x15\xef\x53\x4e\x1d\x5d\x15\x3e\x05\xe1\x2e\x2b\x6d\x38\x75\x00\x52\x00\x39\xb8\x3d\x00\x00\x00\x75\x00\x52\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x41\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x52\x00\xc4\xba\x3d\x00\x86\x14\xfb\x5f\x3d\x00\x7b\x16\x10\x85\x3d\x00\x91\x5c\x75\x00\x41\x00\x39\xb8\x3d\x00\x32\x00\x75\x00\x7a\x00\x39\xb8\x3d\x00\xb1\x00\x75\x00\x11\x00\xf8\xba\x3d\x00\x1e\x56\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x01\x21\x90\x00\x11\x00\x28\x00\x90\x00\x11\x00\x52\x00\x28\x00\x41\x00\x24\x3c\x15\xff\x41\x01\x20\x00\x60\x4e\x59\x00\x3d\x00\x51\x00\xac\x02\x28\x00\x52\x00\x3b\x58\x3d\x00\x34\xfb\x3d\x00\x0d\x1b\xe2\xfa\x00\x17\xe0\x27\xe1\x67\xcf\x71\xa3\x05\xde\x62\x52\x00\x3d\x00\x1d\x3d\xd0\xff\x9b\x29\xba\x4b\x0b\xeb\xdf\x47\x2a\x10\x50\x4c\x41\x00\xa6\x4d\x28\x00\x59\x61\x3d\x00\x3d\x00\xac\x02\x28\x00\x05\xc2\x90\x00\x28\x00\x11\x00\x65\x59\x3d\x00\x9d\x50\x2b\xb6\x11\x00\x2f\xb5\x3d\x00\x0d\x7f\x4a\x6f\x3d\x00\xe9\xe4\x75\x00\x11\x00\x3d\x00\xb3\x95\x08\x3d\x00\x05\x4e\x2f\x8e\xb5\xfc\x99\x37\x75\x00\xb7\x84\x5d\x84\x75\x00\x7a\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x11\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x7a\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x28\x00\xc4\xba\x3d\x00\x7b\x16\xb5\x17\x3d\x00\x94\x5c\x75\x00\x52\x00\xf8\xba\x3d\x00\xec\x19\x02\x42\x3d\x00\xba\x14\xc1\xb6\x3d\x00\x84\x69\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xf9\x79\x90\x00\x52\x00\x28\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x11\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x7f\x7b\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x81\x66\x90\x5e\x59\x00\x20\x00\x75\x00\x80\x3d\x00\x4f\xe2\x28\x00\x4b\x64\x51\x0c\x75\x00\x06\xa3\x2e\x64\x7d\x57\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x85\x78\x02\x42\x3d\x00\xba\x14\x02\x37\x3d\x00\xa4\xe6\x02\x42\x3d\x00\x86\x14\xac\xac\x3d\x00\xba\x14\x21\xf6\x3d\x00\x17\x48\xc7\x43\x3d\x00\x85\x38\x75\x00\x7a\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x34\xd1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xb2\xd3\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x14\xc9\x90\x5e\x59\x00\x20\x00\x75\x00\x3a\x3d\x00\xfc\x02\x75\x00\x81\x59\x28\x00\x9e\xfc\x0c\x27\x05\xcd\xf0\x0f\x5a\x49\xb2\xdc\x43\x69\x76\xf0\xac\x60\xa7\x8d\x66\x63\x9d\xd0\x3f\x05\x75\x00\xea\xd0\x52\x00\x13\x63\xea\x56\x6c\x17\xaa\x0a\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\xfd\x5b\x75\x00\x41\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\x86\x14\x3b\x57\x3d\x00\x7b\x16\x90\x79\x3d\x00\xa3\x5c\x75\x00\x52\x00\xc4\xba\x3d\x00\xba\x14\xf3\xa9\x3d\x00\xe3\xb8\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x27\x69\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x9a\x75\x73\xd0\xc6\xfa\x40\x9c\x79\xb5\xfe\x41\x01\x20\x00\x3d\x00\x51\x00\xac\x02\x52\x00\x7a\x00\x1e\x5b\x3d\x00\x34\xfb\x33\xb4\x67\xd7\x3d\x00\x3d\x00\x12\x02\x90\x00\x2a\x9d\x11\x00\x3d\x00\xff\x01\x76\xe8\xad\x84\x7e\x5a\x13\x19\x04\x06\x02\xfd\x42\x71\x7a\x00\x3d\x00\x12\x02\x7a\x00\x86\xd8\x41\x00\x3d\x00\x0f\xf9\x11\x8f\x5b\xac\xc0\x0c\x43\xef\xca\x36\x43\xe5\xb3\x38\x52\x00\x3d\x00\x3c\x03\x41\x00\x0e\x8f\x41\x00\x6c\xff\x52\x00\x29\xea\x3d\x00\xa8\xc8\x75\x00\x3d\x00\x43\x77\x08\x3d\x00\xa8\xc0\x76\x28\x4a\xca\x1c\x73\x86\xc0\x90\x00\xe6\xf3\xb8\x54\x1d\x52\x39\x46\x3f\x37\xa1\x68\x4b\xec\x7b\xd7\xb1\xce\xfa\xfd\xf9\x1e\x5d\x47\x67\xbe\x00\xa6\x79\xb2\x7f\x7f\x6f\x44\xcb\x87\x4b\x75\x00\x74\xa9\x16\xdb\x52\xf1\x7a\x00\x7a\x00\xea\x29\xc8\x07\xd0\x38\x82\xc9\x32\xbc\x20\x22\x50\x6b\x8c\xae\xf9\x1a\xf0\xc8\x3c\x20\x60\x54\x7a\x00\x52\x00\x41\x00\x7a\x00\xf3\x46\x90\x00\x28\x00\x90\x00\x52\x00\x11\x00\x41\x00\x28\x00\x11\x00\x07\x05\x4e\x77\x49\xe4\xba\x1f\x90\x89\x3c\xc6\xe6\xa8\x9b\x45\xde\x6d\x82\x7c\x76\xa5\x75\x09\xf2\x42\xd3\x3b\x90\x7a\x65\x40\x2b\x31\xc6\x25\x06\x9e\x13\x0b\xc9\x31\xf9\x33\x8a\xd2\xfe\x3c\xef\x63\x4e\xd4\x02\x42\x3d\x00\x6c\x17\x9f\x40\x3d\x00\x9c\xde\x75\x00\x41\x00\x3d\x00\x75\x00\xfd\x5b\x75\x00\x41\x00\xc4\xba\x3d\x00\x7b\x16\x7e\x7f\x3d\x00\x4a\x5c\x75\x00\x7a\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x41\x00\x39\xb8\x3d\x00\x08\x00\x75\x00\x52\x00\xc4\xba\x3d\x00\xba\x14\x66\x68\x3d\x00\xe3\x28\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x27\xf9\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa8\xe6\x24\xff\x41\x01\x20\x00\x11\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\xcf\x01\x28\x00\x0f\x4d\x41\x00\x3d\x00\x12\x02\x11\x00\x6f\x9d\x90\x00\x3d\x00\x8c\x48\xfe\xfc\x00\x31\x8d\x55\xaf\x9e\x3e\x3b\x60\x11\x10\x71\x28\x00\xa6\x4d\x28\x00\xfe\x90\x3d\x00\x62\x84\x4a\x6b\x3d\x00\xef\x93\x7a\x00\x6d\x2b\x3d\x00\x9e\xbd\x2a\x6d\x3d\x00\xb5\x5c\xbb\x6e\x3d\x00\x78\xe3\x75\x00\x11\x00\x3d\x00\xbc\x93\x08\x3d\x00\x7a\x00\x75\x00\xc9\x21\x90\x00\x90\x4e\xc2\xf5\x7a\x00\x52\x00\x41\x00\x28\x00\x0a\x55\x90\x00\x41\x00\x7a\x00\x90\x00\x11\x00\x52\x00\x28\x00\x11\x00\x51\x00\x00\x00\x23\x01\x00\x00\x75\x00\x80\x03\xc5\x75\x00\xbf\xb0\x90\x00\xc4\x53\x51\x0d\x7b\x16\xb7\x4b\x3d\x00\xfd\x5b\x75\x00\x11\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x9b\xcd\xc7\x43\x3d\x00\x7e\x38\x75\x00\x52\x00\xf8\xba\x3d\x00\x45\xdd\x06\x42\x3d\x00\x06\xbd\x02\x42\x3d\x00\x7b\x16\x5d\xbc\x3d\x00\x01\x5c\x75\x00\x11\x00\xf8\xba\x3d\x00\x79\x45\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x09\x21\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x2c\x3c\x33\xff\x41\x01\x20\x00\x60\x4e\x59\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x52\x00\x3b\xc0\x3d\x00\x49\x22\xb3\x6f\x3d\x00\x9b\x93\x90\x00\x3d\x2d\x3d\x00\x11\x00\x52\x00\x1e\x5b\x3d\x00\x69\xb3\x92\xb4\x00\xd9\x3d\x00\x86\x93\x41\x00\x82\x95\x3d\x00\x50\x00\x41\x00\x3b\xbf\x3d\x00\x49\xa7\x08\x71\x3d\x00\x92\x5b\x75\x00\x3d\x00\xbc\xe7\x08\x3d\x00\x41\x00\x75\x00\x3b\xb4\x11\x00\x1a\x03\x71\x67\x7a\x00\x52\x00\x41\x00\x11\x00\x23\x18\x90\x00\x28\x00\x52\x00\x7a\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\x26\x01\x00\x00\x75\x00\x80\xb0\x9c\x7a\x00\x52\x00\x41\x00\x41\x00\x2b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xb4\x03\x93\x09\x3d\x75\xcb\xc5\x45\x67\x95\xc6\x08\x11\x92\x75\x02\x0a\x9e\xa7\x1f\x64\x71\xca\x8f\xef\x91\x19\x41\x73\x96\xc7\x10\xb8\x7a\x00\x32\x13\xbb\x74\x52\x00\x78\x8e\x75\x00\x28\x00\x75\x00\x83\x51\x7f\x87\xa7\xcd\xca\x49\x8e\xba\x11\x00\x75\x00\x52\x00\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x7a\x1b\x90\x00\x28\x00\x11\x00\x52\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x51\x00\x00\x00\xaa\x02\x00\x80\x75\x00\x94\x37\x75\x97\x7b\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\xef\x4c\x06\x42\x3d\x00\xae\x4c\x02\x42\x3d\x00\xba\x14\x32\x90\x3d\x00\x32\x65\x02\x42\x3d\x00\x86\x14\x4f\x0c\x3d\x00\x7b\x16\x7f\x96\x3d\x00\x47\x5b\x75\x00\x28\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xe0\x15\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x66\x17\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x61\x09\x20\x00\x90\x5e\x59\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xa0\x13\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x98\x01\x11\x00\xe0\x38\x11\x00\x90\x00\xc9\x0a\x11\x00\xf3\x37\x75\x00\x75\x00\x00\x1f\x72\x70\xdc\xd8\x0c\xb8\x71\x7c\x9f\x18\xe7\x25\x35\xb6\x11\x00\xfe\x28\x90\x00\x11\x00\xdd\x33\x52\x00\xd8\x5c\x90\x00\xe0\x87\x75\x00\x90\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x7b\x16\xab\xbb\x3d\x00\xbc\x5b\x75\x00\x7a\x00\xf8\xba\x3d\x00\xef\x19\xc7\x43\x3d\x00\xd6\x38\x75\x00\x41\x00\x39\xb8\x3d\x00\x08\x00\x75\x00\x28\x00\x39\xb8\x3d\x00\xda\x00\x75\x00\x11\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x9a\xec\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x27\xf0\x4d\x02\x7f\x7b\x59\xf6\x7c\xc7\xfe\x41\x01\x20\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x20\x23\x3d\x00\x3d\x00\x12\x02\x11\x00\x66\x61\x7a\x00\x3d\x00\xfc\xa1\x27\x1c\x50\x0e\xc5\x2e\x8f\xa7\x3f\x6c\xc0\x33\x97\x01\x52\x00\xcd\x4d\x11\x00\x05\xf7\x3d\x00\x00\x00\x28\x00\x46\xbb\x3d\x00\x50\x00\x52\x00\xb6\xba\x3d\x00\x41\x00\x11\x00\xd5\x58\x3d\x00\xa8\x38\x52\x00\x90\x00\x00\x59\x3d\x00\x8f\x83\x64\x77\x75\x00\x28\x00\x3d\x00\x04\x05\x08\x3d\x00\x85\xb5\x06\x3d\x36\x4a\xca\x68\x98\x40\xef\xa5\x42\x2c\x52\x00\x44\xc1\x18\x99\x00\x8a\xfa\x26\x57\xcf\x44\x68\x74\xee\xf8\xde\x79\xf6\x32\xf9\x6e\x85\xb7\x87\x7c\x20\xa6\x4c\x54\xcd\xc7\x43\x3d\x00\xed\x38\x75\x00\x28\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x52\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x11\x00\xf8\xba\x3d\x00\xb6\x69\x02\x42\x3d\x00\x7b\x16\xc7\x72\x3d\x00\x8d\x5b\x75\x00\x90\x00\xf8\xba\x3d\x00\x7c\xc9\x06\x42\x3d\x00\x56\xb8\xc7\x43\x3d\x00\x47\x38\x75\x00\x28\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x11\x00\x73\x82\x90\x00\x28\x00\x7a\x00\x41\x00\x11\x00\x90\x00\x28\x00\x52\x00\xfd\x9f\x42\xff\x41\x01\x20\x00\xb0\x4b\x59\x00\x3d\x00\x51\x00\xac\x02\x7a\x00\x11\x00\xd5\x58\x3d\x00\x34\xfb\x90\x00\x41\x00\x1e\x5b\x3d\x00\x0c\xfe\xed\xb3\x22\xd9\x3d\x00\x90\x00\x11\x00\xd5\x58\x3d\x00\x2f\x89\x52\x00\x41\x00\xd5\x58\x3d\x00\x18\x6b\x7a\x00\x11\x00\x1e\x5b\x3d\x00\xfe\x8c\xbe\x25\x91\xd8\x3d\x00\x11\x00\x90\x00\x00\x59\x3d\x00\x9d\xfc\x70\x57\x75\x00\x52\x00\x3d\x00\xcc\x25\x08\x3d\x00\x99\xc3\x75\x00\x28\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x90\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x7a\x00\xc4\xba\x3d\x00\x86\x14\x2e\x8c\x3d\x00\x7b\x16\x11\x51\x3d\x00\x12\x5c\x75\x00\x28\x00\xc4\xba\x3d\x00\xba\x14\xb1\x97\x3d\x00\xfd\xa5\xc7\x43\x3d\x00\x47\x38\x75\x00\x52\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x72\x50\x90\x00\x28\x00\x90\x00\x11\x00\x11\x00\x41\x00\x28\x00\x52\x00\x00\x4d\x90\x5e\x59\x00\x20\x00\x6b\xc9\x68\x68\x58\xf0\x41\x01'

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
