#!/usr/bin/python3

import sys
import TVM

def FNC1(state, log):
	eip = state.reg4[TVM.R_EIP]
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


state = TVM.VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\x12\x02\x3d\x00\x8a\x50\x70\xff\x40\x56\x50\x3f\x00\x3e\xa4\x0b\xc7\x34\xf7\x3b\x28\x00\x3d\x00\x40\xc7\x68\x00\xa4\x1f\x69\x15\x23\xa4\xab\x12\xc4\x9b\xe5\x5b\x52\x00\xf4\x4d\x7a\x00\x18\x19\x3d\x00\x3d\x00\xf5\x04\x90\x00\xa8\x3a\x7a\x00\xee\x98\x56\xf5\x3d\x00\x3d\x00\xac\x02\x7a\x00\x81\x00\x52\x00\x11\x00\x11\x00\x3b\x58\x3d\x00\x4f\x46\x3d\x00\x46\xe9\x0b\x25\xa6\xc1\xf6\x3e\xd0\xf3\x7b\x68\xed\xca\x91\x11\x90\x00\x0d\x49\x75\x00\x3d\x00\xb0\xf7\x08\x3d\x00\x75\x00\xca\xec\x7a\x00\xff\x11\x42\x91\x8f\x82\x22\xef\x66\x2b\x7a\xb3\xb3\x7f\xd3\xee\x92\xc4\x4e\x77\x41\x00\xe3\x41\x00\x18\xb1\x0b\x2e\x41\x00\x11\x00\x5b\x8a\xa6\xba\x53\x50\x6d\x03\xc3\x12\x75\x00\xc6\x15\x70\xbe\x3e\xba\x53\x8e\x69\xa8\xf6\xbb\xc0\x49\x4a\x1b\x1f\x0b\xef\x2b\x67\x62\xba\x10\x65\x3b\x02\xe3\x3d\x00\x91\xab\x02\xf3\x3e\x1d\x52\x00\x75\x00\x29\xc9\xd1\x33\xc4\xe7\x72\x02\x72\x9a\x67\x3a\xc7\x4f\x6f\xec\xe6\xbf\xab\x39\xe7\x61\x75\xc6\xa5\x62\x75\x00\x7a\x00\xc4\xba\xee\xb2\x08\x11\x5c\x65\x3d\x00\xdb\xdc\x75\x00\x11\x00\x3d\x00\x75\x00\x83\xda\x1a\x98\x85\x7c\xd6\x38\x75\x00\x90\x00\xf8\xba\x3d\x00\x79\x97\x02\x42\x3d\x00\x7b\x84\xda\x0c\x11\x00\xcd\x5c\x75\x00\x00\x00\x00\x00\x3d\x00\xda\x89\xf0\x0a\x11\x00\xc4\xba\xcc\xf7\x06\x00\x7d\xc7\x3d\x00\x7a\x00\x52\x00\x41\x08\x10\x43\x11\xdf\x90\x00\x28\x00\x41\x00\x90\x00\x11\x00\x7a\x00\x28\x00\x52\x00\x25\xc2\x22\x09\x04\x01\x20\x00\x00\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\x83\x34\x70\xff\x26\xb0\xd4\x0c\x27\x0c\x42\x09\x00\xf5\xa7\x09\x11\x00\x3d\x00\x12\x02\x52\x00\xf7\x71\x41\x00\x3d\x00\x81\xc3\xf8\xe1\x11\xb3\xcc\x56\x0e\x3e\xf8\x16\xf1\x88\x9f\x69\x28\x00\x3d\x00\x04\x9e\xf7\x53\x45\x41\xe9\x44\xf5\x6b\x5d\x76\x92\x5a\xe6\x6f\x28\x00\xf2\x2d\x0d\x11\x11\x00\x9e\xe1\x11\x00\xd7\xff\x41\x00\x56\x06\x3d\x00\xa6\x64\x09\x11\xd5\x58\x3d\x00\xc1\x52\x98\xc1\x80\x7c\x00\x59\x3d\x00\x53\x9e\x64\x77\x75\x00\x52\x00\x3d\x00\xb8\xc4\x0d\x11\x00\x1f\x16\x82\x7f\x3d\x00\xce\x4f\xb6\x1a\xa4\x2c\x55\xe5\x91\x0d\xac\x82\x13\x0c\x46\xc8\x5f\x63\x50\xd9\x90\x7c\xf6\xbd\x16\x67\xe3\xf9\x7c\x20\x88\xbb\xc8\x5f\x06\x42\x3d\x00\xb7\x5f\xc7\x43\x3d\x00\x3d\x38\x75\x00\x11\x00\x2e\xb9\xcc\x76\x0d\x11\x75\x00\x28\x00\x3d\x00\x75\x00\xba\x14\x3f\x19\x3d\x00\x8e\x69\x06\x42\x3d\x00\x14\x68\xe9\x12\x0d\x11\xbf\x38\x75\x00\x11\x00\xf8\xba\x3d\x00\xe9\x86\xc7\x43\x3d\x00\xac\x38\x75\x00\x41\x00\x39\xb8\x3d\x00\x83\x00\x75\x00\x7a\x45\x84\x6b\x0a\x00\x90\x4a\x06\x11\x41\x00\x6a\x12\x81\x7c\x90\x00\x11\x00\x52\x00\x7a\x00\x11\x00\x41\x00\x28\x00\x90\x00\x20\x15\x31\x09\x04\x01\x20\x00\x11\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\xac\x02\x11\x00\x0f\x4d\x11\x00\x7a\x00\x41\x00\xd5\x58\x3d\x00\xc2\xf9\x11\x00\x7a\x00\xd5\x58\x3d\x00\x15\xb5\x41\x00\x52\x00\x3b\x58\x3d\x00\xa4\xfe\x3d\x00\x08\x9c\xa4\xfb\x16\x0a\xbe\x76\x96\xab\xc5\x52\xbf\x50\x5b\x15\x11\x00\x1d\x4d\x41\x00\x7e\xc4\x3d\x00\x32\x08\x58\x6f\x3d\x00\x44\x93\x90\x00\xb4\x2e\x3d\x00\xaa\xcc\x75\x00\x3d\x00\x84\x70\x08\x3d\x00\x28\x00\x75\x00\x08\x19\x90\x00\xcf\xf8\xdd\x7f\x7a\x00\x52\x00\x41\x00\x11\x00\x3f\xeb\x90\x00\x90\x00\x7a\x00\x52\x00\x11\x00\x41\x00\x28\x00\x28\x00\x51\x00\x00\x00\xed\x00\x00\x00\x75\x00\x04\x43\xf5\x21\x0b\x90\x00\x73\xca\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x1b\x18\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7e\x01\x49\x04\x10\xc8\x75\x00\x88\xc7\x12\x73\x52\x00\xfb\x0d\xf0\x66\xde\x70\x1e\x4f\x47\x36\x59\xc9\xf6\x01\xbe\x0e\x97\x15\x85\x65\xb3\x58\x3b\x38\xe3\xaf\xd5\x62\x75\x00\x28\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\x13\xa2\x02\x42\x3d\x00\xba\x14\xf4\xd0\x3d\x00\x7c\xe7\x02\x42\x3d\x00\xba\x14\xf8\x4a\x3d\x00\x67\x81\xc7\x43\x3d\x00\xc7\x38\x75\x00\x52\x00\xc4\xba\x3d\x00\x6a\x17\xc9\x17\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xf1\x8c\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x77\x8e\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x52\x94\x00\x00\x20\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x80\x8e\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xfc\x02\x75\x00\x7e\xff\x11\x00\x7e\xff\x8e\x07\x80\x77\xf6\x12\x71\x39\x5a\xc6\x7b\x8d\xdd\x50\xfb\x10\xc5\xc1\xbc\x18\xa4\xed\x64\x62\x3d\x00\x50\x49\xce\xb1\x60\x46\xec\x21\x20\x85\x30\x47\x03\xc8\x9b\x3d\x52\x00\x90\x00\x1b\xdb\x28\x00\x90\x00\xe0\x32\x41\x00\xbf\xfc\x75\x00\x75\x00\xd9\xf2\x25\x47\x71\xf7\xda\x91\x5b\x0b\x4b\x03\xb0\x7d\x46\x2a\x91\x76\xf5\x97\x09\xda\xd0\xd8\x45\x22\x37\xf5\x75\x00\x7a\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\x6c\x17\xc3\x70\x3d\x00\xd7\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\xba\x14\x55\x4d\x3d\x00\x50\xac\x06\x42\x3d\x00\xe0\x6b\xc7\x43\x3d\x00\xd6\x38\x75\x00\x52\x00\x39\xb8\x3d\x00\x08\x00\x75\x00\x7a\x00\xf8\xba\x3d\x00\xe7\x37\x06\x42\x3d\x00\x0f\xff\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xe1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x6c\xfb\x40\x09\x04\x01\x20\x00\x11\x00\x3d\x00\x51\x00\xac\x02\x28\x00\x52\x00\x65\x59\x3d\x00\x34\xfb\x38\xb6\x41\x00\xb6\xba\x3d\x00\x28\x00\x28\x00\x65\x59\x3d\x00\xc2\xb0\x02\xb6\x7a\x00\x01\xbc\x3d\x00\x3d\x00\xf5\x04\x28\x00\x21\xa0\x41\x00\x88\xf8\xf1\xf4\x3d\x00\x3d\x00\xf5\x04\x52\x00\xb1\x5f\x7a\x00\x4d\x64\x0b\x6c\x3d\x00\x97\x50\x75\x00\x3d\x00\x9f\xed\x08\x3d\x00\xeb\x18\x75\x00\x58\x77\xeb\x60\xdf\xe9\x91\x48\x7a\x00\x52\x00\x41\x00\x28\x00\xa1\x65\x90\x00\x7a\x00\x11\x00\x52\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\x15\x02\x00\x80\x75\x00\x80\xc5\x9d\x27\xdd\xf6\xa5\xb2\xa9\x9b\xfe\x55\x23\x0c\xc9\xf4\x1d\xfd\x0b\xfa\xc0\xeb\x27\xfa\x3b\x24\xec\x32\xc9\xfa\x71\x38\xef\x8a\xc7\xed\xe6\x54\xff\x01\xe9\x9b\x84\x6a\x1c\x3f\x43\x69\x9a\x5d\x8d\x9a\x1a\xc8\xfc\x99\x22\x11\x00\x7c\xce\x11\x00\xfe\x83\xd6\x28\xdb\xdf\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xb1\xb6\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xc3\x02\x00\x00\x75\x00\x04\x0d\xa9\x75\x00\x59\xc9\x90\x00\x69\x56\x1d\x16\x42\x64\xe0\x16\xf3\xc6\xdb\xb3\x4a\xff\xd3\x14\x00\xa3\x09\xf1\x82\xac\xee\x49\xce\x14\xa2\x9b\x05\x74\xef\xfb\xcd\x80\x08\x30\xe8\x46\xfc\x42\x41\x3d\x00\xfe\x08\xcc\xff\xd8\xd1\x1a\xbb\xbb\x28\x38\x64\xd9\xba\xf5\x2e\xb3\x3c\x81\x78\x91\xdd\x2a\xd8\x3d\x00\x00\xa9\x98\xa2\x09\x23\x87\x65\xd7\x7a\x07\xbb\xe1\xb7\x3f\x00\xd6\x48\xdc\xb4\x71\x80\x02\x2f\x93\xb8\xab\xee\xd5\x62\x75\x00\x28\x00\xc4\xba\x3d\x00\x6c\x17\x98\x60\x3d\x00\x9c\xde\x75\x00\x11\x00\x3d\x00\x75\x00\xfd\x5b\x75\x00\x7a\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x41\x00\x39\xb8\x3d\x00\x31\x00\x75\x00\x90\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x41\x00\xc4\xba\x3d\x00\xba\x14\xe6\x65\x3d\x00\x05\xaa\x06\x42\x3d\x00\x95\x65\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x01\xe1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x41\xfc\x4f\x09\x04\x01\x20\x00\x00\x00\x3d\x00\x51\x00\xac\x02\x41\x00\x7a\x00\x65\x59\x3d\x00\x34\xfb\x42\xb6\x52\x00\x46\xbb\x3d\x00\xaa\x00\x7a\x00\xd9\xb9\x3d\x00\x3d\x00\x3c\x03\x28\x00\x5a\x9d\x52\x00\xbd\xff\x11\x00\xe6\x1f\x3d\x00\x3d\x00\x97\x56\x43\xe8\xc8\x77\xf4\x1c\xc4\x32\x19\x0d\x90\x24\xb9\x09\x28\x00\x3d\x00\x11\xa9\xb4\xa4\x8b\x0e\xf1\x37\x9a\xed\xc3\x74\xcb\x34\xd9\x71\x28\x00\x3d\x00\xe8\x57\xf1\xa4\xf6\x32\x29\x52\xc5\x73\x91\x74\x08\x1a\xc4\x66\x28\x00\xa5\xf3\x75\x00\x3d\x00\x78\x4f\x08\x3d\x00\x3a\x8f\x48\xe7\x6f\xf3\x60\xed\xd0\x12\x50\x49\x5f\xcb\x69\x50\x97\x4b\x6b\x97\xd0\xbd\x75\x00\x8d\xd6\x41\x00\x32\x76\xcd\xe1\x86\x14\x35\x87\x3d\x00\x86\x14\x7e\xf6\x3d\x00\x6c\x17\x71\xf6\x3d\x00\xd7\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x7b\x16\x5f\x3f\x3d\x00\x96\x5b\x75\x00\x41\x00\xc4\xba\x3d\x00\x7b\x16\x6e\x63\x3d\x00\x62\x5c\x75\x00\x11\x00\xf8\xba\x3d\x00\x41\xd9\xc7\x43\x3d\x00\xed\x38\x75\x00\x90\x00\xc4\xba\x3d\x00\x6a\x17\x85\xbd\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x51\x5f\x90\x00\x52\x00\x11\x00\x41\x00\x11\x00\x28\x00\x28\x00\x90\x00\x85\x45\x5e\x09\x04\x01\x20\x00\x11\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\x3c\x03\x28\x00\x0f\x4d\x52\x00\xfd\xff\x28\x00\x0d\x6d\x3d\x00\x3d\x00\x10\x06\xc1\x1c\xfa\xda\x69\x1d\x1f\x1f\xbd\x77\x5c\xa4\x7e\x73\x28\x00\xa6\x4d\x52\x00\x7e\x5c\x3d\x00\x75\xce\x83\x70\x3d\x00\xf1\x4c\xbc\x71\x3d\x00\x16\x93\x90\x00\xc6\x2b\x3d\x00\x39\x00\x52\x00\x50\xbd\x3d\x00\xee\xcc\x75\x00\x3d\x00\x5e\x71\x08\x3d\x00\xd5\xaa\x3e\xed\xc9\x08\xe8\x7f\x75\x00\x4d\xf3\x7a\x00\x52\x00\x41\x00\x41\x00\x0e\x19\x90\x00\x52\x00\x11\x00\x7a\x00\x11\x00\x28\x00\x28\x00\x90\x00\x51\x00\x00\x00\xfc\x04\x00\x80\x75\x00\x80\x11\x7f\x39\x5c\xf8\xa5\x8a\x58\x36\xfe\x58\x65\xb5\x6f\x5c\xfe\x9b\x44\x48\x42\xcf\x18\x4c\xed\x84\x26\xea\xca\x56\xd8\x02\xee\x2a\xf7\x7a\x00\x52\x00\x41\x00\x41\x00\xdf\x6f\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa6\x03\x0a\x6a\x28\x80\x00\x00\x29\x48\xe3\x4b\xbc\x05\x11\xe8\x62\x5f\x04\x3d\x07\x17\x00\x72\xab\x00\xe2\x45\x52\x00\xaa\x7a\x00\xd7\x9d\x7a\x00\xe6\xa9\xa8\x2a\xf3\xc5\x75\x00\x5b\xb1\x42\x41\x3d\x00\xc4\x70\x48\xe7\xa7\x8f\x5a\x21\x32\x7b\x30\xc2\xb7\xf3\x9a\xce\x18\x68\x1d\x71\xaf\x2f\xfc\x76\x3d\x00\x26\x74\xf7\xea\x38\x30\x75\x00\x9d\x08\x11\x00\x4a\xf3\x85\xac\x8e\x6f\x00\x8d\xc8\x66\x4c\x3c\x1c\x40\x0f\xed\x2f\x1b\xda\x61\x7c\xf2\xc7\x43\x3d\x00\x3f\x38\x75\x00\x41\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\xfe\x1b\xc7\x43\x3d\x00\x86\x38\x75\x00\x28\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x52\x00\xc4\xba\x3d\x00\x7b\x16\x0b\x8d\x3d\x00\x8b\x5c\x75\x00\x28\x00\xf8\xba\x3d\x00\xbd\x95\x02\x42\x3d\x00\x6a\x17\xcb\x46\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xd5\x9d\x90\x00\x28\x00\x11\x00\x52\x00\x11\x00\x7a\x00\x28\x00\x90\x00\x95\x80\x6d\x09\x04\x01\x20\x00\x00\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\xd0\xd2\x70\xff\x13\xec\x79\x79\xc3\x25\x1b\x57\x87\x39\x97\x43\x52\x00\x3d\x00\x30\x2d\x68\x00\xe2\xeb\x0e\x6d\x2e\xc2\x30\x4e\xcd\x06\x51\x2f\x90\x00\x3d\x00\x4d\xed\xa6\xff\x2a\x02\x0f\x64\x08\x83\x10\x76\x00\x3b\xea\x02\x28\x00\xa6\x4d\x52\x00\x86\x32\x3d\x00\x00\x00\x52\x00\xb6\xba\x3d\x00\x41\x00\x7a\x00\xd5\x58\x3d\x00\x96\x25\x90\x00\x52\x00\x65\x59\x3d\x00\x2e\x71\x7b\xb6\x90\x00\x61\xba\x3d\x00\x27\x77\x75\x00\x28\x00\x3d\x00\xd4\x07\x08\x3d\x00\x28\x00\x56\x39\x11\x00\x21\xa8\x09\x11\x28\x00\x34\xbf\x75\x00\x75\x00\xe1\x4f\x54\x6c\x99\xd3\xb4\xa8\x50\x4e\x78\x34\x78\x04\x98\x04\x01\x81\x6e\xa4\xd9\xe8\xca\x21\x47\x75\x86\x14\xde\x89\x3d\x00\x7b\x16\xf1\x98\x3d\x00\xfd\x5b\x75\x00\x28\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x52\x00\xc4\xba\x3d\x00\x7b\x16\x16\xf4\x3d\x00\xc5\x5c\x75\x00\x90\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x28\x00\x39\xb8\x3d\x00\xc1\x00\x75\x00\x90\x00\xc4\xba\x3d\x00\xba\x14\xe6\x64\x3d\x00\x97\xe9\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x13\xf9\x90\x00\x52\x00\x11\x00\x41\x00\x11\x00\x90\x00\x28\x00\x28\x00\x1e\xe6\x7c\x09\x04\x01\x20\x00\x11\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x28\x00\x3b\xc0\x3d\x00\x49\x22\x46\x6e\x3d\x00\x3d\x00\x3c\x03\x11\x00\xa8\x5a\x41\x00\xc7\xff\x11\x00\xfa\x00\x3d\x00\x3d\x00\xb2\x65\xce\xd3\x4d\x57\x7c\x5d\x00\xa7\x3b\x4e\xf6\xfe\x2a\x50\x11\x00\x52\x00\x11\x00\x65\x59\x3d\x00\x69\x59\xb9\xb6\x7a\x00\x8b\xbe\x3d\x00\xdb\xc2\x67\x70\x3d\x00\x73\x5b\x75\x00\x3d\x00\x6a\xe7\x08\x3d\x00\x90\x00\x9e\x5f\x90\x00\x28\x00\xba\x4b\x90\x00\xc2\x9e\x75\x00\x75\x00\xf4\x37\x59\x6f\xaf\x50\x42\x91\x84\x79\x74\xee\xec\xe9\x05\x90\x99\x2a\x81\x7c\x0a\x15\x0e\x11\xe5\x40\x3a\x16\xa8\x09\x11\x89\x30\xcd\x2d\x12\xe4\x05\xb5\x70\x49\x82\xa6\x16\x45\x27\x25\x94\x9a\x58\xc2\x00\xca\x44\x75\x00\x94\x7b\x52\x00\xc8\x5e\x89\x62\x8a\xb9\x94\xdc\xe5\x39\xa1\x2e\x76\x58\x0f\xef\x6f\x82\x4e\xef\x02\x58\xd7\xb1\x74\xfb\x7a\x00\x41\x00\x09\x5f\x7a\x5a\xf5\x75\x00\x90\x00\x90\x00\x75\x00\x93\xdc\x8a\x0b\x3d\x0b\xa7\x43\x13\x5e\x70\x75\x00\x52\x00\x75\x00\x11\x00\xa8\x1c\x43\x48\xc4\x72\x75\x00\x90\x00\xa1\xba\xe3\xff\x52\x00\x0e\x79\x75\x00\x90\x00\x75\x00\xb1\x5e\xf4\x1b\xa3\x6d\x75\x00\xcf\x38\x90\x00\x75\x00\xff\xe4\x11\x00\xa0\xb3\xef\x94\x24\x87\xa4\x1b\x51\x5c\xfb\x11\x1b\x45\x4c\xed\x76\x5d\x66\xe4\x1c\xfb\x10\xed\x32\xd0\x9b\x24\x98\x0f\x75\x00\xa3\x00\x39\x0d\x52\x00\x16\x71\x75\x00\x95\x96\x64\x1b\x2c\x38\xb0\x96\x7a\x00\x52\x00\x41\x00\x90\x00\x8b\x9b\xe0\x73\x2f\x00\x7a\x00\x41\x00\x11\x00\x11\x00\x28\x00\x28\x00\x51\x00\x00\x00\xcf\x05\x00\x00\x75\x00\x80\x11\x7f\xdf\x60\x81\xa5\xe6\xa9\x3f\x62\xc8\x47\x3c\x34\xd9\x7c\xab\xc9\x13\xfc\x34\x7b\x5d\x44\xf8\x4b\x84\xac\x5a\xbf\xd2\x09\x28\x00\x8e\x28\x00\x86\x83\xf3\xc2\x75\x00\xd6\x12\x40\xb1\x11\x00\xdb\x5b\x6b\x43\x3d\x00\xbf\xae\xd3\xa6\x8e\xa2\x6d\xa5\x9b\x35\x29\x07\x9f\x59\x3e\x21\xfd\xe8\x47\x7c\xba\xeb\xc1\x46\xc4\x78\x3d\x00\xff\x7d\xd1\xab\xbf\x08\x41\x00\x75\x00\x16\xd1\xfc\x63\xc4\xff\x24\xc9\x13\xea\x7b\x64\xc5\xc3\x1b\x42\xc1\xae\x9b\x66\xb0\xbc\xff\x0a\x9b\x5c\xc7\x43\x3d\x00\x3f\x38\x75\x00\x41\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\x86\x14\x13\xb8\x3d\x00\x86\x14\x2c\x25\x3d\x00\x7b\x16\x8c\xdb\x3d\x00\x94\x5c\x75\x00\x7a\x00\xc4\xba\x3d\x00\xba\x14\x9a\xc2\x3d\x00\xd5\x35\x02\x42\x3d\x00\x6a\x17\xd3\xfd\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x15\x15\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x16\x0b\x8b\x09\x04\x01\x20\x00\x00\x00\x3d\x00\x51\x00\xac\x02\x41\x00\x41\x00\x1e\x5b\x3d\x00\x34\xfb\x33\xb4\x8d\xda\x3d\x00\xe6\x00\x72\xd5\x3d\x00\xf8\x8e\xfe\xd6\x3d\x00\x11\x00\x11\x00\x65\x59\x3d\x00\x05\x8b\xc1\xb6\x7a\x00\xd7\x9a\x3d\x00\x3d\x00\xcf\x01\x7a\x00\x42\x09\x52\x00\x3d\x00\xd7\x02\x11\x00\x9c\x8c\x90\x00\x79\x13\x75\x00\x7a\x00\x3d\x00\x19\x61\x08\x3d\x00\x48\x3a\x91\x97\x7e\xa1\x79\xb1\x69\x58\x90\x1f\x8b\xa7\xc4\xa3\x0f\x20\x7d\x0c\x91\x46\x98\x28\xc1\x62\xff\xd7\xba\x07\x15\xef\xd3\x41\xf2\x31\x7b\x52\x4f\x37\x91\x0b\x39\xea\x90\x00\xbf\x2b\xf0\x61\x84\x71\xc8\x6e\x88\xee\x0a\x20\xc5\x51\x4a\x0c\x74\x17\x73\x40\x49\xd5\x98\x71\xc2\xb8\xeb\x1a\x0e\x6f\x52\x00\xeb\xff\x20\xee\xbb\x6f\xd0\x1c\xc6\xfe\xde\xc7\xca\xff\x3c\xf1\x7b\x01\x96\xab\x73\x12\x4a\xef\x29\xc2\x59\xf8\x02\x32\x52\x00\xde\x07\xfa\x9d\xaf\x34\xc4\x54\x04\xe7\xfa\x57\xe1\x35\x04\x7b\x44\xe2\x7e\xf0\x6c\xa9\xbc\x62\x25\x2a\xd5\xcd\x75\x00\x9c\x01\xfb\x91\x49\x75\x00\x52\x00\x52\x00\xba\x14\xb2\x92\x3d\x00\x04\xbd\x02\x42\x3d\x00\x6c\x17\x06\x34\x3d\x00\xd7\xdc\x75\x00\x11\x00\x3d\x00\x75\x00\x86\x14\xee\x5e\x3d\x00\xba\x14\xa6\xa0\x3d\x00\xb7\x65\x06\x42\x3d\x00\xee\x63\xc7\x43\x3d\x00\xcd\x38\x75\x00\x28\x00\xf8\xba\x3d\x00\x9d\x1e\xc7\x43\x3d\x00\x06\x38\x75\x00\x7a\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xbb\xf9\x90\x00\x28\x00\x90\x00\x52\x00\x11\x00\x7a\x00\x28\x00\x11\x00\xd4\xe3\x9a\x09\x04\x01\x20\x00\x7a\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\xcf\x01\x7a\x00\x0f\x4d\x7a\x00\x3d\x00\xf5\x04\x52\x00\xbe\x9d\x28\x00\x74\x2c\x55\x43\x3d\x00\x85\x93\x52\x00\xa7\x01\x3d\x00\x00\x00\x52\x00\x6a\xbe\x3d\x00\x3b\x00\x52\x00\xfd\xbc\x3d\x00\x3d\x00\x3c\x03\x41\x00\xe4\x66\x28\x00\xed\xff\x41\x00\x6c\x20\x3d\x00\x22\x75\x75\x00\x90\x00\x3d\x00\xe6\x05\x08\x3d\x00\x41\x00\x75\x00\xa3\x07\x90\x00\xb1\x6d\x69\x60\x7a\x00\x52\x00\x41\x00\x28\x00\xa8\x71\x90\x00\x52\x00\x11\x00\x7a\x00\x11\x00\x90\x00\x28\x00\x41\x00\x51\x00\x00\x00\x62\x02\x00\x00\x75\x00\x80\xa1\x9d\x2b\x7e\x75\x00\x52\x00\x5d\xb8\x3d\x00\x6c\x51\xb4\x85\xb3\x8f\xfa\x22\x3f\x00\x21\x5d\x06\x31\x12\xc8\xbb\xd5\xba\xf3\xe4\x16\x95\xea\x28\x81\x86\xa9\x13\xbd\x18\x22\x24\x7a\x00\x43\x84\x44\x9c\x9f\xb9\x75\x00\xc6\x15\x10\x45\x3d\x00\xdc\xb9\x88\x1f\x03\xce\x88\xd6\xa6\x2f\x30\x18\x54\x3a\xef\x26\x94\x3c\x3e\x24\x38\x54\x22\x74\x3d\x00\x1a\x50\xed\x0e\x70\x32\x8f\xc9\x2f\xdf\xe7\xfe\xd4\x23\x38\x4f\xc4\xc6\x49\xe9\xbc\xa4\x79\x1d\x50\xb5\xc8\xd4\x7b\x16\xdb\x8c\x3d\x00\xfd\x5b\x75\x00\x11\x00\x2e\xb9\x3d\x00\x9c\xde\x75\x00\x90\x00\x3d\x00\x75\x00\x00\x00\x75\x00\x52\x00\xf8\xba\x3d\x00\x85\x1d\x02\x42\x3d\x00\xba\x14\xdd\x1d\x3d\x00\x34\x6d\xc7\x43\x3d\x00\xe5\x38\x75\x00\x11\x00\xf8\xba\x3d\x00\x61\x8b\x06\x42\x3d\x00\x97\x7a\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xe1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x00\xff\xa9\x09\x04\x01\x20\x00\x00\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x63\x23\x3d\x00\x3d\x00\x11\x64\xc7\xaf\xd8\x77\xb5\x11\x40\x2b\xac\x38\x4c\x37\x3b\x6a\x52\x00\x3d\x00\xac\x02\x90\x00\xd9\x43\x52\x00\x28\x00\x52\x00\x1e\x5b\x3d\x00\x38\x85\x58\x21\xea\x96\x3d\x00\x3d\x00\xd8\x3e\xb7\xdd\x41\x51\x09\x2b\x93\x7f\x00\x41\x5c\x1e\xfb\x3c\x11\x00\x3d\x00\x3c\x03\x7a\x00\x3f\x71\x28\x00\xbe\xff\x28\x00\x22\xa6\x3d\x00\x60\x77\x75\x00\x41\x00\x3d\x00\x00\x05\x08\x3d\x00\xfb\x23\x77\x74\x56\x80\x2b\x33\xdc\x68\x3d\x00\xd6\x22\x01\x69\xde\xd1\xd8\x6e\x55\x56\x68\x1d\xb9\x92\xe4\x5e\x52\x00\x3f\x38\x75\x00\x28\x00\xf8\xba\x3d\x00\xeb\x67\xc7\x43\x3d\x00\x3f\x38\x75\x00\x52\x00\x2e\xb9\x3d\x00\xd7\xdc\x75\x00\x7a\x00\x3d\x00\x75\x00\xba\x14\x5f\x94\x3d\x00\xe4\x28\xc7\x43\x3d\x00\xce\x38\x75\x00\x90\x00\xf8\xba\x3d\x00\x01\x07\x06\x42\x3d\x00\xa5\xfe\x02\x42\x3d\x00\x86\x14\x89\x40\x3d\x00\x6a\x17\xa5\x5d\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xe1\x90\x00\x52\x00\x11\x00\x28\x00\x11\x00\x90\x00\x28\x00\x7a\x00\x8c\xfe\xb8\x09\x04\x01\x20\x00\x7a\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x52\x00\x15\xbd\x3d\x00\x3d\x00\xac\x02\x28\x00\x5c\x9b\x11\x00\x52\x00\x41\x00\x1e\x5b\x3d\x00\x4c\xab\x7f\xb4\xf8\xcf\x3d\x00\x52\x00\x28\x00\xd5\x58\x3d\x00\xef\x83\x90\x00\x11\x00\xf8\x57\x3d\x00\x66\x6c\x3d\x00\xf5\x04\x7a\x00\x34\x3a\x52\x00\x6c\x6a\x82\x48\x3d\x00\x31\xcd\x75\x00\x11\x00\x3d\x00\xfa\xbc\x08\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\xfa\xd5\x90\x00\x90\x00\x7a\x00\x52\x00\x11\x00\x41\x00\x28\x00\x11\x00\xdc\x00\xfe\xea\xc6\xe6\x67\x73\xf6\x65\xf7\x74\x0e\x75\x05\xd4\x67\x7b\x4b\xec\xea\xf7\xfb\xc2\x6d\x5e\xd5\xff\xc2\x2e\xf0\x63\x28\x00\x67\xde\xb4\xff\xa0\x40\x52\x00\x8e\xd7\x41\x00\x52\x00\x3b\x6c\x90\x00\xc1\x35\x75\x00\x75\x00\x9e\xec\x18\x23\x99\xee\xaa\x1f\xc3\x33\x25\x2a\x28\xe2\x20\x3a\xbd\xbf\xc7\x70\x3a\x39\xdf\x1e\x90\x00\x28\x00\x75\x00\x84\x7d\x00\x5d\x90\x00\x45\xae\xac\x9d\x8d\xdf\x4a\x0f\xd5\x30\x3d\x13\x0d\x28\x2b\xd8\xa0\xd7\xd9\x3e\xc3\x7b\x8e\xd9\xef\xae\xc8\xbe\x75\x5d\x8d\xb4\x37\x27\x28\x00\x28\x00\x75\x00\x91\x4a\x51\x60\x7a\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xfb\xf5\x90\x00\x7a\x00\x11\x00\x28\x00\x11\x00\x52\x00\x28\x00\x90\x00\x98\x01\x28\x00\xe0\x38\x28\x00\x41\x00\x8b\x0a\x7a\x00\xf3\x37\x75\x00\x75\x00\xd7\xd2\x53\x4a\x5b\x5e\xda\x40\xa5\x3b\xb8\xee\x18\x1f\x2e\x44\x3d\x89\x14\x1d\x09\x6d\x10\xd8\x97\x24\xf0\xc3\x68\x1f\x87\x01\xe8\x61\x11\x00\x75\x00\x11\x00\x40\x17\x9f\xb0\xdf\x0c\xfe\xfb\x75\x00\x79\x06\x82\x47\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x1a\x70\x06\x42\x3d\x00\xd9\x6f\x06\x42\x3d\x00\xe9\xff\x06\x42\x3d\x00\x6d\xff\x06\x42\x3d\x00\xb7\xff\xc7\x43\x3d\x00\xdc\x38\x75\x00\x90\x00\xc4\xba\x3d\x00\x6a\x17\xc3\x59\x3d\x00\x7a\x00\x52\x00\x41\x00\x28\x00\xd1\x0d\x90\x00\x41\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x57\x0f\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xc0\x12\x11\x00\x20\x00\x7c\x5c\x75\x00\x7a\x00\x2e\xb9\x3d\x00\xdb\xdc\x75\x00\x52\x00\x3d\x00\x75\x00\x4c\x62\x06\x42\x3d\x00\xfe\x39\x06\x42\x3d\x00\xd0\xff\xc7\x43\x3d\x00\xd6\x38\x75\x00\x11\x00\x39\xb8\x3d\x00\x08\x00\x75\x00\x41\x00\x39\xb8\x3d\x00\xda\x00\x75\x00\x7a\x00\xf8\xba\x3d\x00\x3a\x78\x8a\xa6\xba\x53\x7a\x00\x52\x00\x41\x00\x41\x00\x49\x69\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x3b\x74\xe9\x6d\x81\x05\x20\x00\x68\xa8\xf7\x03\x01'
#114127B4
#state.data = b''

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
state.push(0xFCB2A014) #ebp
state.push(0xFF7F0000) #esi
state.push(0xFF8F0000) #edi

state.reg4[TVM.R_EIP] = 0
state.reg4[TVM.R_31] = 0xFCB2A014
state.reg4[TVM.R_ImgBase] = 0x10000000 #imgBase
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

PARSED, ERR = TVM.Parse(state)
for k,v in sorted(PARSED.items()):
	for l in v:
		print(l)
		pass
	print()


for l in ERR:
	print(l)
	pass


