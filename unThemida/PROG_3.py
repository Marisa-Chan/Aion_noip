#!/usr/bin/python3

#105948ed

import sys
import TVM

def FNC(state, log):
	eip = state.reg4[TVM.R_EIP]
	
	log.append("\n\n#OnEnd {:02X}\n\n".format(eip))


state = TVM.VMState()
state.data = b'\x00\x00\x44\x04\x3d\x00\x51\x00\xf5\x04\x6f\x6d\x20\x23\x3d\x00\x3d\x00\x12\x02\x52\x00\x3c\x65\x28\x00\x3d\x00\xa5\xf6\x11\x1c\x98\x85\xe4\x37\x8b\x27\x7d\x03\x27\x74\x4f\x58\x11\x00\x3d\x00\x1b\x7c\x28\xae\xdb\xc8\x18\x4b\x17\xb1\x91\x71\x88\x6a\x6b\x42\x7a\x00\x5e\x4d\x11\x00\xc4\xa2\x3d\x00\x3b\x00\x28\x00\xd9\xb9\x3d\x00\x3d\x00\xac\x02\x7a\x00\x8c\x57\x7a\x00\x52\x00\x28\x00\x00\x59\x3d\x00\xe0\xde\x60\x7f\x75\x00\x41\x00\x3d\x00\x9b\x0f\x08\x3d\x00\x8d\x7c\x69\x42\x3d\x00\x40\x16\x8e\x75\x00\x04\xfc\x75\x00\x61\xff\x03\x95\xcb\xc0\x67\x0e\x11\x00\x61\x5c\x13\x1d\x75\x00\x41\x00\xf3\xce\x41\x00\x7a\x00\x7a\x00\x26\xdf\xd8\xdc\x75\x00\x41\x00\x3d\x00\x75\x00\x75\x00\x33\x25\xa5\xfa\xa7\x40\x12\x9f\xbe\xcf\x75\x00\x3d\x00\xbb\x6b\x90\x00\xe4\xb8\x3d\x00\x24\x4d\xfe\x41\x3d\x00\x52\x00\x53\xce\x41\x00\x52\x00\x65\x0a\x28\x00\xd0\x35\x75\x00\x75\x00\xac\x63\xba\x0f\xc6\xe3\xd1\x0a\x6b\x7a\xf4\x1f\xeb\xee\x80\xa7\x7a\x00\x18\xd9\x52\x00\x95\xce\xbc\xec\x75\x00\x01\xd7\xe6\x17\x6e\x04\x3d\x00\x75\x00\x8a\x57\x52\x00\x11\xe4\x60\x8e\xb1\x6d\x61\xf8\xb4\x00\x74\x87\x96\x2e\xba\xeb\xcd\x6a\x7d\xc8\x3d\x00\x5c\x4b\x68\x3b\x9e\x57\x11\x00\x75\x00\xdb\x83\x3d\x00\x05\xce\xea\xf7\x3f\xd7\x21\x6a\xad\xc7\x00\x79\x37\x77\x59\x66\x52\x00\x3f\x78\xd1\x04\x81\x0f\xcf\xa3\x2e\x1c\x14\xcf\xfe\x13\x34\x2a\x34\x09\x9e\x11\x8b\xec\xc0\x16\x72\xf0\x7a\x00\xd2\x8b\x3d\x00\x28\x00\xdb\x05\x3d\x00\x9c\x02\x11\x00\x6c\x3e\x41\x00\x3d\x00\x4f\x79\xbe\xe4\xa5\xed\x33\x2e\xe0\xc8\xef\x73\xf9\x46\x3d\x00\x99\xf5\x6f\xed\x07\xd9\x99\xf5\x32\xed\x1d\x33\xe9\xc8\xfe\x41\x3d\x00\x7a\x00\x71\x4c\x7a\x00\x28\x00\xf1\x0f\x7a\x00\xe1\x60\x75\x00\x75\x00\x75\x00\x59\xdb\x87\x09\xa9\xf7\x16\xaa\x22\x26\x78\x03\x40\x88\xf7\x58\x31\x4c\x75\x00\x84\x46\x44\xdc\xe0\x55\xbd\xaa\x04\x6e\x05\xf8\x3d\x00\x9c\x02\x11\x00\xfc\x47\x41\x00\x3d\x00\xf0\x5e\xe7\x9b\x10\xef\x83\xcf\x6a\x87\x2a\xd2\x09\xc3\x75\x00\xfc\xdb\xa4\x02\x11\x00\x82\x00\x47\xe7\x38\xe5\x92\xa7\x51\x84\x0b\x9a\xf3\x43\xd6\x74\x73\xfe\xeb\x32\x3e\x26\x6d\x5a\x37\xf0\x8a\x8d\x8d\x3c\x41\x00\xa8\xa1\x41\x00\x11\x00\xaa\xc7\x11\x00\x70\x5f\x90\x00\xe6\x17\xf3\x53\x3d\x00\x75\x00\x85\x3e\x52\x00\x9e\x0e\xa8\x6b\x7a\x00\xed\x13\x72\x02\x11\x00\x4e\x22\x75\x00\x90\x00\x75\x00\x98\xf0\x52\x00\xa6\xaf\x90\x00\x84\x42\x5d\xd3\x75\x00\x6a\x8d\x5d\xfc\xc0\xf7\xf9\xdd\x87\xf3\x49\x00\x3d\x00\x3d\x00\xef\x54\x37\x95\x16\x38\xbf\xc0\x75\x00\xfa\x92\xc3\x0e\x90\x00\x05\x2a\xb9\xde\x75\x00\x3a\xc6\x0d\x82\x52\x00\xd6\x6a\x28\x00\x85\x10\x95\x50\x75\x00\x90\x00\x70\x1b\x52\x00\x7a\x00\x90\x00\x62\xd2\x3d\x00\x06\xe5\x0a\x15\x28\xe3\xe3\x15\x07\x66\xf4\x58\xf2\x39\xda\x18\x7a\x00\xdf\xc3\x7a\x00\x1d\xe9\x6d\x49\x35\x09\x75\x00\xa7\xc3\xfd\xe9\x7a\x00\x52\x00\x41\x00\x41\x00\xa5\x99\x90\x00\x52\x00\x28\x00\x7a\x00\x11\x00\x11\x00\x28\x00\x90\x00\x51\x00\x00\x00\x8f\x00\x00\x00\x75\x00\xa2\x60\x9f\xe6\x28\xe4\x43\x3d\x00\xdd\x48\xde\x41\xd2\xc3\x75\x00\x4f\x55\x98\x2e\x28\x00\x2b\x7b\xf0\x39\x7f\xed\x3d\x00\x3d\x00\x91\x8b\x1b\xc5\xb0\xea\x0f\x1b\x02\xe3\x6a\x41\xf1\x44\xe8\x77\x7a\x00\x1f\xc6\x4f\xb4\x55\x27\x12\x1f\x75\x00\x94\x38\x3d\x00\x70\x02\x28\x00\xc4\x65\x11\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x81\x8b\x90\x00\x11\x00\x28\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x8a\x02\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x40\x8d\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x6f\x03\x7c\xd3\xaa\x57\xc7\x5a\x4d\x34\x90\x00\x75\x00\x90\x00\x75\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x3a\x19\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\xfe\x00\x00\x00\x75\x00\xa2\x38\x79\x4d\x43\x75\x00\x7a\x00\x61\xb9\x3d\x00\x7d\xf9\x3d\x00\x63\x14\x71\x1d\x94\xaa\x2f\xb1\x3d\x00\xe6\x03\x41\x00\x72\x9c\x11\x00\x75\x00\x52\x00\x2d\x32\x99\x5d\x63\x21\x75\x00\x0e\x8a\xe6\xe0\x75\x7e\xa6\xb0\xaf\x1c\x42\xfc\x6e\x8b\x4e\x4c\x03\xad\x28\x00\x7a\x00\x75\x00\x3d\x00\x1c\xdd\x7b\x16\xe4\x84\x3d\x00\x7e\x5b\x75\x00\x7a\x00\xf3\xb8\x3d\x00\xb9\xcb\x55\x00\x79\xab\x27\x06\x75\x54\x09\x01\x75\x00\xe7\x4f\x40\x50\xc9\x88\xe6\x11\x00\x91\xe7\x55\xf1\x5f\x95\x3c\xb7\x8f\x7e\x7a\x00\x41\x00\x75\x00\x40\xf6\x87\xe0\x74\xb4\xd1\xf7\x6a\xa9\x3d\x00\xdc\xfb\xc0\xc8\xc1\x96\x75\x00\x11\x00\xb1\xbc\x52\x00\x28\x00\xec\xcd\x90\x00\x63\x38\x41\x00\xc4\x31\xc6\xbb\xb8\x98\x7f\x28\x41\x00\x52\x00\x75\x00\x3d\x00\xd0\x0e\x7a\x00\x52\x00\x41\x00\x41\x00\x54\xa5\x90\x00\x52\x00\x7a\x00\x28\x00\x11\x00\x11\x00\x28\x00\x90\x00\x51\x00\x00\x00\x60\x01\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x95\xa3\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x7c\x00\x6d\xa7\x41\x00\x9c\x45\x34\xb2\x75\x00\x71\x5b\x43\xd7\x71\x1b\x3d\x00\x63\x2b\x55\xbe\x44\xbc\x59\xc0\x75\x00\x00\x17\x5f\x6c\x11\x00\x11\x00\x38\x53\x7a\x00\x11\x00\x6a\xf5\x7a\x00\xb4\xa0\x75\x00\x75\x00\x75\xb8\x7a\x54\x41\xe0\x70\xc4\x52\x00\x41\x00\x75\x00\x28\x00\x7a\x99\x11\x00\x26\xdd\xce\x3a\x75\x00\x70\x93\x42\xb7\x1b\xf2\xde\x07\x65\xfb\x64\xd6\x3d\x00\x3d\x00\x23\x81\xd6\x32\xa5\xed\xdc\xa5\x32\x56\xcc\x31\x4a\x22\x3d\x00\xb1\x0a\x0b\x93\x6e\xc1\x75\x00\x72\xba\x17\x6c\x41\x00\xb7\x2c\x52\x00\x1e\x05\x16\x03\x5c\xe0\x75\x00\x53\x82\x9c\xdf\xe0\xbc\x1b\xc9\xb8\x03\x3e\xb6\xe5\x5e\x64\xc8\xb0\xb1\x4d\x30\x69\x00\xc6\xed\x02\x8c\x82\xf4\x69\x76\x95\x65\x75\x00\x41\x00\x73\x8b\xe1\xd3\x8a\x51\x71\xd3\x1d\x3a\x75\x00\xc7\xdf\x9e\x07\xc0\x0c\x15\x4e\x33\xa2\x9c\x02\x3d\x00\x91\xcb\x9a\x8b\x42\x8d\x07\xb4\xe7\x83\x6b\x43\x3d\x00\x7b\x88\x66\x6d\x2c\x4a\xac\x3c\x21\x06\xb4\xcd\x15\x41\x3d\x00\xca\xdf\x52\x00\xd3\x89\xd1\xbc\x71\xf7\x75\x00\x2a\x95\x75\x00\xc2\x6c\xd2\x84\x11\x00\x41\x00\x0f\x58\x3d\x00\x7c\x61\x75\x00\xab\x1f\x4a\x07\x38\xbf\x73\x3d\x42\xff\x2e\x04\x5c\x44\x31\x1d\xad\x24\x5e\x4d\x28\x00\xca\x4f\x3d\x00\x3d\x00\x2a\x55\x7a\x00\x52\x00\x41\x00\x52\x00\x33\x1a\x90\x00\x41\x00\x28\x00\x7a\x00\x11\x00\x11\x00\x28\x00\x90\x00\x98\x01\x11\x00\xe0\x38\x41\x00\x90\x00\xc9\x0a\x41\x00\xf3\x37\x75\x00\x75\x00\x7a\xbe\xd7\x35\xfa\xf9\x58\x15\x36\x56\x37\x7b\x33\x77\x5a\xe1\xc8\x0e\x31\xa9\x61\xc0\x75\x00\x9a\x27\xe5\x5c\x41\x00\x01\x7e\x06\x42\x3d\x00\xcc\x7d\x02\x43\x3d\x00\x3d\x00\x5c\x52\x3d\x00\x9b\x00\x52\x00\x86\xc8\x90\x00\xf4\x3e\x4c\x2a\x13\xd0\x6c\xec\x52\x00\x41\x00\x75\x00\x5c\xf2\x83\x09\xe6\xb4\x75\x00\xd8\xbc\x75\x45\xf1\x7f\x8e\x19\x71\xda\xf2\x9f\xcb\xe7\x50\x3e\x3d\x00\x3d\x00\xf0\x1a\x49\x73\xa1\x97\xd5\xc1\x75\x00\x15\x46\x8d\x58\x52\x00\x7b\x12\x3d\x00\x3c\x12\xe8\x37\xae\x7f\x3d\x00\xfa\xb5\xaa\x00\xd3\x56\x64\x25\x43\x2c\xc7\x6d\xff\x67\x58\x3d\x90\x00\xfb\xd3\xfe\x41\x3d\x00\x7a\x00\x7c\x79\x7a\x00\x41\x00\x03\xc8\x11\x00\xcc\x90\x75\x00\x75\x00\x75\x00\xf4\x35\x07\x70\x6c\xb2\xd4\x3c\xa2\x26\xac\x01\x92\x37\xe7\xb7\x45\xc4\x52\xb5\x75\x00\xd6\x68\xc6\x28\xa0\xb8\x25\x62\xa2\x25\x3d\x00\x3d\x00\x0d\x32\x46\x3c\x28\xd6\x74\x4a\x68\xf3\xb2\x62\x6d\x73\xd0\x06\x51\x27\xf0\xae\x0a\x3e\x37\xf0\xc7\xa2\xe4\xa5\x7a\x00\x6a\xb8\x7a\x00\x41\x00\xe9\xe0\x41\x00\x7b\x49\x11\x00\xef\xec\x11\x00\x3d\x00\x09\x54\x40\x31\xf5\x31\x4d\x59\x32\x37\xc1\x2e\xcc\xe6\x9f\xb0\x75\x00\x52\x00\x5d\xb8\x3d\x00\x56\x92\x1d\xa5\x0f\x82\xb1\x90\xf9\x02\x07\x34\xab\xfd\xa4\xb4\x1a\xdb\x75\x00\x2c\x27\x4f\xc7\xe3\xa0\x3e\xa7\x41\x00\x41\x00\x75\x00\x41\x42\xa5\xc8\x89\x03\x3d\x00\x9c\x02\x28\x00\xe9\x5e\x52\x00\x3d\x00\xfb\x55\x7c\x60\x36\x0b\x75\x00\x0b\xf5\x90\x00\x7a\x00\x52\x00\x41\x00\x28\x00\x6a\x1b\x90\x00\x52\x00\x7a\x00\x41\x00\x11\x00\x90\x00\x28\x00\x11\x00\x51\x00\x00\x00\x3b\x02\x00\x00\x75\x00\x80\x17\x76\x7a\x00\x52\x00\x41\x00\x41\x00\x4b\x1a\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa0\x01\x70\xff\x62\x43\x3d\x00\x75\x00\x53\x00\x11\x00\x53\x00\x7b\x07\x2a\xec\xfb\xbc\x7f\x7e\x58\xf9\xd8\x4d\x7d\xeb\x04\x67\x1f\x29\x11\x00\x6c\x9d\x52\x00\xb3\x1c\x7c\xa5\x75\x00\x0b\x97\xbf\xea\x4a\xed\x93\xca\x09\x88\xf6\x5e\x53\x57\xc3\x4c\x16\x7d\x3d\x00\x1b\x55\x7f\x2d\xdd\xeb\xbe\xe9\x3d\x00\x77\xe2\x08\x4a\xa5\x1f\x90\x00\x75\x00\x96\xe2\x52\x00\x28\x00\x8a\x59\x3d\x00\x38\x1d\xd8\xc3\x75\x00\x28\x00\xa4\xb9\x3d\x00\x75\x00\xb2\xec\x90\x00\xef\xf6\x69\x7e\xc3\xec\x02\xb3\xbe\x67\xcd\xa1\x75\x00\x9a\x37\x55\x48\xc6\xdf\x2a\x29\x75\x00\x1f\x9f\xab\x2c\x77\x7e\x3d\x00\x9c\x02\x90\x00\xc5\x58\x11\x00\x3d\x00\x59\xde\x42\x97\x9e\xc8\x41\x00\x75\x00\xe8\xfd\x75\x00\x3e\xa8\x11\x00\x28\x00\xc1\x0f\x60\x47\x61\x42\x0a\xec\x02\x66\xe7\x96\x75\x00\x7a\x00\x57\x73\x5e\xa1\x17\x7a\x75\x00\xe1\x8a\x11\x44\x3d\x00\x8a\xa0\xab\x2b\x5f\xff\xa1\x8e\x6e\x84\xa2\xea\x75\x00\x41\x00\x27\xa0\xdc\xc8\x82\x07\x75\x00\x3d\x00\xb4\x03\x11\x00\x21\x12\x28\x00\x2c\x7c\x7c\x15\x3a\x33\xbb\xf3\xdf\x69\xc5\x02\x5e\xdc\x45\xa3\x93\xd0\x7a\x00\x7c\x00\x2f\x9a\x52\xe5\x41\x00\x1f\x85\x74\x91\x75\x00\x60\xe7\x23\xc7\x72\x77\x3d\x00\x74\x9f\x04\xad\x84\xa7\x6e\xc1\x75\x00\x0e\xe2\xc0\x34\x11\x00\x3d\x88\x11\x00\x30\x5c\xe0\x89\xfd\x10\x75\x00\x1d\xb5\x70\x83\x3b\x00\xe5\xeb\xcf\xd4\x2a\x13\xf0\xa1\xb7\x6a\xaf\xeb\x94\x9d\x25\x13\x08\x8f\x6f\x0a\x37\xdf\x75\x00\x7a\x00\x11\x00\x16\x07\x90\x00\x7a\x00\x95\x5d\x28\x00\xe6\x0b\x90\x00\xd5\x31\x4c\x07\x36\xea\x40\xea\x52\x00\x41\x00\x75\x00\x3d\x00\xfe\x58\x34\xf8\x02\x42\x3d\x00\x86\x17\x9b\x94\x3d\x00\x3d\x00\x19\x5d\x90\x00\x28\x00\xd5\x57\x3d\x00\xbc\x8c\xc8\x2e\xa8\xc7\x40\xba\x67\x48\x75\x00\x2d\xf2\x75\x00\x52\x00\xf3\xb8\x3d\x00\x45\xee\x5f\x31\x30\x93\x3e\x96\x18\xd8\xf4\x06\x75\x00\x37\xd7\x28\x00\x66\xb8\x75\x00\x6b\x72\x3d\x00\x2e\x04\x11\x00\xa9\x66\x41\x00\x12\xcd\x64\xc9\x66\xae\xc2\x1a\xdc\x2f\x3d\x00\x3d\x00\x6e\x23\x7a\x00\x52\x00\x41\x00\x28\x00\x2d\xcc\x90\x00\x11\x00\x52\x00\x7a\x00\x11\x00\x41\x00\x28\x00\x90\x00\x51\x00\x00\x00\xc9\x04\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x77\xc8\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\xa6\x03\x0a\x6a\x28\x80\x00\x00\x4c\x54\x83\x59\x65\xd5\x5a\x09\x9a\x59\xec\x2c\xde\x05\x02\x62\x33\x89\x06\x33\xf3\xae\xfd\x7c\xa1\x65\x9f\x2c\x81\x79\xdf\xdb\x72\x55\x7a\x05\x32\xc5\x67\xb2\xbf\x9a\x11\x4b\x2c\x1a\x58\xc3\xe0\x09\x7a\x00\x75\x00\x75\x00\x1c\x8a\x01\x89\xdf\x00\xe6\xa7\x32\x91\x58\x01\xa6\x44\x5b\x86\x9b\x39\xf7\xc4\x48\xfd\xb6\x52\x2f\x5f\x5f\x83\x85\xee\x07\x61\xad\x38\x02\xe0\x90\x00\x28\x00\x75\x00\x75\x00\x28\xb5\x18\x97\xb5\xe9\x3d\x00\x3f\xba\xd9\x0d\x63\xc3\x75\x00\xfd\x28\xcc\x1c\x52\x00\x75\x00\xda\x09\x7d\x33\x19\x5b\xbd\xd6\x11\x00\x51\x1d\x41\x00\x28\x00\x7f\x83\x52\x00\x4b\xe5\x28\x00\x0e\xeb\x62\xf0\x1c\x47\x81\xc0\x3c\x51\x0b\xee\x92\x14\x10\x47\x3d\x00\x6a\xd9\x68\xb0\xf1\x58\xfa\x08\x82\x62\x75\x00\x75\x00\x3f\x07\x90\x00\x42\xd3\xf4\x02\xfd\xf0\x2a\x30\x30\x3e\x7d\x15\x19\x68\x83\xeb\x63\x53\x9c\xb1\xe6\xd7\x3d\x00\xe6\xdb\xaf\x54\x6e\x60\xc9\x1a\x9e\x5a\x68\x3e\xfa\x66\x75\x00\x9c\x77\xf6\xa5\x93\x29\x28\x00\xa9\x48\x89\x75\x52\x00\x56\x37\x75\x00\x11\x00\x75\x00\x49\xb4\x3d\x00\xab\xb1\xb1\x16\xd7\xff\x3d\x00\x6b\xa6\x86\x5e\xa4\x5f\x89\xde\xb9\x29\x0f\x8a\xec\x40\x3f\xdd\x7d\x4a\x97\x19\x75\x00\x3f\x2f\x90\x00\x41\x00\xdd\x59\x3d\x00\x3d\x29\x4b\x76\x8a\x02\xcc\xd9\xc2\x98\xb1\x75\x3c\x73\xb1\xe4\xe8\x3c\x68\xa6\x64\x5b\x97\x3d\xc4\x7d\x8b\x0d\xb2\xee\xd4\x63\x07\x1e\x75\x00\x47\x30\x28\x00\xd5\x09\x75\x00\x21\x4c\x0f\x38\x75\x00\x41\x00\x26\xba\x3d\x00\xf4\x0a\x86\xaf\x75\x00\x9c\xa1\xa7\x50\x7a\x00\x9c\x5c\x52\x00\x49\x26\x78\xbc\xbb\x70\x52\x00\x75\x00\x41\x00\x99\x6c\x52\x00\x68\xd8\xf4\x35\x75\x00\xad\xfc\x45\x99\xa4\x17\x43\xe3\x75\x00\x1b\xd2\x90\x00\x16\xbf\x3d\x00\x11\x00\xaf\x2d\x41\x00\x7c\x70\x56\x7a\x75\x00\xb9\x25\x20\x47\x75\x00\x90\x00\x26\xb8\x3d\x00\xc6\xff\xe0\xa3\xa0\xc2\x75\x00\xae\x56\x1e\x4e\x41\x00\x5b\x0e\x75\x00\x28\x00\xf3\xb8\x3d\x00\x7c\xe7\x5b\x42\x9c\x68\x91\x56\x18\x3a\x83\xc6\x00\x4f\xaf\x2e\x7d\x73\x52\x00\x75\x00\x0b\x9b\x28\x00\x93\xac\xfe\x8d\x75\x00\xda\xc6\x8c\x91\x1a\x8b\x5c\x83\x7a\x00\x52\x00\x46\x0c\xf2\x68\x61\x42\xff\x2e\xfb\xaf\x7d\x5c\xb1\x75\x00\x11\x82\xe3\x12\xfc\xa2\x7f\x7d\x03\xe8\xaf\xb3\x52\x00\x52\x00\x75\x00\x16\x4c\x5f\x96\x65\x74\xdf\x14\x2f\x36\x11\x00\x41\x00\xc4\x58\x3d\x00\x95\xc5\x41\x60\x5c\x1b\x64\x0e\xfb\xc3\x75\x00\xc5\x2c\x84\x0a\x11\x00\x6f\xbc\x3d\x00\x33\x75\x75\x00\x52\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x28\x00\x26\xba\x3d\x00\x9d\x5f\x82\x76\x75\x00\x2b\x7c\xb9\xc3\x28\x00\xbc\xd7\xa3\x09\xa8\x62\x68\x99\xfa\x24\x3e\x44\x8c\xd2\x77\xf6\xa2\xec\x4d\x63\xb2\x4c\xd3\x61\x9c\x76\xb1\x65\xcd\x4b\x45\xc0\x3d\x00\xdb\xdd\xf4\xa3\xf8\x3d\x00\x45\x05\x92\x75\x00\x96\xc6\xa9\x89\x7e\x06\xa6\xaf\xe1\x36\x73\x1f\x34\xb8\x52\x00\x0f\xbd\x3d\x00\x40\x97\x88\xa6\x08\x0a\x10\x2f\xfd\x47\x61\x3d\x14\xb1\xde\x39\xdd\x3e\xad\x67\xb8\xee\xab\xf5\xde\xd6\x0d\x8b\x75\xa3\xb5\x8b\xbf\xc0\x50\x05\x41\x00\x84\x91\x28\x00\x28\x00\x1f\xb6\x52\x00\x67\x9d\x75\x00\x75\x00\xdd\x1b\x93\x1d\xff\xc5\xef\x24\x72\xc9\x4e\x29\xa5\x30\x8c\x64\x9a\x62\xc5\x64\xc5\x33\x28\x00\x11\x00\x75\x00\x75\x00\x2b\xea\x8e\x5f\x4e\x22\xad\x45\x20\x03\xd9\x07\x0b\x52\x9b\xa5\x71\x69\x3f\x5a\xc7\x26\x88\x43\x75\x00\x52\x00\xbc\x20\xc2\xff\xa0\x3a\xc0\x7e\x75\x00\x75\x00\x5a\x5c\x10\x0e\x2c\x89\x7a\x00\x41\x00\x11\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\xf7\x2d\x90\x00\x28\x00\x90\x00\x52\x00\x11\x00\x41\x00\x28\x00\x11\x00\x51\x00\x00\x00\xcd\x00\x00\x00\x75\x00\x04\xd6\x33\x16\x9a\x75\x00\x90\x00\xf7\xbb\x3d\x00\x9d\xc6\x41\x00\x35\xa2\x01\x97\xd5\x11\x75\x00\x75\x00\xca\x41\x00\x2d\x0c\x90\x00\x70\x6c\x9b\x00\x90\x00\x75\x00\xb5\xe3\x53\x39\xe1\x7b\xfc\x4f\x40\x37\x4e\x7a\x00\x28\x00\x75\x00\x50\xed\x1f\x44\x3d\x00\x31\x16\x75\x00\xf3\xe2\xaf\xad\xb9\xf7\x90\x00\x75\x00\x11\x00\x28\x00\x21\x5a\x3d\x00\x04\x49\xe7\x42\xee\x95\x28\x00\x75\x00\xf9\x92\x75\x00\x24\xa9\x28\x00\x41\x00\x0e\x8a\x9e\x19\xaa\xc0\x52\x07\x03\x19\x42\xfc\x6a\x9b\xc8\x35\x17\xad\x28\x00\x7a\x00\x75\x00\x3d\x00\xf0\xed\x7a\x00\x52\x00\x41\x00\x90\x00\xd6\x85\x90\x00\x28\x00\x41\x00\x11\x00\x11\x00\x52\x00\x28\x00\x7a\x00\x51\x00\x00\x00\x48\x00\x00\x00\x7a\x00\x52\x00\x41\x00\x41\x00\xf5\x82\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x8b\x02\x7d\x15\x0d\x17\x11\x00\x7a\x00\xae\xff\x7a\x00\x52\x00\x41\x00\x41\x00\x56\x0d\x90\x00\x28\x00\x7a\x00\x11\x00\x11\x00\x52\x00\x28\x00\x90\x00\x87\x02\xd7\xcd\x75\x00\x64\xaa\x3a\x42\x0f\xfa\xe2\x96\x7a\x00\x52\x00\x41\x00\x41\x00\x34\xb7\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x49\x00\x00\x00\x75\x00\x80\x04\xa8\x7a\x00\x52\x00\x41\x00\x41\x00\x9e\xb4\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x51\x00\x00\x00\x99\x06\x00\x80\x7a\x00\x52\x00\x41\x00\x41\x00\x5f\xb2\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x07\x05\x1e\x77\xac\xe4\x54\x1d\xc6\x15\xa4\x36\x3d\x00\x19\x65\xc2\xe5\x3f\x43\xa0\x36\x3c\x3b\x19\xdd\x65\x0b\x75\x00\x6b\x24\xef\x13\x05\xe9\x14\x33\xa6\xb2\x60\x15\x2a\x00\x5e\x29\x28\x00\x75\x00\x7a\x00\x11\x00\x14\xb1\xaa\x3a\x75\x00\x7a\x69\x28\x00\x20\x0f\xfd\x4d\xd5\x06\x5d\xa7\x75\x00\x4a\x25\x83\xc3\x11\x00\x75\x00\x75\x00\x07\xb5\x17\x9c\x41\x00\x90\x00\xc5\x58\x3d\x00\xfc\x76\x3d\x00\x45\xf3\x3d\x00\x5e\xc5\x1f\xb4\x03\x15\x28\x00\x75\x00\xc0\x81\x41\x00\x7a\x00\xc9\x57\x3d\x00\xbb\x9f\xe7\xb5\x42\x41\x3d\x00\xc1\x0e\x86\xfe\x0b\x20\xa7\x01\x45\x8c\x99\x1d\x1c\x57\xb9\x71\x0a\xec\xe9\x7b\x94\x19\x22\x06\x54\x21\xab\x22\x64\x94\x90\x00\x52\x00\x75\x00\xf3\x7c\x8b\x8f\xbc\x5b\x3d\x00\x72\x65\x11\x9c\x38\x64\x1f\x1b\x42\xf5\x5f\x1c\xf7\xa2\x83\x67\x7a\x00\x3d\x00\x55\x54\x8a\xce\x3d\x00\x4e\x99\x97\xa7\x5e\x36\x3d\x00\xce\x56\xfb\x40\x72\x36\x36\x7b\x01\x13\x04\x16\xc1\x88\xcf\x73\x11\x00\x3f\x38\x75\x00\x28\x00\x5d\xb8\x3d\x00\xcb\x6c\x7d\x8e\x38\x04\x5b\x7c\xaa\x57\x75\x00\x21\xa3\xc2\x52\xd8\x5d\x5d\x12\x28\xb9\xac\x01\x41\xb5\x06\x75\x65\xd8\x92\x7d\x75\x00\xc7\x2f\x62\xb2\x80\xf1\x3d\x00\x7b\xaa\xcc\x05\xa5\x83\xb5\x71\x34\x78\xc1\x39\xa1\x37\x91\x2f\x41\x00\x3d\x00\xbe\x20\xe8\x83\x19\xca\x75\x00\x6b\x77\x40\xcf\x11\x00\x7a\x00\x52\x00\x41\x00\x52\x00\xee\x43\x90\x00\x28\x00\x11\x00\x41\x00\x11\x00\x90\x00\x28\x00\x7a\x00\xfc\x02\x75\x00\xef\xff\x28\x00\xef\xff\xdf\x07\xc6\xeb\x94\x7a\x1f\x2f\x8f\xea\x7a\x7c\x4b\xec\xdd\xa9\x7e\x78\xf9\x7d\xa5\x1d\xce\x94\x2f\x72\x15\x94\xb7\x24\x1e\x63\x75\x00\x82\x7a\x6c\xe4\x1e\x79\x67\x81\xb8\x47\x52\x00\x4d\x82\x72\x78\x08\x52\x1b\xf6\x50\x46\xb0\x25\xe1\x2f\x2c\x22\xea\xb2\xba\xe7\x56\x7f\x52\x00\xff\x2e\x00\xf0\x0a\x4e\x1a\x1a\xa1\x63\xe0\x88\x8e\x30\x72\xa2\x86\x7e\x71\xf0\x82\x7f\x0f\x06\x11\x00\x28\x00\xb9\x5d\x75\x00\xf8\x4e\x43\x3a\x41\x00\x11\x00\x4f\x86\x41\x00\x28\x00\x03\x0b\x11\x00\x56\x8d\x75\x00\x75\x00\xbe\x1f\x9f\xd0\xb8\x23\x07\x5d\x49\x5c\x74\xee\x12\x54\x39\xd5\xed\xc3\xd2\x08\x3a\x54\xe5\xb5\x3e\x69\x71\xa4\x8f\xfa\x3d\x78\xc8\x97\xce\x3c\x75\x00\x67\x59\x75\x00\x05\xa8\x28\x00\xe7\x1c\x20\x07\x3b\x36\x54\x16\x7a\x00\x28\x00\xbf\xb3\xfe\x0b\xa0\x01\x2e\x79\xe3\x36\x30\x3a\x16\xef\xdd\xc3\x06\x71\xfa\xe6\x97\x1a\x41\x00\x5b\xdd\x10\xaf\xd0\xc8\x4a\x8d\x94\xf9\x1e\x7e\x2a\x60\x00\x23\x3e\x61\x81\x24\x4a\x08\x00\xfb\x41\x00\x52\x00\xfa\x2c\x75\x00\xc5\x81\xca\xcf\x90\x00\xcb\xc4\x24\x81\x54\x79\xd9\x4c\x41\x00\x16\x77\x9f\x12\x4b\x24\x41\x00\x75\x00\x7c\x8c\x3e\xfc\x8e\x6d\x0b\x88\x94\x0f\x11\x00\x4f\x82\x37\xa1\x47\x0c\xb9\x4b\xc6\x31\xbb\x5e\x16\xef\x92\x54\x2d\x7e\x10\x4e\xab\x1f\x90\x00\x4a\x01\x46\xd3\x0d\x13\x5a\x8f\x45\xfc\x2f\x3b\x91\x54\x53\xfb\x3c\x57\x74\xee\xf9\x58\x64\x24\x88\xa5\xcf\x59\x50\xd9\x4d\x46\xae\x5c\xf3\x6e\x83\x91\x2c\x08\x73\xe3\x75\x00\x15\x90\xbb\x8b\x59\xc4\xb7\xb8\x4e\xc6\xe6\x00\x37\x5d\xce\x0b\x71\xf0\xac\x50\x85\x05\x90\x00\x52\x00\x6c\xdd\x75\x00\x45\xcf\xac\x57\x41\x00\x28\x00\x2c\xcd\x90\x00\x52\x00\xa0\x08\x41\x00\xe1\x8c\x75\x00\x75\x00\xfb\xe1\x9b\x4d\x28\x00\x90\x00\x11\x1f\x73\x06\x40\x15\x1e\xcc\x73\x0c\x6e\xb6\x15\x0e\x03\x99\xf3\xcf\x3c\x7f\x66\xbc\x41\x00\x1e\x44\x75\x00\x1b\xfc\x28\x00\x37\xfa\x4c\xa0\xc7\x7b\xdc\xeb\x0d\x4b\x97\xd9\x87\x2f\x15\xef\x0e\xb2\xbc\x9e\x8f\x97\xda\x52\xb5\x13\x92\xd7\x9b\x77\xc1\xf4\x14\x99\x75\x00\x75\x00\xb2\x64\x52\x00\x70\x32\x2e\xac\x32\x65\x70\x2a\x65\xe4\xfa\xe9\x80\x76\x93\x3c\x57\xe6\xb5\x15\x1a\x74\x5b\xca\x7a\x00\x90\x00\xf8\x51\x90\x00\x11\xd9\x6c\xfc\xea\xcd\x8f\x23\xfb\xc0\x11\x00\x45\x82\x49\x15\x33\x12\x03\xd6\x3b\x1e\x9c\x80\x5c\x13\x17\x1d\xb2\x2d\xe3\xd4\xd6\xde\x52\x00\x65\x52\xf3\x22\xd4\xc3\x4a\x8d\x7e\xaa\x7a\x8d\xe6\x7e\xd9\x95\x14\x12\x4b\xec\x83\x36\x6e\x96\xca\x53\x90\x18\x4c\x8c\x7a\x00\x75\x00\xa7\x68\x56\x43\x90\x00\xb9\xc2\x3c\x0f\x90\x00\x90\x00\xc6\xe5\x39\xfb\xc4\x0b\x19\x61\xcb\x3c\x5e\xc3\xa3\x1a\x7c\x4e\x69\x0b\xe6\x6f\xe4\xa5\x5c\x53\x3a\x7f\x41\x00\x90\x00\x2e\x39\x11\x00\x75\x00\x2f\x03\x41\x00\x59\x92\x77\xef\xdf\xef\x93\x6c\x52\x00\x7d\x13\xaf\x2c\xa0\x22\x04\x03\x15\xaa\xf6\x19\x16\xef\x0d\xdd\x00\xcb\xc0\xb3\x3d\x74\x28\x00\xe8\xdd\x61\xfe\x6b\x87\xe9\x9b\x82\xa7\x75\x00\xdf\x20\xf6\x97\x79\xaf\x48\x52\xca\x0d\x45\x48\x0e\x7d\x1a\xc5\xf9\x12\x02\x82\x6a\x4c\x54\xf6\x11\xa3\x1a\x0d\x95\xa3\x71\xa0\x48\x8b\x82\x5d\x7a\x00\x13\xa3\x37\xf2\x75\x00\x73\x06\x34\x66\x71\xef\x47\x2c\xd5\xea\xca\x35\x75\x26\x48\x18\x6e\x4e\xd3\x14\x71\xf0\x5b\x93\x3c\x74\x11\x00\x28\x00\x8b\x40\x75\x00\xfe\x6c\x6d\x1d\x7a\x00\x7a\x00\x52\x00\x41\x00\x90\x00\xa9\x1a\x90\x00\x11\x00\x7a\x00\x52\x00\x11\x00\x41\x00\x28\x00\x28\x00\x51\x00\x00\x00\x24\x03\x00\x80\x75\x00\x94\xbe\x9f\xc9\x18\xa1\xcf\x75\x00\xed\xda\xd2\x5b\x41\x00\xea\xf2\xb8\xb3\xba\x14\x48\xae\x3d\x00\x5d\x6d\x02\x42\x3d\x00\x6c\x17\x4b\x30\x3d\x00\xdb\xdc\x75\x00\x28\x00\x3d\x00\x75\x00\x93\x06\x02\x42\x3d\x00\x7b\x16\xe4\xbf\x3d\x00\x4a\x5c\x75\x00\x28\x00\xc4\xba\x3d\x00\x7b\x16\x07\x01\x3d\x00\xa3\x5c\x75\x00\x28\x00\xf8\xba\x3d\x00\xbd\x15\x06\x42\x3d\x00\x0f\xfd\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x03\xe1\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x0e\xfe\x84\x41\x41\x01\x20\x00\x28\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\xf2\x52\x70\xff\x1e\x6f\x10\x50\xe1\x8d\xfd\x19\x80\xce\xf1\x67\x11\x00\x3d\x00\xc7\x3c\x68\x00\xb2\x51\x40\x08\x9f\x60\x1f\x67\x55\xf2\x49\x7c\x11\x00\xf4\x4d\x11\x00\x97\x61\x3d\x00\x3d\x00\xf5\x04\x7a\x00\xa8\xc2\x11\x00\xd2\x40\xb7\xf6\x3d\x00\x3d\x00\x51\x30\x9f\xf6\x54\x3a\x69\x62\xe9\xab\xd2\x17\x40\xcb\xad\x16\x52\x00\x4d\x4d\x41\x00\x5c\x65\x3d\x00\x3d\x00\x1b\x40\xfe\xcf\x12\x2f\x64\x38\x01\x90\xd0\x56\x41\x18\xef\x25\x11\x00\x14\xe0\x75\x00\x3d\x00\x0d\x5c\x08\x3d\x00\x90\x00\x45\x10\x11\x00\x7a\x00\x00\x22\x28\x00\x4b\x09\x75\x00\x75\x00\x75\x00\xf2\xb5\xb0\x56\x6f\xa7\x70\x46\x55\x26\x9e\x04\x52\x00\x75\x00\x39\x43\xd0\xff\x7a\x00\x67\x46\x75\xc1\x90\x00\x41\x00\x41\x00\xe5\x79\x52\x00\x41\x00\x88\x09\x90\x00\x49\x0d\x75\x00\x75\x00\x64\x71\x7a\x75\x00\x91\xfe\x18\xf5\xfe\x2e\xbc\x3a\x60\xd3\x24\x71\x98\xef\xe1\x71\x2e\xf1\xc5\x46\x7a\x51\x7a\x00\xf6\xd1\x90\x00\x11\x00\x36\xd4\x28\x00\x98\xa7\x75\x00\x75\x00\xb9\x99\x90\x00\xa5\x76\x04\xca\x4d\xbb\x28\x00\x75\x00\xfa\x83\xc7\xfd\xcb\x1e\x52\x00\x90\x00\xfe\xdf\xce\x8d\x79\x75\x00\xd8\x03\xa1\xc7\x2d\x1b\x26\x5e\x5b\x74\x98\xef\xdd\x8e\x38\x81\x69\x57\xaf\x0b\x5f\x77\x8f\x81\x3f\x0a\x75\x00\xc8\x75\x83\x68\x90\x88\x20\x8a\x1f\x2a\xf8\x28\x2f\xcd\x71\x10\xe2\x90\x00\x75\x00\x7d\x4d\x29\x49\x28\x00\x6c\x17\xdf\xc9\x3d\x00\xdb\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\x94\x96\xc7\x43\x3d\x00\x6f\x38\x75\x00\x11\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\xba\x14\x49\xfd\x3d\x00\x55\x39\x06\x42\x3d\x00\xad\xf7\xc7\x43\x3d\x00\xd5\x38\x75\x00\x7a\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x52\x00\x06\xfb\x90\x00\x90\x00\x41\x00\x7a\x00\x11\x00\x11\x00\x28\x00\x28\x00\xc0\xe1\x30\x71\x71\x84\x08\xa8\x0c\x63\x41\x41\x01\x20\x00\x3d\x00\x51\x00\xf5\x04\x6f\x6d\xfd\x23\x3d\x00\x11\x00\x11\x00\x65\x59\x3d\x00\xe0\xd7\x50\xb6\x11\x00\x43\xb7\x3d\x00\xf8\x00\x7a\x00\xff\xbc\x3d\x00\xc2\x88\xbb\x6e\x3d\x00\x11\x00\x52\x00\x1e\x5b\x3d\x00\x24\x89\x1a\xaa\x77\xd9\x3d\x00\x46\xf5\x7a\xd4\x3d\x00\x60\xe7\x75\x00\x3d\x00\x53\x5b\x08\x3d\x00\xbb\x32\xec\xf9\x75\x00\xe0\xfb\xbb\x97\x90\x00\x65\xea\xdc\x42\x3d\x00\xdb\xdc\x75\x00\x7a\x00\x3d\x00\x75\x00\xc7\xc8\x06\x42\x3d\x00\x08\xc9\x02\x42\x3d\x00\xba\x14\xaa\xe5\x3d\x00\x2a\x79\x02\x42\x3d\x00\x7b\x16\xec\x5a\x3d\x00\x01\x5c\x75\x00\x41\x00\x39\xb8\x3d\x00\xe8\x00\x75\x00\x90\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x37\x5a\x90\x00\x28\x00\x52\x00\x7a\x00\x11\x00\x11\x00\x28\x00\x90\x00\xf1\x40\x3c\x2f\xd9\x20\xa1\x9e\x4a\x73\x41\x41\x01\x20\x00\x3d\x00\x51\x00\x12\x02\x3d\x00\x79\x2d\x70\xff\x50\xd5\x80\x21\x00\x85\xf4\x20\x67\x5a\xbd\x4a\x28\x00\x3d\x00\x3c\x03\x28\x00\x1f\x52\x90\x00\x2d\xff\x28\x00\x66\xb4\x3d\x00\x90\x00\x52\x00\x1e\x5b\x3d\x00\x1b\x60\x2c\x01\x70\xd8\x3d\x00\x52\x00\x52\x00\x65\x59\x3d\x00\xd1\xd8\x2b\xb6\x11\x00\xe9\x99\x3d\x00\x3d\x00\xd7\x02\x11\x00\x5c\xde\x52\x00\x5d\xe9\x75\x00\x28\x00\x3d\x00\x33\x98\x08\x3d\x00\x94\x41\x10\x50\xb5\xf5\x3d\x00\x41\x00\xbf\xd6\x90\x00\x90\x00\x66\xb8\x7a\x00\x49\x36\x75\x00\x75\x00\x4c\xe9\xc1\x44\xc2\x05\x2d\xa8\x36\x99\xc4\x00\xdb\x8b\x32\x55\x69\xfc\xcf\x1e\x38\x20\x07\xd5\x74\x6e\x52\x00\x75\x00\x41\x00\x44\x28\x00\x75\x00\x46\x4b\x02\x60\x54\x04\x7a\x00\x7a\x00\x13\x03\x27\x5d\xdb\x59\x75\x00\xc6\xea\xca\xe7\xe9\x65\x42\x7b\xf5\x62\x95\x03\xdb\xaf\xfa\x1e\x0c\x5e\x12\x07\x92\x08\x7e\x6c\xba\xa9\x28\x00\x41\x00\xc8\x52\x41\x00\xb5\x45\xc2\xbb\x85\x3e\x7d\xde\x3c\x8a\x78\x38\x29\x8e\x89\x6b\xf7\xeb\x25\x48\xd0\xc8\xaa\x42\xae\xd5\x61\x80\xdd\x70\x75\x00\x41\x00\x39\xb8\x3d\x00\xb9\x00\x75\x00\x52\x00\xa4\xb9\x3d\x00\x75\x00\x6f\x1d\x7a\x00\x1f\xf2\x2d\x03\xea\xa0\xf2\x0a\xbd\xe3\x8b\xc0\xe5\x90\x1f\x4e\x42\x4c\x7c\x3c\x88\xaf\x92\xc9\x7a\x00\x7a\x00\xc2\x50\x28\x00\xe1\xc1\x06\x42\x3d\x00\xe1\xbd\xdc\x42\x3d\x00\x9c\xde\x75\x00\x41\x00\x3d\x00\x75\x00\x1f\x38\x75\x00\x52\x00\xc4\xba\x3d\x00\x7b\x16\x74\xc1\x3d\x00\x47\x5b\x75\x00\x11\x00\x39\xb8\x3d\x00\x3a\x00\x75\x00\x52\x00\xf8\xba\x3d\x00\x81\x72\x06\x42\x3d\x00\xee\x3a\x06\x42\x3d\x00\x3c\x3a\xd6\x42\x3d\x00\x7a\x00\x52\x00\x41\x00\x90\x00\x03\xe1\x90\x00\x11\x00\x41\x00\x7a\x00\x11\x00\x28\x00\x28\x00\x52\x00\x1b\xfd\x93\x41\x41\x01\x20\x00\x80\xce\x68\x00\x3d\x00\x51\x00\xcf\x01\x3d\x00\x3c\x03\x11\x00\x0f\x4d\x52\x00\x87\xff\x52\x00\x37\x6e\x3d\x00\xaa\x00\x90\x00\x33\xc0\x3d\x00\x32\x72\xf7\x6f\x3d\x00\xbd\x93\x90\x00\x09\x2e\x3d\x00\x3b\x00\x52\x00\xba\xbd\x3d\x00\x11\x00\x52\x00\x1e\x5b\x3d\x00\xfd\x04\x42\x65\x34\xd8\x3d\x00\xc7\x5d\x75\x00\x41\x00\x3d\x00\x86\x2c\x08\x3d\x00\x75\x00\xf6\xe9\x7d\x6c\xd4\xc5\xf1\x8f\x99\x13\x9c\x02\x3d\x00\x27\x9f\x02\xd1\x3d\x00\x5c\x9d\xa5\x66\xc7\x34\xcd\xd4\xd7\x14\x42\x41\x3d\x00\xb0\xf8\x0e\xe6\xd8\xe6\x06\x84\xb3\x39\x9d\x51\x30\x3d\x2d\x3f\x15\xef\x1d\xf7\xc0\x24\xc1\xda\xd9\x0f\x16\x0a\x3f\x38\x75\x00\x7a\x00\x26\xba\x3d\x00\x4d\x79\x63\x8d\x75\x00\x61\xa3\xf6\xb8\x7a\x00\xf2\x8a\x3c\x14\x86\x14\xcc\xd0\x3d\x00\x86\x14\x15\xe8\x3d\x00\x6c\x17\x4b\x16\x3d\x00\x9c\xde\x75\x00\x28\x00\x3d\x00\x75\x00\xfd\x5b\x75\x00\x41\x00\x39\xb8\x3d\x00\x41\x00\x75\x00\x41\x00\x39\xb8\x3d\x00\x31\x00\x75\x00\x52\x00\x39\xb8\x3d\x00\xc9\x00\x75\x00\x11\x00\xc4\xba\x3d\x00\xba\x14\x59\x55\x3d\x00\x17\xea\x02\x42\x3d\x00\x6a\x17\x25\xa0\x3d\x00\x7a\x00\x52\x00\x41\x00\x41\x00\x55\x05\x90\x00\x28\x00\x11\x00\x7a\x00\x11\x00\x52\x00\x28\x00\x90\x00\x52\x19\xa2\x41\x41\x01\x20\x00\xc0\x06\x0b\x00\x3d\x00\x51\x00\x3c\x03\xce\x4d\x52\x00\x58\xbd\x3d\x00\x3d\x00\xb2\xa1\xa6\x4d\xc2\xf7\xf3\x7e\xe0\x4d\x70\x16\x2f\xf4\xe4\x07\x41\x00\xf4\x4d\x41\x00\x19\xf6\x3d\x00\x3d\x00\x8b\x44\x5d\x8a\x6b\x69\x7c\x24\xf2\xe6\x7f\x3b\x8f\x8c\x47\x3c\x52\x00\x5e\x4d\x7a\x00\xb4\x9a\x3d\x00\x41\x00\x7a\x00\xd5\x58\x3d\x00\x51\xca\x52\x00\x41\x00\xf8\x57\x3d\x00\x3a\x15\x3d\x00\xd7\x02\x28\x00\x90\xa4\x28\x00\x20\x3e\x75\x00\x52\x00\x3d\x00\x61\x4f\x08\x3d\x00\x75\x00\x13\xc1\x63\x3a\x0d\x61\x70\xa7\x39\xde\x9c\x02\x3d\x00\xec\x54\x6c\x17\xd4\x60\x3d\x00\xd7\xdc\x75\x00\x90\x00\x3d\x00\x75\x00\x86\x14\xda\x92\x3d\x00\x86\x14\xbc\x6c\x3d\x00\x7b\x16\x23\x92\x3d\x00\x53\x5c\x75\x00\x7a\x00\xf8\xba\x3d\x00\x45\xba\x02\x42\x3d\x00\x7b\x16\x4b\xc0\x3d\x00\x47\x5b\x75\x00\x11\x00\x28\xb9\x3d\x00\x7a\x00\x52\x00\x41\x00\x7a\x00\x20\x0f\x90\x00\x28\x00\x11\x00\x52\x00\x11\x00\x41\x00\x28\x00\x90\x00\x52\x12\xcd\x49\x59\x00\x20\x00\x99\x68\xef\x3c\x41\x01'

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
