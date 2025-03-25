It's start VM protector of 4.6 64bit client. I just do this devirt/trace for find why it's detects x64dbg with scyllahide.

Short answer - it's reads entry point byte(and winapi functions first byte) and compare it with software breakpoints "cc".

x64dbg creates by default 'cc' breakpoint on program entry, but do first TLScallback which run VM which checks for it. So delete entry breakpoints on debug start. 

For winapi calls set breakpoint on second/etc instruction.

`g.py` is just VM emulator for TLS and first part of Entry  (to choose which part you want to trace - edit it in the end of script)

All done for Aion Destiny 4.6 64bit aion.bin(md5 03cd9122d00b61b42dbcdfa4009ad418)

`tls_wo_cc.txt`, `tls_w_cc.txt` and `entry.txt` are traces and `start` is just VM entry for comfort reading because of too often JMP's


This is STACK VM and it's not easy to understand all things and not easy to detect branches, that's why it's trace and emulate how VM branch. 

To modify branch you can patch it in trace func or add wanted data on necessary addr.


`tls_wo_cc` is trace with disabled `vm.AddMem(0x57d832, b'\xcc')`

`tls_w_cc` is trace with enabled


So you will see `tls_w_cc` will set `585786` to `1` and entry VM will also check for it.

Same checks for winapi calls in entryVM, like this:

```
Op_1e   (30)     RSI 589282 RBX 1c9732471 RBP 750
1562	LOAD WRD cc  //store `cc` byte
1563	
Op_9   (9)     RSI 589280 RBX 1c973249c RBP 74e
1564	PUSH VM[60] (cccc00000001)   //winapi addr
1565	
Op_6   (6)     RSI 58927e RBX 1c97324f6 RBP 746
1566	LOAD WRD <-- byte, [RBP] ([cccc00000001] --> 0)  //load first byte of winapi into stack
1567	
Op_c3   (195)     RSI 58927d RBX 1c9732433 RBP 74c
1568	STORE RBP (74c)                              //store into stack current stack position
1569	
Op_25   (37)     RSI 58927c RBX 1c973240e RBP 744
1570	LOAD WRD <-- byte, [RBP] ([74c] --> 0)       //copy loaded byte using address from stack    (yeah, it's just such technique to just copy)
1571	
Op_fd   (253)     RSI 58927b RBX 1c9732411 RBP 74a
1572	~b, RBP[0] (ff) AND ~b,RBP[2] (ff) --> EFLAGS8 (286)  RES2 (ff)   //this is tricky way to do ~byte throught `~b and ~b`
1573	
Op_24   (36)     RSI 58927a RBX 1c97324ed RBP 744
1574	POP VM[a8] = RBP[0]  (286)                                        //POP from stack unneeded EFLAGS
1575	
Op_0   (0)     RSI 589278 RBX 1c9732495 RBP 74c
1576	b, RBP[0] (ff) + b,RBP[2] (cc) --> EFLAGS8  RES2 (cb)             //add `cc` to inverted byte. if it's also `cc` which will be inverted to `33`, so sum will be `ff` which means it's was `cc` byte.
```

