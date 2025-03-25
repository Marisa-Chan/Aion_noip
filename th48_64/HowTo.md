This is devirt of 64bit aion beyound client protector VM first virtualized code which will crash in CloseHandle on win11

PROG2 is first, then it's return into obfuscated code and then go to PROG1 vm where it's devirted up to "CloseHandle" call

CloseHandle will crash in win11 because of stack was not aligned to 16-bytes. It's same way in win10, but internal winapi was use `movups` and now `movaps` which will except on unaligned stack vars.



It's only for this VM type(4.6 and lower use another type):


To debug all of it in debugger(beyond aion client 4.8, because 4.6 use another VM version and another checks) use x64dbg with ScyllaHide.

This VM use own virtual registers, but mostly interested is "EIP/RIP" register because using it you can check where you are in virtualized code.

For aion.bin (MD5 ba79f09fa004656f2649c54f35c524bf) it's `[RBP+59]` with address `6eff4e` so you can set hardware write breakpoint on it and log it `at {rip} vmip {[rbp+59]}`

Good idea is to find VM entry code and setup exec breakpoint(hw) for first VM-opcode jmp, but to do this you just can try to find VM calls to native code functions which are looks like:

```

        005008d0 5d            -50           POP             RBP
        005008d1 5b            -58           POP             RBX
        005008d2 5a            -60           POP             RDX
        005008d3 59            -68           POP             RCX
        005008d4 58            -70           POP             RAX
        005008d5 9d            -78           POPFQ
        005008d6 c2 00 00      -80           RET             0x0

```

So you can find all such function ends by bytes seq `5d 5b 5a 59 58 9d c2` or similar and set breakpoints on RET(and log for something like `CALL {[rsp]}  {RCX}  {RDX}`), do return after function call and it will can point us to something like:

```
        00702da8 68 0d f5                     PUSH            0x2ff50d                                                           VM
                 2f 00
        00702dad 68 68 00                     PUSH            0x68
                 00 00
        00702db2 e9 0a c4                     JMP             SUB_006ef1c1                                                   
                 fe ff
```

where JMP is VM entry which also can be finded by `PUSHFQ/PUSH RAX/PUSH RCX/...` seq (`9c 50 51 52 53 ...`) but now we exactly know it's it!

And now we can setup breakpoint on code like `jmp rax` in the end of VM entry. So on this breakpoint we can start dive into VM and check for many things.
