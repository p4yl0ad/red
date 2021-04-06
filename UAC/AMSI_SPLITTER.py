#!/usr/bin/env python
from cmd import Cmd

def splitter(payload):
    payl = ''
    for i in payload:
        payl += ('"{}"').format(i) + '+'
    return payl

class loop(Cmd):
    prompt="> "
    def default(self, params):
        payload = splitter(params)
        print(payload)

loop().cmdloop()


#EXAMPLE
# [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes("c"+"m"+"d"+" "+"/"+"c"+" "+"w"+"h"+"o"+"a"+"m"+"i"+" "+">"+" "+"C"+":"+"\"+"W"+"i"+"n"+"d"+"o"+"w"+"s"+"\"+"P"+"o"+"o"+"n"+"."+"t"+"x"+"t"))
# $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBtAGQAIAAvAGMAIAB3AGgAbwBhAG0AaQAgAD4AIABDADoAXABXAGkAbgBkAG8AdwBzAFwAUABvAG8AbgAuAHQAeAB0AA==')))
# cmd /c whoami > C:\Windows\Poon.txt
# ;)
