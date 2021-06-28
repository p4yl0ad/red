#!/usr/bin/env python
##Author p4yl0ad##
##   ordinal    ##
##   obfus      ##

from cmd import Cmd

def splitter(payload):
    payl = ''
    step = 50
    for i, v in enumerate(payload):
        if i == len(payload) - 1:
            print("no plus here")
            new = "[char]" + str(ord(v))
            payl += new
        else:
            print(i)
            new = "[char]" + str(ord(v))
            payl += new
            payl += '+'

    return "powershell ([char]45+[char]99) (" + payl + ")"

class loop(Cmd):
    prompt="> "
    def default(self, params):
        payload = splitter(params)
        print(payload)

loop().cmdloop()
