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
