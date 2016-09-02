#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
from Crypto.Cipher import AES
import hashlib, binascii

import json
import getpass
import time
import subprocess
import os
import argparse

def copyToClip(message):
    p = subprocess.Popen(['xclip', '-in', '-selection', 'clipboard'],
                         stdin=subprocess.PIPE, close_fds=True)
    p.communicate(input=message.encode('utf-8'))

def pad(msg):
    return " "*2 + msg.ljust(18)

class Enpassant:
    def __init__(self, filename, password):
        self.initDb(filename, password)
        self.crypto = self.getCryptoParams()
        
        
    # Sets up SQLite DB
    def initDb(self, filename, password):
        self.conn = sqlite.connect(filename)
        self.c = self.conn.cursor()
        self.c.row_factory = sqlite.Row
        self.c.execute("PRAGMA key='" + password + "'")
        self.c.execute("PRAGMA kdf_iter = 24000")
   
    def generateKey(self, key, salt):
        # 2 Iterations of PBKDF2 SHA256
        return hashlib.pbkdf2_hmac('sha256', key, salt, 2)  
          
    def getCryptoParams(self):
        ret = {}
        # Identity contains stuff to decrypt data columns
        try:
            self.c.execute("SELECT * FROM Identity")
        except sqlite.DatabaseError:
            print("Invalid password")
            sys.exit(1)

        identity = self.c.fetchone()
        
        # Info contains more parameters
        info = identity["Info"]
        
        # Get params from stream
        i = 16 # First 16 bytes are for "mHashData", which is unused
        ret["iv"] = bytearray()
        salt = bytearray()
        while i <= 31:
            ret["iv"].append( info[i] )
            i += 1
        while i <= 47:
            salt.append( info[i] )
            i += 1
            
        ret["iv"]  = bytes(ret["iv"])
        ret["key"] = self.generateKey(identity["Hash"].encode('utf-8'), salt)
            
        return ret
        
    def unpad(self, s):
        return s[0:-ord(s[-1])]
    

    def decrypt(self, enc, key, iv ):
        # PKCS5
        cipher = AES.new(key, AES.MODE_CBC, iv )
        return self.unpad(str(cipher.decrypt(enc), 'utf-8'))
        

    def getCard(self, name):
        self.c.execute("SELECT * FROM Cards")
        cards = self.c.fetchall()
        name = name.lower ()
        clipbrd = None
        results = 0
        names = []
        for card in cards:
            dec = self.decrypt(card["Data"], self.crypto["key"], self.crypto["iv"])
            card = json.loads(dec)
            names.append(card["name"].lower())
            if name in card["name"].lower() and len(card["fields"]) > 0:
                print(pad("Name") + " :" + card["name"])
                for field in sorted(card["fields"], key=lambda x:x['label']):
                    print( pad(field["label"]) + " :" + field["value"] )
                    if field["type"] == "password":
                        results += 1
                        clipbrd = field["value"]
                print( pad("Note :") + "\n" + card["note"] )
        
        if results == 1 and clipbrd is not None:
            copyToClip(clipbrd)
            print("Copied password to clipboard")
        
        with open('/home/niels/Documents/Enpass/.enpassant', 'w') as f:
            for name in names:
                f.write("%s\n" % name)


def main(argv=None):
    import sys

    wallet  = '/home/niels/Documents/Enpass/walletx.db'
    command = ''
    name    = ''

    if argv is None:
        parser = argparse.ArgumentParser ()

        parser.add_argument("command", help="get, copy")
        parser.add_argument("-w", "--wallet", help="The Enpass wallet")
        parser.add_argument("name", help="the entry name")

        args = parser.parse_args()

        command = args.command
        name = args.name
        if args.wallet is not None:
            wallet = args.wallet
    else:
        if len(argv) != 3:
            print("Args: command wallet name")
            sys.exit(1)

        command = argv[0]
        wallet  = argv[1]
        name    = argv[2]

    if (args.command is None or args.command not in ['copy','get']):
        print("Command: copy, get")
        sys.exit(1)

    if not os.path.isfile( wallet ):
        print("Wallet not found: " + wallet)
        sys.exit(1)

    password = getpass.getpass( "Master Password:" )
    en = Enpassant(wallet, password)
    en.getCard( name )

if __name__ == "__main__":
    exit( main() )

