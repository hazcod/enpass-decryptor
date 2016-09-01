#!/usr/bin/python2

'''
Enpassant
Made by Steffen Zerbe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
'''

from pysqlcipher import dbapi2 as sqlite
from Crypto.Cipher import AES
import hashlib, binascii
import json
import getpass
import time
import subprocess

def copyToClip(message):
    p = subprocess.Popen(['xclip', '-in', '-selection', 'clipboard'],
                         stdin=subprocess.PIPE, close_fds=True)
    p.communicate(input=message.encode('utf-8'))

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
        ret["iv"] = ""
        salt = ""
        while i <= 31:
            ret["iv"] += info[i]
            i += 1
        while i <= 47:
            salt += info[i]
            i += 1
            
        ret["key"] = self.generateKey(identity["Hash"], salt)
            
        return ret
        
    def unpad(self, s):
        return s[0:-ord(s[-1])]
    

    def decrypt(self, enc, key, iv ):
        # PKCS5
        cipher = AES.new(key, AES.MODE_CBC, iv )
        return self.unpad(cipher.decrypt(enc))
        

    def getCards(self):
        self.c.execute("SELECT * FROM Cards")
        cards = self.c.fetchall()
        ret = []
        for card in cards:
            # Decrypted string
            dec = self.decrypt(card["Data"], self.crypto["key"], self.crypto["iv"])
            # Parsing as object
            item = json.loads(dec)
            ret.append(item)
        return ret
    
    def pad(self, msg):
        return "    " + msg.ljust(18)

    def getCard(self, name):
        self.c.execute("SELECT * FROM Cards")
        cards = self.c.fetchall()
        name = name.lower ()
        clipbrd = None
        results = 0
        for card in cards:
            dec = self.decrypt(card["Data"], self.crypto["key"], self.crypto["iv"])
            card = json.loads(dec)
            if name in card["name"].lower() and len(card["fields"]) > 0:
                print self.pad("Name") + " :" + card["name"]
                for field in card["fields"]:
                    print self.pad(field["label"]) + " :" + field["value"]
                    if field["type"] == "password":
                        results += 1
                        clipbrd = field["value"]
                print self.pad("Note :") + "\n" + card["note"]
        
        if results == 1 and clipbrd is not None:
            copyToClip(clipbrd)
            print("Copied password to clipboard")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("\nusage: " + str(sys.argv[0]) + " name\n")
        sys.exit()
    else:
        wallet = "/home/niels/Documents/Enpass/walletx.db"
        name = sys.argv[1]
        password = getpass.getpass("Master Password:")
        en = Enpassant(wallet, password)
        print ""
        en.getCard(name)
    
    
