from pysqlcipher import dbapi2 as sqlite
from Crypto.Cipher import AES
import hashlib, binascii
import json

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
        self.c.execute("SELECT * FROM Identity")
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
    
    def dumpCards(self):
        cards = self.getCards()
        for card in cards:
            name = card["name"] + ".json"
            with open(name, 'w') as out:
                json.dump(card, out)
            
        
if __name__ == "__main__":
    import sys
    if len(sys.argv ) < 3:
        print("\nusage: " + str(sys.argv[0]) + " walletx.db password\n")
        sys.exit()
    else:
        en = Enpassant(sys.argv[1], sys.argv[2])
        en.dumpCards();
    
    