import sqlite3
import base64, binascii
import struct
import sys
import hashlib, hmac
import getpass
from Crypto.Cipher import AES

WINDOWS_1PASSWORD_DB_FILE = '1Password10.sqliteE'
ENCRYPTION_ALGO = 'sha512'
DEBUG = False

class Windows1PasswordDB:
    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection
        self.cursor = connection.cursor()

    def getConfig(self) -> dict:
        dbVals = self.cursor.execute('select name, value from config')

        return dict(dbVals)

    def getEncryptedMasterKey(self) -> bytes:
        return self.getConfig()['EncryptedMasterKey']

def openDB(filename: str) -> Windows1PasswordDB:
    return Windows1PasswordDB(sqlite3.connect(WINDOWS_1PASSWORD_DB_FILE))

def printBin(prefix, raw):
    if DEBUG:
        print(prefix, bintoAscii(raw))

def bintoAscii(raw) -> str:
    return binascii.b2a_hex(raw).decode('utf-8')

def decrypt_opdata(opdata, enc_key, hmac_key):
    if DEBUG:
        print('Unpacking OPData')
    printBin('Raw opdata:', opdata)

    if opdata[0:8] != b'opdata01':
        print("ERROR - opdata01 block missing 'opdata01' header. Quitting.")
        sys.exit(1)

    if DEBUG:
        print('Header:', opdata[0:8].decode('utf-8'))

    pt_len = struct.unpack('<Q', opdata[8:16])[0]
    if DEBUG:
        print('Plain Text length:', pt_len)

    iv = opdata[16:32]
    printBin('Initialisation Value:', iv)

    ct = opdata[32:-32]  # header + iv: 32 bytes; trailing HMAC tag: 32 bytes
    printBin('Cipher Text', ct)

    ht = opdata[-32:]
    printBin('HMAC digest:', ht)

    printBin('OPdata Msg:', opdata[0:-32])   # don't HMAC the provided HMAC tag
    printBin('HMAC key:', hmac_key)
    hm = hmac.new(hmac_key, opdata[0:-32], digestmod=hashlib.sha256)
    printBin('Computed HMAC:', hm.digest())

    if hm.digest() != ht:
        if DEBUG:
            print("ERROR - Computed HMAC does not match provided value.")
        sys.exit(1)
    else:
        if DEBUG:
            print("HMAC signature verified.")

    C = AES.new(enc_key, AES.MODE_CBC, iv)
    PT = C.decrypt(ct)

    start_at = len(ct) - pt_len

    PT=PT[start_at:] # first x bytes are random padding

    if DEBUG:
        print("\n\n")
        print("*** decrypted opdata")
    printBin('Plaintext:', PT)

    enc_key = PT[0:32]
    hmac_key = PT[32:]

    printBin('Encrypted master key:', enc_key)
    printBin('Encrypted HMAC key:', enc_key)

def validatePassword(emk: bytes, pw: bytes) -> bool:
    if DEBUG:
        print('Decoding master key')
    b = base64.b64decode(emk + '==', altchars='-_')
    printBin("Decoded master key:", b)

    iterations = struct.unpack('<I', b[0:4])[0]

    if DEBUG:
        print('Iterations:', iterations)

    saltLength = struct.unpack('<I', b[4:8])[0]
    if saltLength != 16:
        print("Unexpected salt length of {}. quitting.".format(saltLength))
        sys.exit(1)
    
    salt = b[8:24]

    if DEBUG:
        print('Salt length:', saltLength)
    printBin('Salt:', salt)

    raw_key = hashlib.pbkdf2_hmac(ENCRYPTION_ALGO, pw, salt, iterations)

    printBin('Raw derived key:', raw_key)

    emk_enc_key = raw_key[0:32]
    emk_hmac_key = raw_key[32:64]
    printBin('Derived enc key:', emk_enc_key)
    printBin('Derived hmac key:', emk_hmac_key)

    payloadLength = struct.unpack('<I', b[24:28])[0]
    if DEBUG:
        print("Payload length:", payloadLength)

    opdata = b[28:]
    
    if len(opdata) != payloadLength:
        print("Unexpected payload length of {}. quitting.".format(len(opdata)))
        sys.exit(1)

    try:
        decrypt_opdata(opdata, emk_enc_key, emk_hmac_key)
        return True
    except:
        return False

if __name__ == "__main__":
    print('Opening DB')
    db = openDB(WINDOWS_1PASSWORD_DB_FILE)

    print('Extracting encrypted master key')
    emk = db.getEncryptedMasterKey()

    pw = getpass.getpass().encode()

    valid = validatePassword(emk, pw)

    print("Correct password:", valid)