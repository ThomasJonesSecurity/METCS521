# adopted from https://www.trustedsec.com/march/generate-an-ntlm-hash-in-3-lines-of-python/

import hashlib,binascii
hash = hashlib.new('md4', "password".encode('utf-16le')).digest()
print(binascii.hexlify(hash))
