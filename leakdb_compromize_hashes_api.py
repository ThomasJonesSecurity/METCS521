# adopted from http://blog.abusix.com/2013/07/08/using-leakdb-for-compromised-password-hashes/
# Requests dependancy installed by $ sudo pip install requests

#  resolve given hashes to plain text passwords: leakdb-hashes.py

import requests

hashes = ['482c811da5d5b4bc6d497ffa98491e38',                                   # md5 of password123
          'ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548' +
          'baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413',   # sha512 of '123456'
          '1234512345123451234512345123451234512345',                           # invalid checksum
          '1e420eb085cb98428a2da2cca8b90918ad790a74']                           # sha1 of 's3cr3tpw!'

for hash_value in hashes:
    # Use the j parameter for json output
    r = requests.get('https://api.leakdb.net/?j=%s' % hash_value)
    json = r.json()
    if json['found'] == 'true':
        print('plaintext for %s => %s' % (hash_value, json['hashes'][0]['plaintext']))
    else:
        print('plaintext for %s not found ' % (hash_value))
