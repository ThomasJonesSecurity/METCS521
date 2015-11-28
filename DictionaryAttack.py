import sqlite3
import hashlib
import binascii

PASSWORD_DICTIONARY = 'common_password_list.txt'   # sam test is a simulated file for testing

#def create_rainbow_table_datbase():
connection = sqlite3.connect('rainbow_table.db')
cursor = connection.cursor()
cursor.execute('DROP TABLE IF EXISTS rainbow_table')
cursor.execute('CREATE TABLE rainbow_table(password text, ntlm text)')
connection.commit()

with open(PASSWORD_DICTIONARY,'r') as dictionary:
    for word in dictionary:
        # Compute NTLM Hash
        hash = hashlib.new('md4', word.encode('utf-16le')).digest()
        ntlm = binascii.hexlify(hash)
        cursor.execute('INSERT INTO rainbow_table VALUES (?,?)',(word,ntlm,))
dictionary.close()
connection.commit()
connection.close()

# Insert into table




'''
for password in dictionary:
    cursor.executemany('INSERT INTO rainbow_table VALUES (?,"","")', password)
dictionary.close()
connection.commit()
connection.close()

def read_in_password_dictionary_list():
    conn = sqlite3.connect('rainbow_table.db')
    for row in file(PASSWORD_DICTIONARY,'r').readlines():
        conn.execute("INSERT INTO rainbow_table (text) VALUES (row);")
    return

def read_in_password_dictionary_list:

    return

def compute_ntlm_hashes:

    return

def compute_lm_hashes:

    return
'''