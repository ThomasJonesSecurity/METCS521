import sqlite3
import hashlib
import binascii

PASSWORD_DICTIONARY = 'common_password_list.txt'

def precompute_rainbow_table_db(dictionary_file):
    connection = sqlite3.connect('rainbow_table.db')
    cursor = connection.cursor()
    cursor.execute('DROP TABLE IF EXISTS rainbow_table')
    cursor.execute('CREATE TABLE rainbow_table(password text, ntlm text)')
    connection.commit()

    with open(dictionary_file,'r') as dictionary:
        for word in dictionary:
            # Compute NTLM Hash
            hash = hashlib.new('md4', word.encode('utf-16le')).digest()
            ntlm = binascii.hexlify(hash).decode("utf-8")
            # Insert into table
            cursor.execute('INSERT INTO rainbow_table VALUES (?,?)',(word,ntlm,))

    dictionary.close()
    connection.commit()
    connection.close()
    return

def rainbow_table_lookup(ntlmhash):
    connection = sqlite3.connect('rainbow_table.db')
    cursor = connection.cursor()
    cursor.execute("SELECT password FROM rainbow_table WHERE ntlm=?", (ntlmhash,))
    record = cursor.fetchone()
    connection.close()
    if record is None:
        print("There is no password match in the given dictionary: ",PASSWORD_DICTIONARY)
        return None
    else:
        return record[0]


precompute_rainbow_table_db(PASSWORD_DICTIONARY)
print(rainbow_table_lookup("4f2dbc410d6a0e7dcc7a41978"))
