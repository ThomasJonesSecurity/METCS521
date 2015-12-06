import HashedCredential
import sqlite3   # for database
import hashlib   # to compute hash
import binascii  # to encode hash as hex

# Purpose is to create a rainbow table of passwords and associatefd percomputed ntlm hashes
# the rainbow table enables a reverse lookup of a password if the matched unsalted hash is
# found in the database.

DATABASE = 'rainbow_table.db'


def plaintext_to_ntlm(plaintext):
    hash = hashlib.new('md4', plaintext.encode('utf-16le')).digest()
    decoded_hash = binascii.hexlify(hash).decode("utf-8")
    ntlm = str(decoded_hash).upper()
    return ntlm


def precompute_rainbow_table_db(dictionary_file):
    # Intent: Initialize database rainbow_table.db with records of passwords and corresponding ntlm hash values
    # Precondition: dictionary_file must be a valid text file with one potential password per line
    #    duplicate lines reduce the lookup efficiency and should not exist in dictionary_file
    # Post Condition 1: ranibow_table.db created or tables reset if it already existed
    # Post Condition 2: read string from all lines of dictionary_file
    # Post Condition 3: compute ntlm hash

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute('DROP TABLE IF EXISTS rainbow_table')
    cursor.execute('CREATE TABLE rainbow_table(password text, ntlm text)')
    connection.commit()

    with open(dictionary_file, 'r') as dictionary:
        for word in dictionary:
            # Compute NTLM Hash
            ntlm = plaintext_to_ntlm(word.rstrip('\n'))
            # Insert into table
            cursor.execute(
                'INSERT INTO rainbow_table VALUES (?,?)', (word, ntlm,))

    dictionary.close()
    connection.commit()
    connection.close()
    return


def rainbow_table_lookup(ntlmhash):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT password FROM rainbow_table WHERE ntlm=?", (ntlmhash,))
    record = cursor.fetchone()
    connection.close()
    if record is None:
        return None
    else:
        return record[0]


def ntlm_rainbow_table_attack(dictionary, accounts_list):
    precompute_rainbow_table_db(dictionary)
    for each_user in accounts_list:
        match = rainbow_table_lookup(each_user.ntlm)
        if match:
            each_user.cracked(str(match).rstrip('\n'))
            each_user.update_status(
                "successfully cracked by dictionary attack")
    return


def uncracked_accounts(account_list):
    uncracked = []
    for account in account_list:
        if not account.cracked_yet:
            uncracked.append(account)
    return uncracked
