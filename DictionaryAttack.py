from GlobalValues import DATABASE # name of db in project

import binascii  # to encode hash as hex
import hashlib   # to compute hash
import sqlite3   # for database

# MODULE PURPOSE is to create a rainbow table of passwords and associatefd percomputed ntlm hashes
# the rainbow table enables a reverse lookup of a password if the matched unsalted hash is
# found in the database.


def plaintext_to_ntlm(plaintext):
    # Inent: plaintext -> NTLM hash
    # Precondition: argument is ascii alpha-numeric string
    # Postcondition: return the uppercase ciphertext NTLM hash computed from the plaintext

    # Algorithm for NTLM hashing with no salt:
    md4_hash = hashlib.new('md4', plaintext.encode('utf-16le')).digest()  # md4 hash digest
    decoded_hash = binascii.hexlify(md4_hash).decode("utf-8")  # Hex in readable format

    ntlm_hash = str(decoded_hash).upper()  # all caps
    return ntlm_hash


def precompute_rainbow_table_db(dictionary_file):
    # Intent: Initialize database rainbow_table.db with records of passwords and corresponding ntlm hash values
    # Precondition: dictionary_file must be a valid text file with one potential password per line
    #    duplicate lines reduce the lookup efficiency and should not exist in dictionary_file
    # Post Condition 1: sqlite3 DATABASE created or used if already exists
    # Post Condition 2: rainbow_table in DATABASE created or recreated if alreday exists
    # Post Condition 3: read string from all lines of dictionary_file
    # Post Condition 4: compute ntlm hash and insert it into the

    # Post Condition 1: create or connect db
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Post Condition 2: create Table rainbow_table
    cursor.execute('DROP TABLE IF EXISTS rainbow_table')
    cursor.execute('CREATE TABLE rainbow_table(password text, ntlm text)')
    connection.commit()

    # Post Condition 3:
    with open(dictionary_file, 'r') as dictionary:
        for word in dictionary:
            # Post Condition 4: Compute NTLM Hash
            ntlm = plaintext_to_ntlm(word.rstrip('\n'))  # trim newline char

            cursor.execute(
                'INSERT INTO rainbow_table VALUES (?,?)', (word, ntlm,))  # Insert into table

    # Close and commit for file and db
    dictionary.close()
    connection.commit()
    connection.close()

    return


def rainbow_table_lookup(ntlmhash):
    # Intent: return password of ntlmhash if exist in DATABASE rainbow_table
    # Precondition 1: ntlmhash arugment is string of valid uppercase NTLM hash
    # Precondition 2: DATABASE and rainbow_table populated with plaintext passwords and matching NTLM hashe relationships
    # Post Condition 1: if record is not found, return None
    # Post Condition 2: if a record where ntlm matches ntlmhash, then the related password is returned

    # db connection
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT password FROM rainbow_table WHERE ntlm=?", (ntlmhash,))  # search db of ntlm for ntlmhash
    record = cursor.fetchone()  # get the record at cursor
    connection.close()

    if record is None: # no matching ntlm found
        return None
    else:  # match found
        return record[0]  # return the password element of record


def ntlm_rainbow_table_attack(dictionary, accounts_list):
    # Intent: precompute a rainbow table of NTLM hashes from dictionary
    #         try to find try matched hash in accounts_list to determing plaintext password
    # Precondition 1: dicionary is ascii text file with likley aplha-numeric passwords one-per-line
    # Precondition 2: accounts_list is list of at least one HashedCredential objects
    # Post Condition 1: database created from dictionary
    # Post Condition 2: every HashedCredential element in accounts_list has the ntlm value compared
    #         to the database ntlm values and match is plaintext found or None
    # Post Condition 3: if match is plaintext password HashedCredential.crack() and .update(status)
    #         write cracked record to accounts_list (else is implicity condition that match is None
    #         and no instruction is required just the same return)

    # Post Condition 1: initilize lookup rainbow table db from dictionary
    precompute_rainbow_table_db(dictionary)

    # Post Condition 2: match gets plaintext password or None for all elements
    for each_user in accounts_list:
        match = rainbow_table_lookup(each_user.ntlm)

        # Post Condition 3: update if match isn't None
        if match:
            # HashedCredential object methods for updating plaintext and status
            each_user.cracked(str(match).rstrip('\n'))
            each_user.update_status(
                "successfully cracked by dictionary attack")

    return


def uncracked_accounts(account_list):
    # Intent: returns list accounts not yet cracked by this attack.  This allows other attacks to
    #         be skip accounts cracked here.
    # Precondition 1: accounts_list is list of at least one HashedCredential objects
    # Post Condition 1: uncracked is list of all account_list elements where crack_yet is False
    uncracked = []

    # Post Condition 1: uncracked appended if not cracked_yet
    for account in account_list:
        if not account.cracked_yet:
            uncracked.append(account)

    return uncracked
