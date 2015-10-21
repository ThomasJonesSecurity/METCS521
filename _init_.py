import HashedCredential
import os.path
import requests  # pip install requests for web API

SAM_TARGET_FILE = 'sam_test'   # sam test is a simulated file for testing

def read_and_parse_sam_file_lines(sam_filename):
# Intent: read in a SAM file and parse out the users and password hashes
# Precondition: sam_filename is a valid formatted Windows SAM file in
#               the same path as the python file being fun
# Postcondition: returns a tuple, accounts, of HashedCredential objects containing:
#      the username, sam_ntlm_hash and sam_lm_hash from the SAM_TARGET_FILE

    accounts = ()  #empty list

    if os.path.isfile(sam_filename):  #if the file is valid

        sam_file = open(sam_filename)

        for each_line in sam_file:

            # split to parse each_line at each delimiting semicolon & assign
            sam_username = each_line.split(":")[0]
            sam_lm_hash = each_line.split(":")[2]
            sam_ntlm_hash = each_line.split(":")[3]

            # create an instance of HashedCredential for each_line
            user_hashes = HashedCredential.HashedCredential(username = sam_username,
                          ntlm_hash = sam_ntlm_hash, lm_hash = sam_lm_hash)

            # tuple accounts is immuatble. this_accounts is temp in lieu of append()
            this_accounts = (user_hashes,)
            accounts = accounts + this_accounts

        sam_file.close()

    else:  # os.path determined that the sam_filename did not exist
        print("Error locating a file " + sam_filename)

    return accounts

def online_hash_lookup_by_leakedb_api(accounts_list):
# Intent: check http://api.leakdb.net for each hash stored in accounts_list
# Precondition: accounts_list has each key as a username and the value
#               associated with the key is a list of hashed passwords
# Postcondition: prints the username and crack attempt results to screen

    for this_user in accounts_list:

        # request this this_user ntlm hash from LeakDB API
        r = requests.get('https://api.leakdb.net/?j=%s' % this_user.ntlm)  # ?j for JSON
        json = r.json()

        if json['found'] == "true":
            this_user.cracked(json['hashes'][0]['plaintext'])

        else:  # ntlm wasn't cracked. try lm
            r = requests.get('https://api.leakdb.net/?j=%s' % this_user.lm)  # ?j for JSON
            json = r.json()
            if json['found'] == "true":
                this_user.cracked(json['hashes'][0]['plaintext'])

        this_user.write_output()  # echo results

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
