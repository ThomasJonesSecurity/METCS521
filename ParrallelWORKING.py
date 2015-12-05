# Author: Thomas Jones
# Last Modified: 11/4/2015
# Written for python3 interpreter
#
# MET CS 521 Information Structures in Python Project
# -------------------------------------------------------------------
# Will attempt to read Windows SAM file, parse the file, and launch
# an attack against the hashed credentials.
#
# The current attack relies on the online lookup of leaked or precomputed
# hashes through a API provided by https://leakdb.abusix.com/
#
# Stores the credential
# data and meta-data in object provided by the class HashedCredential.py 

import HashedCredential
import DictionaryAttack


import requests  # pip install requests for web API
import os
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
    # Post: Content of a_url is at the back #######################
    a_queue.put(requests.get(a_url))

def online_hash_lookup_by_leakedb_api(accounts_list):
    # Intent: check http://api.leakdb.net for each hash stored in accounts_list
    # Precondition: accounts_list has each key as a username and the value
    #               associated with the key is a list of hashed passwords
    # Precondition: able to reach api.leakdb.net over the internet
    # Post condition: prints the username and crack attempt results to console

    ntlm_urls = []
    lm_urls = []
    ntlm_queue = Queue()
    lm_queue = Queue()

    for each_user in accounts_list:
        # request this each_user ntlm hash from LeakDB API
        ntlm_urls.append('https://api.leakdb.net/?j=%s' % each_user.ntlm)
        lm_urls.append('https://api.leakdb.net/?j=%s' % each_user.lm)

    print(ntlm_urls)  #######################################################################################
    print(lm_urls)  #######################################################################################

    for url in ntlm_urls:
        thread = Thread(target=get_url, args=(ntlm_queue, url))
        thread.start()

    print(ntlm_queue.get())  #######################################################################################
    print(lm_queue.get())  #######################################################################################

    for url in lm_urls:
        thread = Thread(target=get_url, args=(lm_queue, url))
        thread.start()
    pt
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

def ntlm_rainbow_table_attack(dictionary,accounts_list):
    DictionaryAttack.precompute_rainbow_table_db(dictionary)
    for each_user in accounts_list:
        match = DictionaryAttack.rainbow_table_lookup(each_user.ntlm)
        if match:
            each_user.cracked(match)
    return

def draw_gui():
    # Intent: provide a tkinter GUI that allows user to browse for a valid SAM file
    #         and then takes that input file through the parse and crack functions
    # Precondition: SAM_TARGET_FILE is globally initialized to a valid default SAM file
    # Precondition: Display able to render with static geometry dimensions 698x120+250+100
    # Post condition 1: Allows user to reset SAM_TARGET_FILE to another file with Browse button
    # Post condition 2: Show user the path and filename of SAM_TARGET_FILE if they've browsed to a file
    # Post condition 3: Call read_and_parse_sam_file_lines and online_hash_lookup_by_leakedb_api
    #                  with the argument SAM_TARGET_FILE (default or user selected)

    def get_file_choice():
        global SAM_TARGET_FILE

        SAM_TARGET_FILE = askopenfilename(
            initialdir=os.getcwd(), initialfile="sam_test")
        entry.delete(0, END)
        entry.insert(0, SAM_TARGET_FILE)

    def pass_file_choice_to_cracking():
        credentials = read_and_parse_sam_file_lines(SAM_TARGET_FILE)
        # online_hash_lookup_by_leakedb_api(credentials) ##############################################
        ntlm_rainbow_table_attack(PASSWORD_DICTIONARY,credentials)
        return

    root = Tk()
    root.title('SAM File Crack')
    root.geometry("698x120+250+100")

    mf = Frame(root)
    mf.pack()

    f1 = Frame(mf, width=700, height=250)
    f1.pack(fill=X)
    f2 = Frame(mf, width=700, height=250)
    f2.pack()

    Label(f1, text='Select a valid Windows SAM  file \n \
                  (Try sam_test in the current working directory)')\
        .grid(row=0, column=0, sticky='e')

    # Post condition 2 - Show selected SAM_TARGET_FILE to user in GUI
    entry = Entry(f1, width=50, textvariable=SAM_TARGET_FILE)
    entry.grid(row=0, column=1, padx=2, pady=2, sticky='we', columnspan=25)

    # Post condition 1 - Button to Browse for file
    Button(
        f1,
        text="Browse",
        command=get_file_choice).grid(
        row=0,
        column=27,
        sticky='ew',
        padx=8,
        pady=4)

    # Post condition 3 - Button to call parse and crack functions
    Button(
        f2,
        text="Crack - Output to Console",
        width=32,
        command=pass_file_choice_to_cracking).grid(
        sticky='ew',
        padx=10,
        pady=10)

    root.mainloop()

def main():
    ## draw_gui() #################  S K I P    G U I  ########################################################################################################
    read_in_accounts = read_and_parse_sam_file_lines(SAM_TARGET_FILE)
    online_hash_lookup_by_leakedb_api(read_in_accounts)
    ###########################################################ntlm_rainbow_table_attack(PASSWORD_DICTIONARY,read_in_accounts)
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
#
# tkinter Entry() technique adapted from: http://effbot.org/zone/tkinter-geometry.htm
