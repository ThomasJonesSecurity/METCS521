import HashedCredential
import DictionaryAttack
import OnlineLookupAttack
from GlobalValues import sam_target_file
from GlobalValues import PASSWORD_DICTIONARY

import os
from tkinter.filedialog import askopenfilename
from tkinter import *


def read_and_parse_sam_file_lines(sam_filename):
    # Intent: read in a SAM file and parse out the users and password hashes
    # Precondition: sam_filename is a valid formatted Windows SAM file in
    #               the same path as the python file being fun
    # Post condition: returns a tuple, accounts, of HashedCredential objects containing:
    #      the username, sam_ntlm_hash and sam_lm_hash from the sam_target_file

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


def print_cracking_summary(list_of_accounts):
    cracked_count = 0
    account_count = 0

    for account in list_of_accounts:
        account_count += 1
        account.write_output()
        if account.cracked_yet:
            cracked_count += 1

    print("\n\n\n\n CRACKED ACCOUNTS:\n--------------------------------------------------------- ")
    for account in list_of_accounts:
        account.write_user_and_plaintext()

    print("\n SUMMARY:\n--------------------------------------------------------- ")
    print(
        "         ",
        100 *
        float(cracked_count) /
        float(account_count),
        "% of accounts successfully cracked")
    print(
        "         ",
        cracked_count,
        " of",
        account_count,
        "accounts provided have been cracked")

    return


def draw_gui():
    # Intent: provide a tkinter GUI that allows user to browse for a valid SAM file
    #         and then takes that input file through the parse and crack functions
    # Precondition: sam_target_file is globally initialized to a valid default SAM file
    # Precondition: Display able to render with static geometry dimensions 698x120+250+100
    # Post condition 1: Allows user to reset sam_target_file to another file with Browse button
    # Post condition 2: Show user the path and filename of sam_target_file if they've browsed to a file
    # Post condition 3: Call read_and_parse_sam_file_lines and online_hash_lookup_by_leakedb_api
    # with the argument sam_target_file (default or user selected)

    def get_file_choice():

        gui_sam_target_file = askopenfilename(
            initialdir=os.getcwd(), initialfile="SAM")
        entry.delete(0, END)
        entry.insert(0, gui_sam_target_file)

    def pass_file_choice_to_cracking():
        root.destroy()
        print("\n Reading in accounts from selected file:",
              sam_target_file, " . . . \n")
        accounts = read_and_parse_sam_file_lines(sam_target_file)
        print("\n Cracking using database computer from dictionary:",
              PASSWORD_DICTIONARY, ". . . \n")
        DictionaryAttack.ntlm_rainbow_table_attack(
            PASSWORD_DICTIONARY, accounts)
        print("\n Cracking any remaining accounts with an online lookup through api.leak.db . . . \n")
        OnlineLookupAttack.online_hash_lookup_by_leakedb_api(
            DictionaryAttack.uncracked_accounts(accounts))
        print_cracking_summary(accounts)
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
                  (Try SAM in the current working directory)')\
        .grid(row=0, column=0, sticky='e')

    # Post condition 2 - Show selected sam_target_file to user in GUI
    entry = Entry(f1, width=50, textvariable=sam_target_file)
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
