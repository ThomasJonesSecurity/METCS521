import HashedCredential    # custom class for account objects
import DictionaryAttack    # dictionary to rainbow table lookup attack
import OnlineLookupAttack  # threaded online lookup attack by api.leakdb.net

from GlobalValues import sam_target_file      # default SAM file of hashed passwords
from GlobalValues import PASSWORD_DICTIONARY  # dictionary text file of common passwords

import os
from tkinter.filedialog import askopenfilename  # Tk GUI for SAM file browse dialog only
from tkinter import *

# MODULE PURPOSE a GUI is drawn to offer user to browse for a SAM file to crack. Once the crack button
# event is clicked by user: the file selected is parsed for hashes and a dictionary attack is conducted.
# Any accounts remaining uncracked are submitted to an online lookup attack.  Results and summary are
# printed to the console.

# ATTACK SEQUENCE function pass_file_choice_to_cracking() nested in draw_gui() coordinates the attacks and output.
# that function orchestrates most of the other modules to obtain, track and attack the one target SAM file.


def read_and_parse_sam_file_lines(sam_filename):
    # Intent: read in a SAM file and parse out the users and password hashes
    # Precondition: sam_filename is a valid formatted Windows SAM file in
    #               the same path as the python file being fun
    # Post Condition: returns a tuple, accounts, of HashedCredential objects containing:
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
    # Intent: print results and simple summary of how successful the attacks were to console
    # Pre Condition 1: list_of_accounts is list of HashedCredential objects. Ideally that have been through an attack function.
    # Post Condition 1: Print all HashedCredential object's values of interest for each account in the list
    # Post Condition 2: Print usernames and plaintext passwords
    # Post Condition 3: Prints percentage and number of accounts cracked vs. number of accounts in SAM file

    cracked_count = 0
    account_count = 0

    #Post 1: HashedCredential values to Console
    for account in list_of_accounts:
        account_count += 1  # how many accounts
        account.write_output()  # show HashedCredential values
        if account.cracked_yet:
            cracked_count += 1  # count the cracked ones

    # Post 2: Accounts to Console
    print("\n\n\n\n CRACKED ACCOUNTS:\n--------------------------------------------------------- ")
    for account in list_of_accounts:
        account.write_user_and_plaintext()

    # Post 2: Summary Statistics
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
    # Post Condition 1: Allows user to reset sam_target_file to another file with Browse button
    # Post            : pass sam_target_file for reading, account parsing, DictionaryAttack and OnlineLookupAttack
    # Post Condition 2: Show user the path and filename of sam_target_file if they've browsed to a file
    # Post Condition 3: Call read_and_parse_sam_file_lines and online_hash_lookup_by_leakedb_api
    # with the argument sam_target_file (default or user selected)

    gui_sam_target_file = sam_target_file  #default from GlobalValues

    # Post 1: User get file
    def get_file_choice():
        global gui_sam_target_file

        gui_sam_target_file = askopenfilename(
            initialdir=os.getcwd(), initialfile="SAM")

        entry.delete(0, END)
        entry.insert(0, gui_sam_target_file)

    # Post 2 : Read, parse, attack, and summarize
    def pass_file_choice_to_cracking():
        global gui_sam_target_file

        root.destroy() # close window, remaining work on console

        # Read and parse accounts and hashes:
        print("\n Reading in accounts from selected file:",
              gui_sam_target_file, " . . . \n")
        accounts = read_and_parse_sam_file_lines(gui_sam_target_file)

        # DictionaryAttack
        print("\n Cracking using database computer from dictionary:",
              PASSWORD_DICTIONARY, ". . . \n")
        DictionaryAttack.ntlm_rainbow_table_attack(
            PASSWORD_DICTIONARY, accounts)

        # OnlineLookupAttack on remaining accounts not cracked by DictionaryAttack
        print("\n Cracking any remaining accounts with an online lookup through api.leak.db . . . \n")
        OnlineLookupAttack.online_hash_lookup_by_leakedb_api(
            DictionaryAttack.uncracked_accounts(accounts))

        #Summarize
        print_cracking_summary(accounts)
        return


    # Draw GUI
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

    # Post Condition 2 - Show selected sam_target_file to user in GUI
    entry = Entry(f1, width=50, textvariable=sam_target_file)
    entry.grid(row=0, column=1, padx=2, pady=2, sticky='we', columnspan=25)

    # Post Condition 1 - Button to Browse for file
    Button(
        f1,
        text="Browse",
        command=get_file_choice).grid(
        row=0,
        column=27,
        sticky='ew',
        padx=8,
        pady=4)

    # Post Condition 3 - Button to call parse and crack functions
    Button(
        f2,
        text="Crack - Output to Console",
        width=32,
        command=pass_file_choice_to_cracking).grid(
        sticky='ew',
        padx=10,
        pady=10)

    root.mainloop()
