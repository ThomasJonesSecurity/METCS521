import HashedCredential
import requests  # pip install requests for web API
import os
from tkinter.filedialog import askopenfilename
from tkinter import *

SAM_TARGET_FILE = 'sam_test'   # sam test is a simulated file for testing
content = ''             # Used byDraw GUI
file_path = ''           # Used byDraw GUI


def draw_gui():

    def open_file(): # Used byDraw GUI
        global content
        global file_path

        filename = askopenfilename(initialdir=os.getcwd(),initialfile="sam_test")
        infile = open(filename, 'r')
        content = infile.read()
        file_path = os.path.dirname(filename)
        entry.delete(0, END)
        entry.insert(0, filename)
        return content

    def process_file(content):    # Used byDraw GUI
        print(content)

    root = Tk()
    root.title('SAM File Crack')
    root.geometry("698x120+250+100")

    mf = Frame(root)
    mf.pack()

    f1 = Frame(mf, width=700, height=250)
    f1.pack(fill=X)
    f2 = Frame(mf, width=700, height=250)
    f2.pack()

    file_path = StringVar

    Label(f1,text='Select a valid Windows SAM  file \n (Try sam_test in the current working directory)').grid(row=0, column=0, sticky='e')
    entry = Entry(f1, width=50, textvariable=file_path)
    entry.grid(row=0,column=1,padx=2,pady=2,sticky='we',columnspan=25)
    Button(f1, text="Browse", command=open_file).grid(row=0, column=27, sticky='ew', padx=8, pady=4)
    Button(f2, text="Crack Accounts", width=32, command=lambda: process_file(content)).grid(sticky='ew', padx=10, pady=10)

    root.mainloop()

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
    draw_gui() #@TODO Draw GUI should pass SAM_TARGET_FILE
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
