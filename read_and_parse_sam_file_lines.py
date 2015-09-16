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

# Initial Values For Testing
sam_target_file = 'sam_test'  # sam test is a simulated file for testing

def main():
    # if the file string sam_target is determined valid by os.path
    if os.path.isfile(sam_target_file):

        # open the file identified by string sam_target_file as sam_file
        sam_file = open(sam_target_file)

        # read in sam_file line by line
        for each_line in sam_file:

            # start this line on a new line
            print("READ IN: " + each_line, end='')

            # split line at each delimiting semicolon & assign
            sam_username = each_line.split(":")[0]
            sam_lm_hash = each_line.split(":")[2]
            sam_ntlm_hash = each_line.split(":")[3]

            # output for testing
            print("PARSED:  " +sam_username + " " + sam_lm_hash + " " + sam_ntlm_hash)

        # close file after all lines have been handled
        sam_file.close()

    else:  # os.path determined that the file did not exist
        print("Error locating a file " + sam_target_file)

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
