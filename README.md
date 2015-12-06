# Intent - SAM File Credential Cracking
This program will attempt to read Windows SAM file, parse the file, and launch an attack against the hashed credentials.
The current attack relies on the online lookup of leaked or precomputed hashes through a API provided by https://leakdb.abusix.com/

# Project for MET CS 521 Information Structures in Python Project
All code is an course related academic exercise. This is an academic hash cracking exercise based on existing attack algorithms so I am going to simulate password attacks.  This is not intended for any use.
Again this code is not fit for any use.  These tasks have all been accomplished by more experience developers.  Please feel free to ask me questions, but understand that this code might never see a production ready level of functionality.

# Dependency prerequisites
Python Interpreter Version 3.x
Request for WebResponse:  pip install requests

# Author: Thomas Jones
Last Modified: 11/27/2015


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