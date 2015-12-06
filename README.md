# Intent - SAM File Credential Cracking
This program will attempt to read Windows SAM file, parse the file, and launch an attack against the hashed credentials.
The current attacks rely on an online lookup of leaked or precomputed hashes through a API provided by http://api.leakdb.net/ and a text file dictionary of common passwords.

# Usage
Execute python3 _init_.py and a GUI file browse dialog will allow for the selection of a Windows SAM file.
Cracking output and results will be output to the console.

# Interpreter and Libraries
Python Interpreter Version 3.x

# Author: Thomas Jones
Last Modified: 12/6/2015

# Academic Context
This is my personal project for MET CS 521 Information Structures in Python Project.
All code is an course related academic exercise. This is an academic hash cracking exercise based on existing attack algorithms so I am going to simulate password attacks.  This is not intended nor warranted for any use. These tasks have all been accomplished by more experience developers.  Please feel free to ask me questions, but understand that this code might never see a production ready level of functionality.

The SAM file and common_password_list.txt dictionary are contrived test files. The dictionary is nowhere near extensive  for significant key-space hash attacks.

# Dependencies / Python Libraries Used
binascii
hashlib
sqlite3
urllib
string
json
time
queue
threading
unittest
os
tkinter

# Unit Test
TestHashedCredentials.py

# Attribution and Citation:
Learned to use a main function and protect against execution in modules from:
Guido van Rossum blog in 2003
https://www.artima.com/weblogs/viewpost.jsp?thread=4829

Learned to use os.path for basic file verification from a StackOverflow thread:
http://stackoverflow.com/questions/82831/check-whether-a-file-exists-using-python

Example SAM file found online from KPMG Advisory N.V
http://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf

Adopted LeakDB lookup from:
http://blog.abusix.com/2013/07/08/using-leakdb-for-compromised-password-hashes/

tkinter Entry() technique adapted from: http://effbot.org/zone/tkinter-geometry.htm

