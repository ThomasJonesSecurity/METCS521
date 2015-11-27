# METCS521

All code posted here is an course related academic exercise.
This is an academic hash cracking exerise based on exisitng attack algorithms so I am going to simulate password attacks.  This is not intended for any use.

Again this code is not fit for any use.  These tasks have all been accomplished by more experience developers.  Please feel free to ask me questions, but understand that this code might never see a production ready level of functionality.


The program will attempt to lookup or crack Windows passwords.  The input will be a simulated file of a Security Account Manager (SAM). The SAM file is a database file that stores account user names and hashed (LM and NTLM) passwords.  The output will show account user names along with the corresponding plain-text passwords (or an indication that the hash was not cracked).

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
