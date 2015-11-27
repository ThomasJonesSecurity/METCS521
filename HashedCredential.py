import string # used to confirm hex characters

# Windows SAM Files store usernames, lm and ntlm hashes.
# This class, HashedCredential, intends to handle the credentials and
# metadata related to attempting to crack the hashes

class HashedCredential:

    def __init__(self, username, lm_hash, ntlm_hash):
    # Intent: Object stores username, ntlm hash string, and lm has string
    #         Also provide status meta-data indicated status of cracking attempt
    # Precondition: all arguments provided as single-line strings
    # Post condition: initializes an object containing the strings from arguments
    #         Post 1:   as well as default (un-cracked) status values
    #         Post 2:   does some basic length and character checks to help
    #                   validate the input hash strings

        #Post 1 - default values
        self.cracked_yet = False
        self.plaintext = ''
        self.username = username

        # invalid until proven otherwise
        self.valid_hashes = False
        self.status = 'LM and NTLM hashes invalid'
        self.lm = 'Invalid LM hash'
        self.ntlm = 'Invalid NTLM hash'


        # Post 1 - hexadecimal and length check of lm_hash and ntlm_hash

        def is_hex(test_for_hex):
        # used to confirm hex characters
            return all(c in string.hexdigits for c in test_for_hex)

        if len(lm_hash) == 32 and is_hex(lm_hash):
        # lm_hash and ntlm_hash strings must contain hexadecimal characters only
        # Checking each hash lengths == 32 and only hex chars
            self.lm = lm_hash
            self.status = 'NTLM hash length or character invalid'
            if len(ntlm_hash) == 32 and is_hex(ntlm_hash):
                self.ntlm = ntlm_hash
                self.valid_hashes = True
                self.status = 'hashes validated'

        if self.valid_hashes == False:
            print("WARNING: Likely Bad Hash Input : ", self.status)

    def cracked(self, new_plaintext):
    # Intent: update object with provided plaintext password
    # Precondition: assuming that the function provides a plaintext password string
    #               that is the proper cracked password from the hashes contained in the object
    # Post condition: updates status, cracked_yet flag, and plaintext
    #                   validate the input hash strings
        self.cracked_yet = True
        self.plaintext = new_plaintext
        self.status = 'successfully cracked'

    def update_status(self,new_status):
    # Intent: self.status is using a free-text string to describe the object's state
    # Precondition: a text string is provided as the new_status
    # Post condition: updates status
         self.status = new_status

    def write_output(self):
    # Intent: Provides basic format to output all object values with descriptions
    # Precondition: Object contains printable values
    # Post condition: prints output of all object values to screen
          print("\n\n Username: {0.username} \n Status: {0.status} \n Cracked: {0.cracked_yet} \n Plaintext: {0.plaintext} \
                 \n LM Hash: {0.lm} \n NTLM Hash: {0.ntlm} \n Valid Hashes: {0.valid_hashes}".format(self))
