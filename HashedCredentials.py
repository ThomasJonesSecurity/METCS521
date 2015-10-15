# Windows SAM Files store usernames, lm and ntlm hashes.
# This class, HashedCredential, intends to handle the credentials and
# metadata related to attempting to crack the hashes

class HashedCredential:
  
    def __init__(self, username, lm_hash, ntlm_hash):
        self.cracked_yet = false
        self.plaintext = ''
        self.username = username
        
        self.valid_hashes = false # invalid until proven otherwise
        self.status = 'LM and NTLM hashes invalid'
        
        # Checking each hash lengths == 32 and only hex chars
        if len(lm_hash) == 32 and isHex(lm_hash):
            self.lm = lm_hash
            self.status = 'NTLM hash length or character invalid'
            if len(ntlm_hash) == 32 and isHex(ntlm_hash):
                self.ntlm = ntlm_hash
                self.valid_hashes = true
                self.status = 'hashes validated'
        
    def cracked(self, new_plaintext):
        self.cracked_yet = true
        self.plaintext = new_plaintext
        self.status = 'successfully cracked'
        
    def is_cracked(self):
        return self.cracked_yet
        
    def status(self):
        return self.status
        
     def update_status(self,new_status):
        self.status = new_status
  
      def write_output(self):
          print("/n/n Username: {0.username} /n Status: {0.status} /n Cracked: {0.cracked_yet} /n Plaintext: {0.plaintext} \
                 /n LM Hash: {0.lm} /n NTLM Hash: {0.ntlm} /n Valid Hashes: {0.valid_hashes}".format(self))
                
