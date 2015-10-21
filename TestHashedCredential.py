import unittest
import HashedCredential

class TestHashedCredentials(unittest.TestCase):

    def test_HashedCredential_init_(self):
        test_good_record = HashedCredential.HashedCredential(username = 'admin', ntlm_hash = '8846F7EAEE8FB117AD06BDD830B7586C', lm_hash = 'E52CAC67419A9A224A3B108F3FA6CB6D')
        self.assertTrue(test_good_record.valid_hashes)
        self.assertEqual(test_good_record.status, 'hashes validated')

        test_bad_hash_record = HashedCredential.HashedCredential(username = 'admin', ntlm_hash = 'TESTBAdData8846F7EAEE8FB117AD06BDD830B7586C', lm_hash = 'E52CAC67419A9A224A3B108F3FA6CB6D')
        self.assertFalse(test_bad_hash_record.valid_hashes)
        self.assertEqual(test_bad_hash_record.status, 'NTLM hash length or character invalid')

    def test_HashedCredential_cracked(self):
        test_crack_record = HashedCredential.HashedCredential(username = 'admin', ntlm_hash = '8846F7EAEE8FB117AD06BDD830B7586C', lm_hash = 'E52CAC67419A9A224A3B108F3FA6CB6D')
        self.assertFalse(test_crack_record.cracked_yet)

        test_crack_record.cracked("password")
        self.assertTrue(test_crack_record.cracked_yet)
        self.assertEqual(test_crack_record.status, 'successfully cracked')
        self.assertEqual(test_crack_record.plaintext, 'password')

    def test_HashedCredential_update_status(self):
        test_good_record = HashedCredential.HashedCredential(username = 'admin', ntlm_hash = '8846F7EAEE8FB117AD06BDD830B7586C', lm_hash = 'E52CAC67419A9A224A3B108F3FA6CB6D')
        self.assertEqual(test_good_record.status, 'hashes validated')

        test_good_record.update_status('free text for testing')
        self.assertEqual(test_good_record.status, 'free text for testing')


if __name__ == '__main__':
    unittest.main()

