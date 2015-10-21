import HashedCredential

record = HashedCredential.HashedCredential(username = 'admin', ntlm_hash = '8846F7EAEE8FB117AD06BDD830B7586C', lm_hash = 'E52CAC67419A9A224A3B108F3FA6CB6D')

record.write_output()
print("\nLogical is_cracked(): False <----> ", record.is_cracked())
print("\nStatus: hashes validated <----> ", record.status)
record.cracked("password")

record.write_output()
print("\nLogical is cracked: False <----> ", record.is_cracked())
print("\nStatus: hashes validated <----> ", record.status)

record.update_status('freely defined status')
print("\nStatus: freely defined status <----> ", record.status)
