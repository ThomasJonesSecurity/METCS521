line_from_sam = "testuser1:"":0F20048EFC645D0A179B4D5D6690BDF3:1120ACB74670C7DD46F1D3F5038A5CE8:::"
print(line_from_sam)

sam_username = line_from_sam.split(":")[0]
print(sam_username)

sam_lm_hash = line_from_sam.split(":")[2]
print(sam_lm_hash)

sam_ntlm_hash = line_from_sam.split(":")[3]
print(sam_ntlm_hash)

# comment