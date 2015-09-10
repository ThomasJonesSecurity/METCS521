sam_file = open("sam_test")

for each_line in sam_file:
    print(each_line, end='')
    sam_username = each_line.split(":")[0]
    print(sam_username)

    sam_lm_hash = each_line.split(":")[2]
    print(sam_lm_hash)

    sam_ntlm_hash = each_line.split(":")[3]
    print(sam_ntlm_hash)

sam_file.close()