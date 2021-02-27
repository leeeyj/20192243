# ================================================================
#
# author: 국민대학교 정보보안암호수학과 20192243 이용진
# Kookmin Univ. Information security math & cryptography
#
# Team: Fas_Forensic
#
# Project : Develop ooxml parsing program
#
# Date : 2021.2.3 ~
# ================================================================

import binascii

def parsing(rooxml):
    with open(rooxml, "rb") as infile:
        buffer = infile.read()
        # print(binascii.hexlify(buffer))

    len_buffer = len(buffer)
    EOCD_offset = len_buffer - 4

    while True:
        if binascii.hexlify(buffer[len_buffer - 4:len_buffer]) != b'504b0506':
            # print(binascii.hexlify(buffer[len_buffer - 4:len_buffer]))
            len_buffer -= 1
            EOCD_offset -= 1
        else:
            len_buffer = len(buffer)
            break

    # print(hex(EOCD_offset))

    CD_Num = int.from_bytes(buffer[EOCD_offset+10:EOCD_offset+12], byteorder="little", signed=False)
    print("Central Directory 개수:", CD_Num)

    CD_offset = int.from_bytes(buffer[EOCD_offset+16:EOCD_offset+20], byteorder="little", signed=False)
    # print(hex(CD_offset))

    CD = buffer[CD_offset:EOCD_offset]
    LHOL = []
    # LHOL = Local Header offset list

    for i in range(1, CD_Num + 1):
        print("Central Directory ", i, ":")

        Local_Header_Offset = int.from_bytes(CD[42:46], byteorder='little', signed=False)
        LHOL.append(Local_Header_Offset)

        file_length = int.from_bytes(CD[28:30], byteorder='little', signed=False)
        extra_field_length = int.from_bytes(CD[30:32], byteorder='little', signed=False)
        file_comment_length = int.from_bytes(CD[32:34], byteorder='little', signed=False)
        file_name = CD[46:46 + file_length]
        print("파일 이름: ", file_name.decode('euc-kr'), '\n')

        f = open("C:/Users/LeeYongJin/Desktop/Fas_Forensic/210129_FaS 과제/ppt2.txt", 'a')
        f.write(file_name.decode('euc-kr')+'\n')
        CD = CD[46 + file_length + extra_field_length + file_comment_length:]

read_ooxml1 = ""
read_ooxml2 = ""

parsing(read_ooxml2)
