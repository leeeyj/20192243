# ================================================================
#
# author: 국민대학교 정보보안암호수학과 20192243 이용진
# Kookmin Univ. Information security math & cryptography
#
# Team: Fas_Forensic
#
# Project : Develop My own zip file parsing program
#
# ================================================================
import binascii

def Forensic(rzip):
    with open(rzip, "rb") as infile:
        buffer = infile.read()

        # binascii.hexlify(buffer)
        # 바이트 확인용

        len_buffer = len(buffer)
        EndofCentralDirectory_offset = len_buffer - 4

        while True:
            if binascii.hexlify(buffer[len_buffer - 4:len_buffer]) != b'504b0506':
                # print(binascii.hexlify(buffer[len_buffer - 4:len_buffer]))
                len_buffer -= 1
                EndofCentralDirectory_offset -= 1
            else:
                len_buffer = len(buffer)
                break

        print("End of Central Directory 시작 주소: ", end='')
        print(hex(EndofCentralDirectory_offset))

        NumberofCentralDirectory = int.from_bytes(buffer[EndofCentralDirectory_offset + 8: EndofCentralDirectory_offset + 10], byteorder='little', signed=False)
        print("Number of Central Directory: ", end='')
        print(NumberofCentralDirectory)

        TotalNumberofCentralDirectory = int.from_bytes(buffer[EndofCentralDirectory_offset + 10: EndofCentralDirectory_offset + 12], byteorder='little', signed=False)
        print("총 파일 수: ", end='')
        print(TotalNumberofCentralDirectory)
        print("")

        OffsetofStartofCentralDirectory = int.from_bytes(buffer[EndofCentralDirectory_offset + 16: EndofCentralDirectory_offset + 20], byteorder='little', signed=False)
        print("Central Directory 시작 Offset: ", end='')
        print(hex(OffsetofStartofCentralDirectory))

        Central_Directory = buffer[OffsetofStartofCentralDirectory:EndofCentralDirectory_offset]
        # print(binascii.hexlify(Central_Directory))
        Local_Header_list = []

        for i in range(1, NumberofCentralDirectory+1):
            print("Central Directory ", i, ":")

            Local_Header_Offset = int.from_bytes(Central_Directory[42:46], byteorder='little', signed=False)
            print("     Local Header Offset: ", hex(Local_Header_Offset))
            Local_Header_list.append(Local_Header_Offset)

            file_length = int.from_bytes(Central_Directory[28:30], byteorder='little', signed=False)
            print("     파일 이름 길이: ", file_length)

            extra_field_length = int.from_bytes(Central_Directory[30:32], byteorder='little', signed=False)
            print("     추가 필드 길이: ", extra_field_length)

            file_comment_length = int.from_bytes(Central_Directory[32:34], byteorder='little', signed=False)
            print("     파일 주석 길이: ", file_comment_length)

            file_name = Central_Directory[46:46 + file_length]
            print("     파일 이름: ", file_name.decode('euc-kr'), '\n')

            Central_Directory = Central_Directory[46 + file_length + extra_field_length + file_comment_length:]

        for i in range(0, len(Local_Header_list)):
            if i == len(Local_Header_list) - 1:
                Local_File_Header = buffer[Local_Header_list[i]:OffsetofStartofCentralDirectory]
            else:
                Local_File_Header = buffer[Local_Header_list[i]:Local_Header_list[i+1]]

            file_length = int.from_bytes(Local_File_Header[26:28], byteorder='little', signed=False)
            # 추가 필드 길이도 구해서 정확도를 높여야함 ***
            extra_field_length = int.from_bytes(Local_File_Header[28:30], byteorder='little', signed=False )

            print("Local Header ", i + 1, ":")
            print("     파일 이름: ", Local_File_Header[30:30 + file_length].decode('euc-kr'))

            file_data_offset = Local_Header_list[i] + 30 + file_length + extra_field_length
            print("     Offset of start to file data", i + 1, " : ", hex(file_data_offset), '\n')

            if i == len(Local_Header_list) - 1:
                file_data = buffer[file_data_offset:OffsetofStartofCentralDirectory]
            else:
                file_data = buffer[file_data_offset:Local_Header_list[i + 1]]

            open(Local_File_Header[30:30 + file_length].decode('euc-kr'), 'wb').write(binascii.hexlify(file_data))

read_zip_file = ""
# write_zip_file = ""

print("\n헤더의 모든 멀티 바이트 값은 리틀 엔디안 바이트 순서로 저장한다.\n")
Forensic(read_zip_file)
