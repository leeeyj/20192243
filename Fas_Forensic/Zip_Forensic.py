import binascii


def Forensic(rzip, wzip):
    with open(rzip, "rb") as infile:
        with open(wzip, "wb") as outfile:
            buffer = infile.read()
            # binascii.hexlify(buffer)[52:56], 파일 이름 길이 확인
            file_length = int.from_bytes(buffer[26:28], byteorder='little', signed=False)
            print("파일 이름 길이: ", end="")
            print(file_length)

            print("파일 이름: ", end="")
            file_name = buffer[30:30 + file_length].decode('utf-8')
            print(file_name)

            print("파일 데이터 정보 시작 offset: ", end="")
            file_data_offset = 30 + file_length
            print(file_data_offset)

            print("파일 데이터 정보: ", end="")
            file_data_end = 0

            while True:
                if binascii.hexlify(buffer[file_data_offset:file_data_offset+4]) != b'504b0102':
                    file_data_end += 1
                    file_data_offset += 1
                else:
                    file_data_offset = 30 + file_length
                    break

            file_data = buffer[file_data_offset: file_data_offset + file_data_end].decode('utf-8')
            print(file_data)

            outfile.write(file_data.encode('utf-8'))


read_zip_file = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/Test.zip."
write_zip_file = "C:/Users/LeeYongJin/Desktop/Fas_Forensic/Test_write.txt."
name = b'\xb0\xf8\xc1\xf6\xbb\xe7\xc7\xd7'
print(name.decode("utf-8"))

print("헤더의 모든 멀티 바이트 값은 리틀 엔디안 바이트 순서로 저장한다.")
Forensic(read_zip_file, write_zip_file)
